"""Approval path with a fake MCP SDK session: what the chat sees and what the agent sends.

The Gateway's authorizer starts the CIBA request itself and answers an MCP 2026-07-28 `input_required` result
with a `requestState`; the agent retries the identical call with that state until the approval resolves.
Refusals are `MCPError`s (-32080 with data.reason, -32081 with the policy's challenge).
"""
import asyncio

import pytest
from mcp import MCPError
from mcp.types import CallToolResult, InputRequiredResult

from acgw.gateway import APPROVAL_META_KEY, AUTH_CHALLENGE, AUTHZ_ERROR
from acgw.tools import DEADLINE_MARGIN, EVENT_KEY, RETRY_PAUSE, GatewayTool, Outcome, Turn, run_tool

BOB, ALICE = "user-bob", "user-alice"
DELETE = "snowflake___delete_user"
ARGS = {"user_name": "carol.martinez"}
ACTION = "delete_user user_name=carol.martinez (snowflake)"
OK_RESULT = CallToolResult.model_validate(
    {"content": [{"type": "text", "text": '{"tool": "delete_user", "user_name": "carol.martinez"}'}]})


def input_required(state="state-1", code="DEL-4821", expires_in=180):
    approval = {"bindingMessage": code}
    if expires_in is not None:
        approval["expiresIn"] = expires_in
    wire = {"resultType": "input_required", "_meta": {APPROVAL_META_KEY: approval}}
    if state is not None:
        wire["requestState"] = state
    return InputRequiredResult.model_validate(wire)


def refused(reason, message="Request denied"):
    return MCPError(AUTHZ_ERROR, message, {"reason": reason})


class FakeClock:
    def __init__(self):
        self.now, self.waits = 0.0, []

    async def sleep(self, seconds):
        self.waits.append(seconds)
        self.now += seconds

    def __call__(self):
        return self.now


class FakeSession:
    """Answers tools/call from a script, like `mcp.ClientSession.call_tool(..., allow_input_required=True)`.

    An exception in the script is raised. `hold` seconds pass on the clock per call (the server's hold).
    """

    def __init__(self, *answers, clock=None, hold=0):
        self.answers, self.calls, self.clock, self.hold = list(answers), [], clock, hold

    async def call_tool(self, name, arguments=None, read_timeout_seconds=None, progress_callback=None, *,
                        input_responses=None, request_state=None, meta=None, allow_input_required=False,
                        allow_claimed=False):
        assert allow_input_required, "the agent drives the approval rounds itself"
        assert input_responses is None and meta is None
        self.calls.append((name, arguments, request_state))
        if self.clock:
            self.clock.now += self.hold
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer


def make_turn(*answers, user=BOB, hold=0):
    clock = FakeClock()
    session = FakeSession(*answers, clock=clock, hold=hold)
    turn = Turn(user_claims={"sub": user}, session=session, login_hints={BOB: "bob", ALICE: "alice"},
                sleep=clock.sleep, clock=clock)
    return turn, session, clock


def collect(turn, tool=DELETE, arguments=ARGS):
    async def go():
        return [item async for item in run_tool(turn, tool, arguments)]

    items = asyncio.run(go())
    assert isinstance(items[-1], Outcome)
    return items[:-1], items[-1]


def types(events):
    return [e["type"] for e in events]


def test_approved_after_several_rounds_retries_the_identical_call_with_the_latest_state():
    turn, session, clock = make_turn(input_required("s1"), input_required("s1"), input_required("s2"), OK_RESULT)

    events, outcome = collect(turn)

    assert types(events) == ["tool_call", "approval_required", "approval_result", "tool_result"]
    assert events[1] == {"type": "approval_required", "code": "DEL-4821", "action": ACTION, "approver": "bob",
                         "expiresIn": 180}
    assert events[2] == {"type": "approval_result", "approved": True}
    assert events[3]["ok"] and outcome.ok
    assert session.calls == [(DELETE, ARGS, None), (DELETE, ARGS, "s1"), (DELETE, ARGS, "s1"), (DELETE, ARGS, "s2")]
    assert clock.waits == [RETRY_PAUSE] * 3


def test_approval_approved_within_the_first_hold_needs_no_approval_events():
    turn, session, _ = make_turn(OK_RESULT)

    events, outcome = collect(turn)

    assert types(events) == ["tool_call", "tool_result"]
    assert session.calls == [(DELETE, ARGS, None)] and outcome.ok


def test_approval_required_leaves_out_expires_in_when_the_gateway_gives_none():
    turn, _, _ = make_turn(input_required(expires_in=None), OK_RESULT)

    events, _ = collect(turn)

    assert events[1] == {"type": "approval_required", "code": "DEL-4821", "action": ACTION, "approver": "bob"}


@pytest.mark.parametrize("reason, words", [
    ("approval_denied", "The approval request was declined."),
    ("approval_expired", "The approval request expired before anyone approved it."),
    ("approval_already_used", "That approval was already used for another call."),
])
def test_a_declined_or_expired_approval_changes_nothing(reason, words):
    turn, session, _ = make_turn(input_required(), input_required(), refused(reason))

    events, outcome = collect(turn)

    assert types(events) == ["tool_call", "approval_required", "approval_result", "denied", "tool_result"]
    assert events[2] == {"type": "approval_result", "approved": False}
    assert events[3] == {"type": "denied", "tool": DELETE, "reason": words}
    assert len(session.calls) == 3
    assert not outcome.ok and "Do not retry" in outcome.text


def test_waiting_stops_at_the_local_deadline_when_the_approval_never_resolves():
    expires_in, hold = 60, 20
    turn, session, clock = make_turn(*[input_required(expires_in=expires_in) for _ in range(20)], hold=hold)

    events, outcome = collect(turn)

    assert types(events) == ["tool_call", "approval_required", "approval_result", "tool_result"]
    assert events[2]["approved"] is False
    assert "expired" in events[3]["summary"] and not events[3]["ok"]
    deadline = expires_in + DEADLINE_MARGIN
    assert deadline <= clock.now < deadline + RETRY_PAUSE + hold  # stopped at the first check past the deadline
    assert len(session.calls) < 20
    assert not outcome.ok and "Nothing was changed" in outcome.text


ELICITATION = {"confirm": {"method": "elicitation/create", "params": {
    "mode": "form", "message": "Sure?", "requestedSchema": {"type": "object", "properties": {}}}}}


def test_an_input_request_the_agent_cannot_answer_is_reported_without_an_approval_card():
    turn, session, _ = make_turn(InputRequiredResult.model_validate(
        {"resultType": "input_required", "inputRequests": ELICITATION}))

    events, outcome = collect(turn)

    assert types(events) == ["tool_call", "tool_result"]
    assert not events[1]["ok"] and "can't give" in events[1]["summary"]
    assert len(session.calls) == 1 and not outcome.ok


def test_an_input_request_in_a_later_round_settles_the_approval_card():
    later = InputRequiredResult.model_validate(
        {"resultType": "input_required", "inputRequests": ELICITATION, "requestState": "s2"})
    turn, session, _ = make_turn(input_required(), later)

    events, outcome = collect(turn)

    assert types(events) == ["tool_call", "approval_required", "approval_result", "tool_result"]
    assert events[2]["approved"] is False and not events[3]["ok"]
    assert len(session.calls) == 2 and not outcome.ok


def test_policy_denials_are_explained_with_the_challenges_description_and_never_retried():
    reason = "Your PingOne role does not allow you to delete or deactivate users (it lacks users:delete)"
    challenge = {"status": 403, "scheme": "Bearer", "error": "insufficient_scope", "error_description": reason,
                 "www_authenticate": f'Bearer error="insufficient_scope", error_description="{reason}"'}
    turn, session, _ = make_turn(MCPError(AUTH_CHALLENGE, reason, {"com.pingidentity/auth-challenge": challenge}))

    events, outcome = collect(turn)

    assert types(events) == ["tool_call", "denied", "tool_result"]
    assert events[1]["reason"] == reason
    assert len(session.calls) == 1
    assert not outcome.ok and "Do not retry" in outcome.text


@pytest.mark.parametrize("message, data, words", [
    ("Request denied", {"reason": "approval_mismatch"},
     "The approval didn't match this call (another user, or different details)."),
    # A reason this agent has no words for: the authorizer's own plain-words message
    ("The approval state didn't match this call, so it was refused.", {"reason": "approval_state_invalid"},
     "The approval state didn't match this call, so it was refused."),
    # A policy deny body passed on without its challenge header
    ('{\n  "id" : "x",\n  "code" : "ACCESS_FAILED",\n  "message" : "You do not have access to this resource."\n}',
     None, "You do not have access to this resource."),
    ("Service provider error HTTP 403 Forbidden", None, "Service provider error HTTP 403 Forbidden"),
])
def test_authorizer_refusals_are_explained(message, data, words):
    turn, _, _ = make_turn(MCPError(AUTHZ_ERROR, message, data))

    events, outcome = collect(turn)

    assert events[1] == {"type": "denied", "tool": DELETE, "reason": words}
    assert not outcome.ok


def test_other_mcp_errors_are_reported_but_not_as_denials():
    turn, _, _ = make_turn(MCPError(-32001, "Request timed out"))

    events, outcome = collect(turn)

    assert types(events) == ["tool_call", "tool_result"]
    assert events[1] == {"type": "tool_result", "tool": DELETE, "ok": False, "summary": "Request timed out"}
    assert not outcome.ok


def test_read_passes_through_and_reports_the_server_hop():
    result = CallToolResult.model_validate({"content": [{"type": "text", "text": (
        '{"tool": "whoami", "token": {"sub": "user-alice", "scope": "whoami:users.read", "act": {"sub": "gw"}}}')}]})
    turn, _, _ = make_turn(result, user=ALICE)

    events, outcome = collect(turn, "whoami___whoami", {})

    assert types(events) == ["tool_call", "identity", "tool_result"]
    assert events[1] == {"type": "identity", "hop": "server",
                         "claims": {"sub": "user-alice", "scope": "whoami:users.read", "act": {"sub": "gw"}}}
    assert outcome.ok


def test_structured_content_and_tool_errors_are_reported():
    turn, _, _ = make_turn(CallToolResult.model_validate({
        "content": [{"type": "text", "text": "no such user"}], "structuredContent": {"error": "no such user"},
        "isError": True}))

    events, outcome = collect(turn, "slack___get_user", {"user_name": "nobody"})

    assert events[1] == {"type": "tool_result", "tool": "slack___get_user", "ok": False,
                         "summary": '{"error": "no such user"}'}
    assert not outcome.ok and outcome.text == "The tool reported an error: no such user"


def gateway_tool(turn, name=DELETE):
    return GatewayTool(turn, {"name": name, "description": "Delete a user",
                              "inputSchema": {"type": "object", "properties": {"user_name": {"type": "string"}}}})


def stream(tool, tool_use):
    async def go():
        return [e async for e in tool.stream(tool_use, {})]

    items = asyncio.run(go())
    return [i[EVENT_KEY] for i in items[:-1]], items[-1].tool_result


def test_strands_adapter_streams_the_events_the_chat_relies_on_in_order():
    turn, _, _ = make_turn(input_required(), input_required(), OK_RESULT)

    events, result = stream(gateway_tool(turn), {"toolUseId": "t1", "name": DELETE, "input": ARGS})

    # The chat opens a tool card on tool_call, shows the approval banner (with its countdown) on
    # approval_required, settles it on approval_result, and closes the card on tool_result.
    assert events == [
        {"type": "tool_call", "tool": DELETE, "arguments": ARGS},
        {"type": "approval_required", "code": "DEL-4821", "action": ACTION, "approver": "bob", "expiresIn": 180},
        {"type": "approval_result", "approved": True},
        {"type": "tool_result", "tool": DELETE, "ok": True,
         "summary": '{"tool": "delete_user", "user_name": "carol.martinez"}'},
    ]
    assert result["toolUseId"] == "t1" and result["status"] == "success"


def test_strands_adapter_closes_the_tool_call_when_the_gateway_is_unreachable():
    turn, _, _ = make_turn(ConnectionError("gateway down"))

    events, result = stream(gateway_tool(turn, "whoami___whoami"), {"toolUseId": "t2", "name": "whoami___whoami"})

    assert types(events) == ["tool_call", "tool_result"]
    assert events[-1]["ok"] is False
    assert result["status"] == "error"


def test_strands_adapter_settles_the_approval_when_the_gateway_fails_mid_wait():
    turn, _, _ = make_turn(input_required(), ConnectionError("gateway down"))

    events, result = stream(gateway_tool(turn), {"toolUseId": "t3", "name": DELETE, "input": ARGS})

    assert types(events) == ["tool_call", "approval_required", "approval_result", "tool_result"]
    assert events[2]["approved"] is False and events[3]["ok"] is False
    assert result["status"] == "error"
