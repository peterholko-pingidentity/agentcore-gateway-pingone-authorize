"""Gateway tools exposed to the Strands agent, waiting for a CIBA approval when the authorizer asks for one.

The Gateway's authorizer decides with PingOne Authorize. When the policy wants the user's approval it starts a
PingOne CIBA request itself, holds the call for a while, and if nobody has approved yet answers with an MCP
2026-07-28 `input_required` result: an opaque `requestState` plus the approval's binding message and lifetime in
`_meta["com.pingidentity/approval"]`. The agent tells the chat once, then retries the identical call with that
`requestState` (multi round-trip requests) until the call goes through, is refused, or the approval expires.

`run_tool` holds the logic and yields contract events, ending with an `Outcome` for the model; `GatewayTool`
adapts it to Strands. Every tool_call is closed by exactly one tool_result; denied / approval_* come between.
"""
import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from mcp import MCPError
from mcp.types import InputRequiredResult
from strands.types._events import ToolResultEvent
from strands.types.tools import AgentTool

from . import events
from .gateway import APPROVAL_META_KEY, AUTH_CHALLENGE, AUTHZ_ERROR, tool_payload

EVENT_KEY = "acgw_event"  # marks our events inside Strands' tool stream
DEFAULT_EXPIRES_IN = 180  # seconds, when the approval's _meta has no expiresIn (the authorizer's CIBA default)
DEADLINE_MARGIN = 30  # seconds past expiresIn before the agent stops waiting: one server hold (~20 s) and slack
RETRY_PAUSE = 1.0  # seconds between rounds; the server itself holds each round for about 20 s
logger = logging.getLogger(__name__)


@dataclass
class Turn:
    """What one invocation's tools share: the caller and the Gateway session."""

    user_claims: dict
    session: Any  # mcp.ClientSession from gateway.open_session, negotiated, holding the Gateway token
    login_hints: dict = field(default_factory=dict)  # PingOne user id -> username, when the token has no username
    sleep: Callable = asyncio.sleep  # injected in tests
    clock: Callable = time.monotonic

    def login_hint(self):
        c = self.user_claims
        return c.get("username") or c.get("preferred_username") or self.login_hints.get(c.get("sub"))


@dataclass
class Outcome:
    ok: bool
    text: str  # what the model sees as the tool result


async def run_tool(turn, tool, arguments):
    """Call one Gateway tool as the user. Yields contract events; the last item is an Outcome."""
    yield events.tool_call(tool, arguments)
    started = turn.clock()  # the authorizer starts the CIBA request during this call
    try:
        result = await turn.session.call_tool(tool, arguments, allow_input_required=True)
    except MCPError as e:
        for item in _refused(tool, e):
            yield item
        return
    if isinstance(result, InputRequiredResult):
        async for item in _await_approval(turn, tool, arguments, result, started):
            yield item
        return
    for item in _finish(tool, result):
        yield item


async def _await_approval(turn, tool, arguments, pending, started):
    """The authorizer started a CIBA approval: retry the identical call with its requestState until it resolves.

    The arguments are the model's, unchanged, so the authorizer's call fingerprint matches. Each retry is held
    by the server until the approval resolves or its hold ends; another input_required means still pending.
    """
    if not _state_only(pending):
        for item in _cannot_answer(tool):
            yield item
        return
    approval = (pending.meta or {}).get(APPROVAL_META_KEY) or {}
    expires_in = _seconds(approval.get("expiresIn"))
    yield events.approval_required(approval.get("bindingMessage") or "", describe(tool, arguments),
                                   turn.login_hint() or turn.user_claims.get("sub") or "you", expires_in)
    deadline = started + (expires_in or DEFAULT_EXPIRES_IN) + DEADLINE_MARGIN
    result = pending
    try:
        while isinstance(result, InputRequiredResult):
            if not _state_only(result):
                yield events.approval_result(False)
                for item in _cannot_answer(tool):
                    yield item
                return
            if turn.clock() >= deadline:
                yield events.approval_result(False)
                message = "The approval request expired before anyone approved it."
                yield events.tool_result(tool, False, message)
                yield Outcome(False, message + " Nothing was changed.")
                return
            await turn.sleep(RETRY_PAUSE)
            try:
                result = await turn.session.call_tool(tool, arguments, request_state=result.request_state,
                                                      allow_input_required=True)
            except MCPError as e:
                yield events.approval_result(False)
                for item in _refused(tool, e):
                    yield item
                return
    except Exception:
        # E.g. the Gateway unreachable mid-wait: settle the approval card; GatewayTool closes the tool_call.
        yield events.approval_result(False)
        raise
    yield events.approval_result(True)
    for item in _finish(tool, result):
        yield item


def _state_only(result):
    """An input_required that only asks to retry with its requestState: the authorizer's approval wait.

    Input requests (elicitation, sampling, roots) are not something the Gateway's authorizer sends; this agent
    has no way to answer them.
    """
    return bool(result.request_state) and not result.input_requests


def _cannot_answer(tool):
    message = "The Gateway asked for input this agent can't give, so the call can't be completed."
    yield events.tool_result(tool, False, message)
    yield Outcome(False, message + " Nothing was changed.")


def _seconds(value):
    """A positive number of seconds from the approval's _meta, else None."""
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        return None
    return seconds if seconds > 0 else None


# Plain words for the authorizer's -32080 reasons. Unknown reasons fall back to its own plain-words message.
DENIAL_REASONS = {
    "approval_denied": "The approval request was declined.",
    "approval_expired": "The approval request expired before anyone approved it.",
    "approval_already_used": "That approval was already used for another call.",
    "approval_mismatch": "The approval didn't match this call (another user, or different details).",
    "approval_reference_invalid": "The approval reference wasn't recognized, so the call was refused.",
    "approval_not_accepted": "The policy still asked for an approval after one was given.",
    "approval_unavailable": "An approval can't be requested for this call.",
    "approval_not_configured": "Approvals aren't set up on the Gateway.",
    "ciba_unavailable": "The approval service couldn't be reached, so the call was refused.",
    "approval_store_unavailable": "The approval records couldn't be read, so the call was refused.",
    "pdp_unreachable": "PingOne Authorize could not be reached, so the call was refused.",
    "pdp_http_error": "PingOne Authorize returned an error, so the call was refused.",
}


def denial_reason(error):
    """Why the Gateway refused a call (an `mcp.MCPError`), in words, from `error.data`.

    The policy's own words when it gave some: the auth-challenge's error_description (-32081). Else the -32080
    reason code in words, else the authorizer's message (unwrapped when it is a PingOne deny body passed on as
    JSON text), else the bare reason code.
    """
    data = error.data if isinstance(error.data, dict) else {}
    challenge = data.get("com.pingidentity/auth-challenge")
    if isinstance(challenge, dict) and challenge.get("error_description"):
        return challenge["error_description"]
    reason = data.get("reason")
    return DENIAL_REASONS.get(reason) or _unwrap(error.message) or (reason if isinstance(reason, str) else "")


def _unwrap(message):
    """The message inside a PingOne error body ({"code": "ACCESS_FAILED", "message": …}), else the text as is."""
    try:
        body = json.loads(message)
    except (TypeError, ValueError):
        return message
    return (body.get("message") or message) if isinstance(body, dict) else message


def _refused(tool, error):
    if error.code in (AUTHZ_ERROR, AUTH_CHALLENGE):
        reason = denial_reason(error)
        yield events.denied(tool, reason)
        yield events.tool_result(tool, False, f"Denied: {reason}")
        yield Outcome(False, f"The call was refused: {reason} Nothing was changed. Do not retry; "
                             "explain the reason to the user.")
    else:
        yield events.tool_result(tool, False, _short(error.message))
        yield Outcome(False, f"The Gateway refused the call: {error.message}")


def _finish(tool, result):
    result = result.model_dump(by_alias=True, mode="json", exclude_none=True)  # the wire shape
    payload = tool_payload(result)
    if isinstance(payload, dict) and isinstance(payload.get("token"), dict):
        # The whoami stub echoes the claims it received: the server end of the identity trail.
        yield events.identity("server", payload["token"])
    ok = not result.get("isError")
    yield events.tool_result(tool, ok, summarize(payload))
    texts = [c.get("text", "") for c in result.get("content", []) if c.get("type") == "text"]
    text = "\n".join(texts) or json.dumps(payload, default=str)
    yield Outcome(ok, text if ok else f"The tool reported an error: {text}")


def describe(tool, arguments):
    """Human-readable action for the approval card, e.g. 'delete_user username=demo-jane (whoami)'."""
    target, _, name = tool.rpartition("___")
    args = " ".join(f"{k}={v}" for k, v in arguments.items())
    return " ".join(p for p in (name, args, f"({target})" if target else "") if p)


def summarize(payload):
    if isinstance(payload, dict):
        payload = {k: v for k, v in payload.items() if k != "token"} or payload
    text = payload if isinstance(payload, str) else json.dumps(payload, default=str)
    return _short(text or "ok")


def _short(text, limit=200):
    return text if len(text) <= limit else text[: limit - 1] + "…"


class GatewayTool(AgentTool):
    """One Gateway tool (`<target>___<tool>`) as a Strands tool."""

    def __init__(self, turn, spec):
        super().__init__()
        self._turn, self._spec = turn, spec

    @property
    def tool_name(self):
        return self._spec["name"]

    @property
    def tool_spec(self):
        return {
            "name": self._spec["name"],
            "description": self._spec.get("description") or self._spec["name"],
            "inputSchema": {"json": self._spec.get("inputSchema") or {"type": "object", "properties": {}}},
        }

    @property
    def tool_type(self):
        return "mcp"

    async def stream(self, tool_use, invocation_state, **kwargs):
        outcome = Outcome(False, "The tool produced no result.")
        try:
            async for item in run_tool(self._turn, self.tool_name, tool_use.get("input") or {}):
                if isinstance(item, Outcome):
                    outcome = item
                else:
                    yield {EVENT_KEY: item}
        except Exception as e:  # noqa: BLE001 - e.g. the Gateway unreachable; close the tool_call for the UI
            logger.exception("tool %s failed", self.tool_name)
            yield {EVENT_KEY: events.tool_result(self.tool_name, False, _short(f"{type(e).__name__}: {e}"))}
            outcome = Outcome(False, f"The tool call failed: {type(e).__name__}: {e}")
        yield ToolResultEvent({
            "toolUseId": tool_use["toolUseId"],
            "status": "success" if outcome.ok else "error",
            "content": [{"text": outcome.text}],
        })
