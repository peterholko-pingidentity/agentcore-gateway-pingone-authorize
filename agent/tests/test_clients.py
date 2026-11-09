"""The Gateway session (`acgw.gateway`) on the real MCP SDK, against a 2026-07-28 Gateway on a mock transport."""
import asyncio
import json

import certifi
import httpx2
import pytest
from mcp import MCPError
from mcp.types import InputRequiredResult

from acgw import events, gateway
from acgw.app import handle
from acgw.gateway import APPROVAL_META_KEY, list_tools, open_session
from acgw.tools import Outcome, Turn, run_tool

URL = "https://gw.example/mcp"
DELETE = "snowflake___delete_user"
APPROVAL = {APPROVAL_META_KEY: {"bindingMessage": "DEL-4821", "expiresIn": 180}}
PENDING = {"resultType": "input_required", "requestState": "eyJyZWYiOiJhcmlkLTEifQ.c2ln", "_meta": APPROVAL}
DELETED = {"resultType": "complete", "content": [{"type": "text", "text": '{"deleted": "carol.martinez"}'}]}
CHALLENGE = {"code": -32081, "message": "You may not delete users", "data": {
    "com.pingidentity/auth-challenge": {"error": "insufficient_scope", "error_description": "You may not delete users"}}}
DECLINED = {"code": -32080, "message": "The approval request was declined.", "data": {"reason": "approval_denied"}}


class MockGateway:
    """A Gateway on an httpx2.MockTransport. tools/call answers come from a script: a result, or {"code": …} as a
    JSON-RPC error, always at HTTP 200. `legacy` makes it a pre-2026 server (no server/discover)."""

    def __init__(self, *call_answers, legacy=False):
        self.call_answers, self.legacy, self.requests = list(call_answers), legacy, []

    def transport(self):
        return httpx2.MockTransport(self)

    def __call__(self, request):
        if request.method != "POST":
            return httpx2.Response(405)
        body = json.loads(request.content)
        self.requests.append((request.headers, body))
        method, params = body["method"], body.get("params") or {}
        if "id" not in body:
            return httpx2.Response(202)
        if self.legacy:
            if method == "initialize":
                return self._answer(body, {"protocolVersion": "2025-03-26", "capabilities": {},
                                           "serverInfo": {"name": "gw", "version": "1"}})
            return self._answer(body, {"code": -32601, "message": "Method not found"})
        if method == "server/discover":
            return self._answer(body, {"supportedVersions": ["2026-07-28"], "capabilities": {"tools": {}}})
        if method == "tools/list":
            page = {"tools": [{"name": "whoami___whoami", "inputSchema": {"type": "object"}}], "nextCursor": "2"} \
                if not params.get("cursor") else {"tools": [{"name": DELETE, "inputSchema": {"type": "object"}}]}
            return self._answer(body, {"resultType": "complete", "ttlMs": 0, "cacheScope": "private", **page})
        if method == "tools/call":
            return self._answer(body, self.call_answers.pop(0))
        return self._answer(body, {"code": -32601, "message": "Method not found"})

    @staticmethod
    def _answer(body, answer):
        key = "error" if "code" in answer else "result"
        return httpx2.Response(200, json={"jsonrpc": "2.0", "id": body["id"], key: answer})

    def calls(self):
        return [body["params"] for _, body in self.requests if body["method"] == "tools/call"]


def run(coro):
    return asyncio.run(coro)


def test_session_negotiates_2026_07_28_with_the_bearer_token_and_lists_every_page():
    gw = MockGateway()

    async def go():
        async with open_session(URL, "gateway-token", transport=gw.transport()) as session:
            return session.protocol_version, await list_tools(session)

    version, tools = run(go())
    assert version == "2026-07-28"
    assert [t["name"] for t in tools] == ["whoami___whoami", DELETE]
    assert tools[0] == {"name": "whoami___whoami", "inputSchema": {"type": "object"}}
    assert [body["method"] for _, body in gw.requests] == ["server/discover", "tools/list", "tools/list"]
    for headers, body in gw.requests:
        assert headers["authorization"] == "Bearer gateway-token", body["method"]
        assert headers["mcp-protocol-version"] == "2026-07-28", body["method"]


def test_input_required_and_in_band_refusals_reach_the_caller_from_the_wire():
    gw = MockGateway(PENDING, DECLINED, CHALLENGE)

    async def go():
        async with open_session(URL, "t", transport=gw.transport()) as session:
            first = await session.call_tool(DELETE, {"user_name": "carol.martinez"}, allow_input_required=True)
            errors = []
            for state in (first.request_state, None):
                with pytest.raises(MCPError) as refused:
                    await session.call_tool(DELETE, {"user_name": "carol.martinez"}, request_state=state,
                                            allow_input_required=True)
                errors.append(refused.value)
            return first, errors

    first, (declined, challenge) = run(go())
    assert isinstance(first, InputRequiredResult)
    assert first.request_state == PENDING["requestState"] and first.meta == APPROVAL
    assert (declined.code, declined.data) == (-32080, {"reason": "approval_denied"})
    assert challenge.code == -32081 and challenge.data == CHALLENGE["data"]
    retry = gw.calls()[1]
    assert retry["requestState"] == PENDING["requestState"]  # echoed byte-exact
    assert retry["arguments"] == {"user_name": "carol.martinez"} and retry["name"] == DELETE


def test_run_tool_over_the_sdk_session_waits_for_the_approval_and_retries_the_identical_call():
    gw = MockGateway(PENDING, PENDING, DELETED)
    waits = []

    async def sleep(seconds):
        waits.append(seconds)

    async def go():
        async with open_session(URL, "t", transport=gw.transport()) as session:
            turn = Turn(user_claims={"sub": "user-bob", "username": "bob"}, session=session, sleep=sleep)
            return [item async for item in run_tool(turn, DELETE, {"user_name": "carol.martinez"})]

    items = run(go())
    assert [i["type"] for i in items[:-1]] == ["tool_call", "approval_required", "approval_result", "tool_result"]
    assert items[1]["code"] == "DEL-4821" and items[1]["expiresIn"] == 180 and items[1]["approver"] == "bob"
    assert items[2]["approved"] is True and items[3]["ok"] is True
    assert isinstance(items[-1], Outcome) and items[-1].ok
    calls = gw.calls()
    assert [c.get("requestState") for c in calls] == [None, PENDING["requestState"], PENDING["requestState"]]
    assert all(c["arguments"] == {"user_name": "carol.martinez"} for c in calls) and len(waits) == 2


def test_a_gateway_that_only_offers_older_protocol_versions_is_refused():
    async def go():
        async with open_session(URL, "t", transport=MockGateway(legacy=True).transport()):
            pass

    with pytest.raises(RuntimeError, match="2025-03-26.*2026-07-28"):
        run(go())


def test_errors_inside_the_session_come_out_as_themselves_not_as_exception_groups():
    def down(request):
        raise httpx2.ConnectError("gateway down")

    async def go():
        async with open_session(URL, "t", transport=httpx2.MockTransport(down)):
            pass

    with pytest.raises(httpx2.ConnectError, match="gateway down"):
        run(go())

    async def body_fails():
        async with open_session(URL, "t", transport=MockGateway().transport()):
            raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        run(body_fails())


def test_tls_is_verified_against_certifis_bundle(monkeypatch):
    cafiles = []
    create = gateway.ssl.create_default_context

    def spy(*args, cafile=None, **kwargs):
        cafiles.append(cafile)
        return create(*args, cafile=cafile, **kwargs)

    monkeypatch.setattr(gateway.ssl, "create_default_context", spy)

    async def go():
        async with open_session(URL, "t", transport=MockGateway().transport()):
            pass

    run(go())
    assert cafiles == [certifi.where()]


def test_invocation_without_a_user_token_reports_an_error_and_ends():
    async def go():
        return [e async for e in handle({"prompt": "hi"}, None, None, "session", services=None)]

    assert run(go()) == [events.error(
        "No user token: call the agent with the user's PingOne token as a Bearer token."), events.done()]
