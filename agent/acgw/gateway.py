"""The agent's MCP session with AgentCore Gateway, on the official MCP SDK (protocol 2026-07-28 only).

`open_session(url, token)` yields an `mcp.ClientSession` over streamable HTTP that has already negotiated the
protocol with the SDK's own auto-negotiation (`server/discover`). The Gateway's authorizer speaks two things on
top of plain MCP (docs/contracts.md):

- an approval-needing `tools/call` answers `{"resultType": "input_required", "requestState": …}` with
  `_meta["com.pingidentity/approval"]` = {bindingMessage, expiresIn}; the client retries the identical call
  with that `requestState` until the approval resolves (multi round-trip requests);
- refusals are JSON-RPC errors at HTTP 200, which the SDK raises as `mcp.MCPError`: `-32080` with `data.reason`
  and a plain-words message, or `-32081` with the policy's challenge in `data["com.pingidentity/auth-challenge"]`.
"""
import json
import ssl
from contextlib import asynccontextmanager

import certifi
import httpx2
from mcp import ClientSession
from mcp.client.client import negotiate_auto  # the SDK's connect-time policy (what mcp.Client and Strands use)
from mcp.client.streamable_http import streamable_http_client
from mcp.types import Implementation, PaginatedRequestParams
from mcp_types.version import MODERN_PROTOCOL_VERSIONS

# Error codes of the sideband authorizer (p1az-ciba-authorizer), both at HTTP 200
AUTHZ_ERROR = -32080  # refused: data.reason, and a plain-words message
AUTH_CHALLENGE = -32081  # the policy's denial as an in-band challenge; data["com.pingidentity/auth-challenge"]
APPROVAL_META_KEY = "com.pingidentity/approval"  # in an input_required result's _meta: bindingMessage, expiresIn

CLIENT_INFO = Implementation(name="acgw-agent", version="2.0")
CONNECT_TIMEOUT = 30.0  # connect, write and pool
READ_TIMEOUT = 300.0  # the authorizer holds an approval round for about 20 s; tools can be slow too


@asynccontextmanager
async def open_session(url, token, *, transport=None):
    """An `mcp.ClientSession` with the Gateway, negotiated at MCP 2026-07-28, as the holder of `token`.

    Every request carries `Authorization: Bearer <token>`. TLS is verified against certifi's CA bundle (httpx2
    uses the system trust store, which the Runtime's microVM may not have). Raises `RuntimeError` when the
    Gateway only offers a pre-2026 protocol version: approvals need multi round-trip requests.
    `transport` (an `httpx2` transport) is for tests.

    The SDK's task groups wrap anything raised inside the session in an exception group; a single error comes out
    as itself (e.g. `httpx2.ConnectError`), so callers and the chat see what went wrong.
    """
    try:
        async with _session(url, token, transport) as session:
            yield session
    except BaseExceptionGroup as group:
        error = _sole(group)
        if error is group:
            raise
        raise error from None


def _sole(error):
    """The one exception inside nested single-member exception groups, else the group itself."""
    while isinstance(error, BaseExceptionGroup) and len(error.exceptions) == 1:
        error = error.exceptions[0]
    return error


@asynccontextmanager
async def _session(url, token, transport):
    http = httpx2.AsyncClient(
        headers={"Authorization": f"Bearer {token}"},
        timeout=httpx2.Timeout(CONNECT_TIMEOUT, read=READ_TIMEOUT),
        verify=ssl.create_default_context(cafile=certifi.where()),
        transport=transport,
    )
    async with (
        http,
        streamable_http_client(url, http_client=http) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream, client_info=CLIENT_INFO) as session,
    ):
        await negotiate_auto(session)
        if session.protocol_version not in MODERN_PROTOCOL_VERSIONS:
            raise RuntimeError(f"The Gateway negotiated MCP {session.protocol_version}; this agent needs "
                               f"{' or '.join(MODERN_PROTOCOL_VERSIONS)} (multi round-trip approvals).")
        yield session


async def list_tools(session):
    """Every tool the Gateway lists for this caller, as plain dicts (name, description, inputSchema, …)."""
    tools, cursor = [], None
    while True:
        result = await session.list_tools(params=PaginatedRequestParams(cursor=cursor) if cursor else None)
        tools.extend(t.model_dump(by_alias=True, mode="json", exclude_none=True) for t in result.tools)
        cursor = result.next_cursor
        if not cursor:
            return tools


def tool_payload(result):
    """A tools/call result (wire dict) as data: structuredContent, else the first text item as JSON, else the text."""
    if "structuredContent" in result:
        return result["structuredContent"]
    texts = [c.get("text", "") for c in result.get("content", []) if c.get("type") == "text"]
    if not texts:
        return None
    try:
        return json.loads(texts[0])
    except ValueError:
        return "\n".join(texts)
