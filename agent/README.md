# Demo agent (Phase 5)

A Strands agent on AgentCore Runtime (HTTP protocol) that manages user accounts through AgentCore Gateway
**as the signed-in user**. Full setup, interfaces and token rules: the [setup guide](https://aws-agentcore-ping.pingtapdemos.com/).

```
chat app --(user's PingOne token)--> Runtime acgw_agent --(exchange 1: AgentCore OBO)--> Gateway --> MCP servers
                                          |                                     |
                                          |   MCP 2026-07-28 only               +-- authorizer: PingOne Authorize;
                                          |                                         starts PingOne CIBA (email
                                          +<-- input_required + requestState -------+ DEL-NNNN), holds ~20 s
                                          +--> same tools/call + requestState ----> (until approved / refused)
```

| File | What |
|---|---|
| `main.py` | Runtime entry point (`BedrockAgentCoreApp`, `/invocations` + `/ping` on 8080) |
| `acgw/app.py` | One invocation: user token → Gateway token → Gateway tools → Strands agent → contract events |
| `acgw/identity.py` | Exchange 1 (`GetResourceOauth2Token`, `ON_BEHALF_OF_TOKEN_EXCHANGE`, `subject_token_type` override) |
| `acgw/gateway.py` | `open_session(url, token)`: an MCP SDK `ClientSession` with the Gateway (2026-07-28), and `list_tools` |
| `acgw/tools.py` | Gateway tools as Strands tools; the approval wait (multi round-trip requests) and denial words |
| `acgw/events.py` | The `text/event-stream` events |
| `deploy.py` | Secret, workload identity, arm64 zip, role, runtime, PingOne audience |
| `local.py` | `serve` locally; `invoke` locally or against the runtime |

## Behaviour

Each invocation (`{"prompt": ...}`, `Authorization: Bearer <sign-in token>`) streams:

1. `identity` hop `user`: decoded claims of the sign-in token (forwarded via the runtime's header allowlist).
2. Exchange 1 with baseline scopes `mcp:tools users:read users:write`. On Runtime the subject is bound by the
   `WorkloadAccessToken` header; locally the agent calls `GetWorkloadAccessTokenForJWT` on `acgw-agent`.
   Then `identity` hop `gateway`.
3. One MCP session per invocation on the official SDK (`mcp==2.3.0`): streamable HTTP over an `httpx2` client
   with the Gateway token as `Authorization: Bearer`, TLS verified against certifi's CA bundle, timeouts 30 s
   (300 s for reads). The SDK's auto-negotiation (`server/discover`) must land on **2026-07-28**; a Gateway that
   only offers older versions is an `error`. Then `tools/list` (every page), and the model
   (`us.anthropic.claude-sonnet-5-5`, override with `MODEL_ID`) runs with those tools. `text` deltas stream as
   the model writes.
4. Every tool use is `tool_call` … `tool_result` (exactly one each, never interleaved: tools run sequentially).
   The agent calls `session.call_tool(..., allow_input_required=True)`. Between the two events:
   - The policy wants an approval: the Gateway's authorizer starts PingOne CIBA itself, holds the call (about
     20 s), and if nobody has approved yet answers `{"resultType": "input_required", "requestState": …}` with
     `_meta["com.pingidentity/approval"]` = `{bindingMessage, expiresIn}`. The agent emits `approval_required`
     once (`code` = the binding message, action, approver = the user, `expiresIn` when given), then retries the
     **identical** call with that `requestState` after a 1 s pause; another `input_required` means still
     pending. It stops at a final result (`approval_result` approved), a refusal (`approval_result` not
     approved, then `denied`), or its own deadline of `expiresIn` (default 180 s) + 30 s from the first call
     (`approval_result` not approved, "expired"). Every delete needs its own approval: the authorizer spends it.
   - Refusals are JSON-RPC errors at HTTP 200, raised by the SDK as `MCPError`: `-32080` with `data.reason`
     (put in words by `denial_reason`, else the authorizer's plain message) or `-32081` with the policy's
     `data["com.pingidentity/auth-challenge"].error_description`. Both give `denied`; never retried. Other
     errors (e.g. a timeout) close the call with a failed `tool_result`.
   - An `input_required` with input requests (elicitation and the like) isn't something the authorizer sends;
     the agent can't answer one and closes the call.
   - A tool result that echoes the server's token claims (the `whoami` stub's `token` object) adds `identity`
     hop `server`.
5. `error` on failure, and always `done` last.

Conversation history is kept in memory per (runtime session id, user `sub`), so follow-ups work within a chat.

The approval card names the approver by **username**, but the sign-in token carries only `sub`. The agent uses
a `username` or `preferred_username` claim if one is added later; until then `deploy.py` looks up the demo
users' ids (`LOGIN_HINTS`).

## Setup

```bash
.venv/bin/pip install -r agent/requirements.txt pytest
```

`deploy.py` and `local.py` come from the demo project and expect its layout: a `.env` and `spike/.state.json`
at the project root, which aren't in this repo. The [setup guide](https://aws-agentcore-ping.pingtapdemos.com/)
covers the same steps by hand.

AWS profile and region come from `.env` (`AWS_PROFILE=gte`); PingOne from `.env` and `spike/.state.json`
(read only). The Gateway is `spike/.state.json` → `gateway_url` unless `GATEWAY_URL` is set (set it for Gateway
v2, then re-deploy).

## Run locally

```bash
.venv/bin/python agent/deploy.py --prepare
```

Creates (idempotently) the secret `acgw/approvals-client` (no longer read by the agent), the workload identity
`acgw-agent`, and the login hints in `agent/.state.json`. Then, in one terminal:

```bash
.venv/bin/python agent/local.py serve
```

and in another (uses `user_token` from `spike/.state.json`; sign in again with `spike/login.py` when it expires):

```bash
.venv/bin/python agent/local.py invoke "Use the whoami tool and tell me who I am and which scopes the server saw."
```

## Test

```bash
cd agent && ../.venv/bin/python -m pytest -q
```

`tests/test_approval.py` drives `run_tool` and the Strands adapter with a fake SDK session: approved after
several `input_required` rounds (the latest `requestState` echoed, the arguments unchanged), approved within
the first hold, declined / expired / already used (`-32080`), the local deadline, `-32081` and `-32080` reasons
in words, input requests the agent can't answer, and the exact event order the chat relies on.
`tests/test_clients.py` runs `open_session` on the real MCP SDK against a mock 2026-07-28 Gateway
(`httpx2.MockTransport`): `server/discover`, the Bearer token and `MCP-Protocol-Version` on every request,
paginated `tools/list`, `input_required` with its `_meta`, the `requestState` echoed byte-exact, refusals at
HTTP 200, a legacy-only Gateway refused, errors surfacing as themselves (not exception groups), and certifi's
CA bundle.

## Deploy

```bash
.venv/bin/python agent/deploy.py
```

Builds `agent/build/deployment.zip` (arm64, CPython 3.12 wheels, no `bin/` or `__pycache__`, explicit file
modes), uploads it to `s3://acgw-agent-<account>-<region>`, upserts role `acgw-agent-runtime` and runtime
`acgw_agent` (HTTP, PingOne JWT authorizer with audience = the runtime's own URL, `Authorization` allowlisted),
then sets the PingOne resource `acgw-spike agent-runtime` audience to the runtime URL. IDs and the URL are in
`agent/.state.json`. After the audience changes, sign in again for a token the runtime accepts, then:

```bash
.venv/bin/python agent/local.py invoke --runtime "who am I?"
```

The chat app calls `InvokeAgentRuntime` on `agent/.state.json` → `runtime.url` (`?qualifier=DEFAULT`) with the
user's token as Bearer and a `X-Amzn-Bedrock-AgentCore-Runtime-Session-Id` of at least 33 characters.
