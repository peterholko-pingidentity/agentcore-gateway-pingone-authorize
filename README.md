# AgentCore Gateway + PingOne Authorize, with CIBA approvals

Demo code for an AI agent that acts **as the signed-in user** through Amazon Bedrock AgentCore Gateway. PingOne
Authorize decides every MCP tool call, and risky ones, like deleting a user, wait until the user approves them on
another device (PingOne CIBA, by email in the demo).

> **Demo code, not a production integration kit.**

| Folder | What it is |
|---|---|
| [`agent/`](agent/) | Strands agent on AgentCore Runtime (Python, Strands 1.64 + MCP SDK 2.3). It exchanges the user's PingOne token for a Gateway token through AgentCore Identity and calls the Gateway's tools. |
| [`p1az-ciba-authorizer/`](p1az-ciba-authorizer/) | The Gateway's interceptor Lambda (Rust). It asks PingOne Authorize API Access Management (sideband) about each call and, when the policy asks for approval, runs PingOne CIBA, with approval records in DynamoDB. A fork of the PingOne Authorize AWS Bedrock Gateway Lambda authorizer prototype. |

## How approvals work

Everything speaks **MCP 2026-07-28 only** (the Gateway's `supportedVersions` is `["2026-07-28"]`). Approvals use
the protocol's multi round-trip requests:

1. A `tools/call` that the policy wants approved starts PingOne CIBA, and the authorizer holds the call for up to
   `CIBA_HOLD_SECONDS` (20 s by default).
2. If the user hasn't approved by then, the Gateway answers `{"resultType": "input_required", "requestState": …}`
   with the code to show in `_meta["com.pingidentity/approval"]`.
3. The MCP client sends the same call again with that `requestState` until it's approved, declined or expired.
   Stock MCP SDK 2.x clients do this with no extra code.

Refusals come back as JSON-RPC errors at HTTP 200: `-32080` (declined, expired or invalid approval) and `-32081`
(policy denial).

## Docs

- [Setup guide](https://aws-agentcore-ping.pingtapdemos.com/): step by step, assuming your own PingOne and AWS
  accounts and MCP servers.
- [Blog post](https://blog.pingtapdemos.com/agentcore-gateway-approvals/): what the demo does and what we learned
  building it.
- [`agent/README.md`](agent/README.md) and [`p1az-ciba-authorizer/README.md`](p1az-ciba-authorizer/README.md):
  behaviour, configuration, build and tests.

## Known issue

AgentCore Gateway currently passes the client's 2026-07-28 fields in `params._meta` on to MCP servers it talks to
at an older version. Servers that check those fields against the request's headers, such as Snowflake's managed MCP
server, refuse every request. It's reported to AWS; until it's fixed, try each MCP server through the Gateway
before you rely on it. The setup guide has the details.

## Earlier version

This repo used to hold a Python interceptor that called the PingOne Authorize decision endpoint
(`pingone_authorize_interceptor.py`). It's still in the history at commit `14ebe74`.
