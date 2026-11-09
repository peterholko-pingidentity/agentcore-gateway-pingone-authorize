# Authorizing AgentCore Gateway tool calls with PingOne Authorize and CIBA approvals

This repo holds the code for a demo you can set up in your own PingOne environment and AWS account, in front of your
own MCP servers. An AI agent on Amazon Bedrock AgentCore Runtime calls MCP tools through AgentCore Gateway. A Lambda
interceptor sends every tool call to PingOne Authorize, and a call that needs the user's approval waits for a CIBA
approval on the user's other device.

The [setup guide](https://aws-agentcore-ping.pingtapdemos.com/) walks through every step, and this README covers the
first part of it. The guide follows the demo's own configuration. Names such as `agent-obo` and `users:delete` are
examples: use your own, and keep them consistent between PingOne and AWS.

> [!NOTE]
> Demo code, not a production integration kit.

## What's in this repo

| Folder | What it is |
|---|---|
| [`agent/`](agent/) | The demo's Strands agent on AgentCore Runtime (Python, Strands Agents 1.64 and MCP SDK 2.3). It exchanges the user's PingOne token for a Gateway token through AgentCore Identity and calls the Gateway's tools. |
| [`p1az-ciba-authorizer/`](p1az-ciba-authorizer/) | The authorizer Lambda (Rust), deployed as the Gateway's interceptor. It sends each call to PingOne Authorize API Access Management and, when the policy asks for approval, runs PingOne CIBA, with approval records in DynamoDB. It's a fork of the PingOne Authorize AWS Bedrock Gateway Lambda authorizer prototype. |

## Goals

- Decide every MCP tool call with a PingOne Authorize policy that sees the user's permissions, the tool, and its
  arguments.
- Require the user's approval through CIBA for sensitive calls. The approval is tied to the exact request and the
  same user, and works once.
- Keep the user's identity on every hop with on-behalf-of token exchange
  ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)). Each MCP server receives a token minted for it alone that
  names the user and the agents acting for them.
- Tell the user why a call was refused, in the policy's own words.

## How it works

![Architecture: the user signs in with PingOne SSO and chats with the agent on AgentCore Runtime. The agent exchanges the user's token through AgentCore Identity and calls tools on AgentCore Gateway. The Gateway runs the Lambda authorizer, which asks PingOne Authorize, starts PingOne CIBA approvals that reach the user by email, and records approvals in DynamoDB. The Gateway then calls your MCP servers with a token minted for each server.](docs/architecture.svg)

Numbers match the steps below. Both token exchanges go through AgentCore Identity and PingOne SSO: the agent's for
the Gateway token, and the Gateway's for each MCP server's token.

1. **The user signs in.** Your chat app signs the user in with PingOne. The sign-in token is valid only at the agent
   runtime and names the agent in `may_act`.
2. **The agent gets a Gateway token.** AgentCore Identity exchanges the user's token for one valid only at the
   Gateway, with `act` naming the agent.
3. **The interceptor asks PingOne Authorize.** The Gateway runs the authorizer Lambda on every request. The Lambda
   sends the request to PingOne Authorize API Access Management, which applies your policy.
4. **A sensitive call waits for approval.** When the policy asks for approval, the Lambda starts a PingOne CIBA
   request and holds the call while it waits. If the user hasn't answered yet, it returns an MCP `input_required`
   result with a sealed `requestState` and the approval code. The agent's MCP client sends the same call again with
   that state, with no extra code, until the user answers.
5. **The approved call goes ahead once.** The Lambda checks that the approval matches this request and user, asks
   PingOne Authorize again with a trusted approval header that only the Lambda can set, and records the approval as
   used in DynamoDB.
6. **The MCP server gets its own token.** The Gateway exchanges the Gateway token for one valid only at that MCP
   server, with `act` naming the Gateway and the agent.

> [!NOTE]
> For how AgentCore Identity uses PingOne for inbound authentication and outbound credentials in general, see
> [Securing Amazon Bedrock AgentCore Identity with Ping Identity](https://developer.pingidentity.com/identity-for-ai/integrations/idai-securing-aws-ping.html).
> This demo builds on that pattern with token exchange, policy and approvals.

## Before you begin

You need:

- A PingOne environment with PingOne SSO, DaVinci and PingOne Authorize (API Access Management), and an admin who can
  create applications, resources and policies.
- An AWS account with Amazon Bedrock AgentCore in your Region, and permission to create IAM roles, Lambda functions
  and DynamoDB tables.
- MCP servers reachable over HTTPS (streamable HTTP) that validate PingOne access tokens: issuer, signature, and an
  audience equal to the server's own URL. Tools that act on a person should take that person's username as an
  argument (the demo uses `user_name`) so the policy can read it. Check each server behind a `2026-07-28` Gateway
  first: some older servers refuse what the Gateway passes on (see the [known issue](#known-issue) below).
- The authorizer Lambda package `bootstrap.zip`, built from the [`p1az-ciba-authorizer`](p1az-ciba-authorizer/)
  source for arm64 with `make docker-package` or `cargo lambda build --release --arm64 --bin bedrock`.
- An agent whose MCP client supports protocol version `2026-07-28`: MCP Python SDK 2.0 or later, or Strands Agents
  1.64 or later with its `MCPClient`. These clients complete approvals on their own
  ([step 11](https://aws-agentcore-ping.pingtapdemos.com/#agent) of the setup guide). The agent also calls AgentCore
  Identity for its Gateway token. The demo's Strands agent, in [`agent/`](agent/), is the reference.

## Set it up

The [setup guide](https://aws-agentcore-ping.pingtapdemos.com/) continues from here, in eleven steps: PingOne
resources and applications, roles, CIBA, the AgentCore Identity credential providers, the Gateway and its targets,
the agent on AgentCore Runtime, API Access Management, the policy, the authorizer Lambda, and the agent's Gateway
token and approvals. It ends with tests and troubleshooting.

For what the demo does and what we learned building it, see the
[blog post](https://blog.pingtapdemos.com/agentcore-gateway-approvals/). Each folder's README covers its own
configuration, build and tests.

## Known issue

AgentCore Gateway currently passes the client's `2026-07-28` fields in `params._meta`
(`io.modelcontextprotocol/protocolVersion`, `clientInfo` and `clientCapabilities`) on to MCP servers it talks to at an
older version. A server that ignores those fields works, like the demo's Slack server. A server that checks them
against the request's headers refuses the request, with errors such as "Header MCP-Protocol-Version does not match the
request body" or "Missing required header Mcp-Method". With `listingMode` `DYNAMIC`, the agent's whole tool list then
fails.

Snowflake's managed MCP server, which supports protocol version 2025-11-25, is one of these, so the demo leaves it off
the Gateway for now. The authorizer can't remove the fields, because the Gateway requires them in the interceptor's
output. We've reported the issue to AWS. Until it's fixed, try each MCP server through the Gateway before you rely on
it.

## Earlier version

This repo used to hold a Python interceptor that called the PingOne Authorize decision endpoint
(`pingone_authorize_interceptor.py`). It's still in the history at commit `14ebe74`.
