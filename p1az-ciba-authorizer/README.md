# AWS Bedrock Gateway Lambda Authorizer

> **NOTE: This is a prototype, not a production integration kit.**

> **Fork:** this copy adds an optional **CIBA approval flow** -- a PingOne
> Authorize policy can ask for the user's approval on another device (PingOne or
> PingFederate CIBA) instead of only permitting or denying. It's off unless the
> `CIBA_*` variables are set; without them the authorizer behaves exactly as
> upstream. See [CIBA approval flow](#ciba-approval-flow-fork).

A AWS Lambda authorizer that integrates [PingOne Authorize](https://www.pingidentity.com/en/platform/capabilities/authorization-management.html) (P1AZ) with [AWS Bedrock AgentCore Gateways](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway.html) to authorize MCP (Model Context Protocol) tool calls.

## How It Works

This Lambda function is deployed as **both** a Bedrock AgentCore Gateway **REQUEST interceptor** and a **RESPONSE interceptor** (the same binary handles both phases; it distinguishes them by the presence of `gatewayResponse` in the event).

**REQUEST phase.** When an MCP client (or AI agent) invokes a tool through the Gateway, this Lambda:

1. **Receives** the full MCP JSON-RPC request from the Bedrock AgentCore Gateway (including headers and body).
2. **Translates** the request into the P1AZ [sideband protocol](https://docs.pingidentity.com/pingone/authorization_using_pingone_authorize/p1_az_api_access_management.html) `InboundRequest` format.
3. **Calls** PingOne Authorize for an authorization decision (`POST /sideband/request`)
4. Based on the response:
   - **PERMIT**: The (possibly modified) request is forwarded to the backend MCP server.
   - **DENY**: The Gateway is instructed to respond to the client with the denial.
   - **ERROR**: The Gateway is instructed to respond to the client with an error.

```
MCP Client/Agent
      |
      v
Bedrock AgentCore Gateway
      |
      v
[This Lambda] --POST /sideband/request--> PingOne Authorize
      |                                          |
      |<---------- authorization decision -------|
      |
      |-- PERMIT --> transformedGatewayRequest  --> Backend MCP Server
      |-- DENY ----> transformedGatewayResponse --> Client (short-circuit)
      |-- ERROR ---> transformedGatewayResponse --> Client (502/429)
```

**RESPONSE phase.** The RESPONSE interceptor runs for both a genuine backend
response (following a PERMIT on REQUEST phase) and a DENY or ERROR short-circuit (which never reaches the backend, but Bedrock still invokes the RESPONSE interceptor).

- For genuine backend responses, this Lambda authorizes against P1AZ (`POST /sideband/response`), transforming the responses before they reach the client.
- For requests that resulted in DENY or ERROR, the RESPONSE phase is used to attach the error details.

For the full mechanics see [CLAUDE.md](CLAUDE.md).

## Background

### PingOne Authorize

PingOne Authorize (P1AZ) supports an external authorization pattern specifically designed for API Gateways to authorize HTTP transactions. Plugins, or Integration Kits (IKs), send their client's HTTP transaction to P1AZ. This "protocol" is sometimes called the "sideband" protocol. It supports request/inbound authorization and response/outbound authorization. See [PingOne Authorize API Access Management](https://docs.pingidentity.com/pingone/authorization_using_pingone_authorize/p1_az_api_access_management.html).

### AWS Bedrock AgentCore Gateway

AWS Bedrock AgentCore Gateway is a Model Context Protocol (MCP) Gateway. Similar to AWS API Gateways, MCP Gateways provide access, security, observability, and other features for MCP workloads inside of AWS. The MCP Gateways support Lambda for "transformers" (interceptors), which are invoked with the full JSON-RPC request, including headers and body. The Lambda can transform the request, which is then forwarded to the backend MCP workload. Or the Lambda can return a response, which causes the MCP Gateway to immediately respond to the requesting client or agent. This is ideal for our external authorization scenario.

For the Bedrock AgentCore interceptor specification, see:
- [Interceptor types](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-interceptors-types.html)
- [Header propagation](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-headers.html#gateway-headers-interceptor-propagation)

## Configuration

The Lambda is configured via environment variables:

| Variable | Required | Default | Description |
|---|---|---|---|
| `SERVICE_URL` | Yes | -- | P1AZ sideband API base URL (e.g., `https://http-access-policy.pingone.com/v1/environments/<env-id>`) |
| `SECRET_HEADER_VALUE` | Yes | -- | Shared secret for P1AZ authentication (sent as the `Client-Token` header) |
| `AUTH_ERROR_MODE` | No | unset | How auth challenges are returned to clients -- see [Auth error modes](#auth-error-modes). Any other value than the supported modes aborts at startup. |
| `RUST_LOG` | No | `info` | Logging level. Use `trace` for full request/response dumps, `debug` for operational details, `info` for decisions only. |
| `RESPONSE_AUTHORIZATION` | No | `on` | (fork) `off`: no `x-paz-state` carrier, so responses pass through unauthorized. Needed when the targets would have to forward the carrier: AgentCore caps a forwarded header value at 4 KB, and the state is about 6 KB with a PingOne access token in the request. |

## CIBA approval flow (fork)

Some tool calls should only go ahead after the user has approved them on another
device (deleting an account, moving money). With the CIBA variables set, a policy
asks for that approval by **denying with an `auth-challenge` statement whose
`acrValues` include `ciba-approval`** (`CIBA_CHALLENGE_ACR`). Instead of passing
the challenge to the client, the authorizer uses **MCP 2026-07-28 multi
round-trip requests**, so any 2026-07-28 client (MCP SDK 2.x, Strands 1.64+)
completes the approval with no custom code:

1. it sends a CIBA request to the provider (`CIBA_PROVIDER`: `pingfederate` or
   `pingone`) naming the caller (`login_hint`, from the bearer token) with a
   binding message such as `APR-4821`; with PingFederate it also describes the
   exact request in `authorization_details`;
2. it **holds** the call for up to `CIBA_HOLD_SECONDS` (default 20), polling the
   provider. If the user approves in that time, the request goes on at once
   (step 4);
3. otherwise it answers HTTP 200 with an **`input_required` result**. Its
   `requestState` is sealed with HMAC-SHA256 (`CIBA_STATE_KEY`) and names the
   approval: provider reference, caller, request fingerprint and expiry. Its
   `_meta["com.pingidentity/approval"]` carries `bindingMessage` and
   `expiresIn` for clients that show them. The client **retries the identical
   call** with that `requestState`, and the authorizer checks the seal, the caller
   and the request, then holds and polls again;
4. once approved, it checks the approval was given by the caller for this exact
   request, sends the request to `/sideband/request` again with the trusted
   headers **`x-ciba-approval: approved`** and **`x-ciba-approver: <sub>`** (the
   policy permits on those), records the approval as spent in DynamoDB
   (conditional write, so an approval is used once), and forwards the request
   without `requestState`, `inputResponses` or the trusted headers.

The trusted headers are removed from every client request before it reaches the
sideband API, so only the authorizer can set them. `params._meta`, the
protocol's own envelope, is forwarded unchanged.

```
Agent -> Gateway -> [Lambda] -> /sideband/request -> DENY + challenge(acr ciba-approval)
                       |-> CIBA request (PingFederate/PingOne) -> user's device
                       |-> hold up to 20 s, polling the provider
Agent <- result {resultType: input_required, requestState, _meta: {bindingMessage}}
Agent -> same call + requestState -> [Lambda] -> check seal, caller, request
                       |-> DynamoDB (spent? request matches?) -> hold and poll
                       |-> /sideband/request + x-ciba-approval -> PERMIT
                       |-> DynamoDB: put spent (if absent) -> forward to the MCP server
```

### Policy contract

- **Ask for an approval:** deny with an `auth-challenge` statement, for example
  `{"httpStatus": 401, "error": "insufficient_user_authentication", "acrValues": ["ciba-approval"]}`,
  when the request needs approval and the `x-ciba-approval` request header isn't
  `approved`.
- **Permit the approved request:** permit when `x-ciba-approval` is `approved`
  (read it from `PingOne.API Access Management.HTTP.Request.Headers`); the approver's
  `sub` is in `x-ciba-approver`.
- Put the other deny rules first, so nobody is asked to approve a request that
  would be refused anyway. If the policy asks again after an approval, the
  authorizer refuses with `approval_not_accepted` instead of looping.

### Client contract

Any MCP **2026-07-28** client: on an `input_required` result, retry the same
call with a new JSON-RPC `id` and the unchanged `requestState`, until a final
result or error. MCP SDK 2.x and Strands 1.64+ do this by themselves. They stop
after 10 retries, which is why `CIBA_REQUESTED_EXPIRY` (180) is shorter than 10 ×
`CIBA_HOLD_SECONDS`: the approval expires, with a clear refusal, before the client
gives up. The Gateway should list only `2026-07-28` in
`protocolConfiguration.mcp.supportedVersions`.

The authorizer's own refusals are HTTP 200 JSON-RPC `-32080` errors with
`data.reason` and a plain-words `message`, because most clients show the model only
the message. Policy denials are upstream's `-32080`/`-32081`.

| `data.reason` | Meaning |
|---|---|
| `approval_denied` / `approval_expired` | The user declined / the approval (or its `requestState`) expired. |
| `approval_reference_invalid` | The `requestState` was altered, forged or malformed, or the provider doesn't know the reference. |
| `approval_mismatch` | The `requestState` or approval belongs to another user or another request. |
| `approval_already_used` | The approval was used by another request. |
| `approval_not_accepted` | The policy asked for an approval again after one was given. |
| `approval_unavailable` | The caller's token lacks `CIBA_LOGIN_HINT_CLAIM` (or, with table binding, `CIBA_SUBJECT_CLAIM`), or the request is batched. |
| `ciba_unavailable` | The provider couldn't be reached or rejected the client. |
| `approval_store_unavailable` | DynamoDB couldn't be reached. |

### PingFederate or PingOne

| | PingFederate | PingOne |
|---|---|---|
| `CIBA_AUTHORIZATION_ENDPOINT` | `https://<host>/as/bc-auth.ciba` | `https://auth.pingone.<tld>/<envId>/as/cibaAuthorization` |
| `CIBA_TOKEN_ENDPOINT` | `https://<host>/as/token.oauth2` | `https://auth.pingone.<tld>/<envId>/as/token` |
| Binding message | up to 20 characters | up to 8 (`APR-4821` fits) |
| Request binding | `authorization_details` returned with the approval (needs PingFederate 11.2+, an authorization detail type `mcp_request` and processor) | `request#…` record in the table, checked before redeeming |

Both bind the approval to the request a second time through the sealed `requestState`.

### CIBA configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `CIBA_AUTHORIZATION_ENDPOINT` | For CIBA | -- | Enables the flow. The provider's CIBA endpoint. |
| `CIBA_TOKEN_ENDPOINT` | For CIBA | -- | The provider's token endpoint. |
| `CIBA_CLIENT_ID` / `CIBA_CLIENT_SECRET` | For CIBA | -- | The CIBA client (poll mode, HTTP Basic). |
| `CIBA_TABLE` | For CIBA | -- | DynamoDB table: partition key `pk` (string), TTL on `ttl`. |
| `CIBA_STATE_KEY` | For CIBA | -- | Secret HMAC key for `requestState`, at least 32 characters (e.g. `openssl rand -hex 32`). Changing it invalidates pending approvals. |
| `CIBA_PROVIDER` | No | `pingfederate` | `pingfederate` or `pingone`. |
| `CIBA_HOLD_SECONDS` | No | `20` | Longest wait for the user in one invocation before answering `input_required`. Keep it well under the Lambda timeout. |
| `CIBA_CHALLENGE_ACR` | No | `ciba-approval` | `acr_values` entry that marks a challenge as "get a CIBA approval". |
| `CIBA_APPROVAL_HEADER` / `CIBA_APPROVER_HEADER` | No | `x-ciba-approval` / `x-ciba-approver` | Trusted headers set on an approved request. |
| `CIBA_SCOPE` | No | `openid` | Scope of the CIBA request. |
| `CIBA_LOGIN_HINT_CLAIM` | No | `sub` | Caller-token claim sent as `login_hint` (PingOne's DaVinci approval flows usually need `username`). |
| `CIBA_SUBJECT_CLAIM` | No | `sub` | Caller-token claim that must equal the approver's `sub`. |
| `CIBA_REQUESTED_EXPIRY` | No | `180` | Requested approval lifetime; keep it under 10 × `CIBA_HOLD_SECONDS` (see the client contract). |
| `CIBA_BINDING_MESSAGE_PREFIX` | No | `APR` | Must fit the provider's limit with `-NNNN`. |
| `CIBA_AUTHORIZATION_DETAILS_TYPE` | No | `mcp_request` | PingFederate `authorization_details` type; empty binds requests through the table instead. |
| `CIBA_POLL_INTERVAL` | No | `5` | Seconds between polls while holding, when the provider gives no interval (+5 after `slow_down`). |
| `CIBA_TABLE_TTL_SECONDS` | No | `86400` | Item lifetime; never shorter than `CIBA_REQUESTED_EXPIRY`. |
| `CIBA_HTTP_TIMEOUT` | No | `5` | Seconds, for provider and DynamoDB calls. |
| `CIBA_DYNAMODB_ENDPOINT` | No | regional endpoint | Override (tests, VPC endpoints). |

A partial or invalid CIBA configuration aborts at startup, like the sideband variables.

### DynamoDB table and permissions

```bash
aws dynamodb create-table --table-name acgw-ciba \
  --attribute-definitions AttributeName=pk,AttributeType=S \
  --key-schema AttributeName=pk,KeyType=HASH --billing-mode PAY_PER_REQUEST
```

```bash
aws dynamodb update-time-to-live --table-name acgw-ciba \
  --time-to-live-specification Enabled=true,AttributeName=ttl
```

Give the Lambda's role `dynamodb:GetItem` and `dynamodb:PutItem` on that table.
The authorizer calls DynamoDB's JSON API directly (SigV4-signed with the Lambda's
credentials) instead of linking the AWS SDK, so the binary stays small. Set the
Lambda timeout to about 60 seconds: one invocation can hold for
`CIBA_HOLD_SECONDS`, then call the sideband API, DynamoDB and the provider in turn.

If the provider treats `auth_req_id` as single-use, an approval redeemed by a
request the policy then denies (or that times out before the spent record is
written) is used up, and the user has to approve again.

## Developer Integration Notes

Details to understand when developing an agent that that integrates with an MCP server protected
by this Lambda and PingOne Authorize.

### Response errors

JSON-RPC error codes returned by this Lambda:

| Code | Meaning |
|---|---|
| `-32080` | Generic P1AZ authorization error (used in wrapped deny bodies) |
| `-32081` | Auth challenge (only in `AUTH_ERROR_MODE=jsonrpc` responses. See below.) |
| `-32603` | Internal error (fail-closed infra failures) |

### Auth error modes

By default, and per MCP specification, an authorization challenge reaches the client as a
transport-level HTTP 4xx with a `www-authenticate` response header. Many MCP client libraries
destroy transport-level challenges in transit. Aa a workaround, setting `AUTH_ERROR_MODE=jsonrpc` converts
them into an **in-band** challenge instead:

- **HTTP 200** with a JSON-RPC error body of code `-32081`, whose `error.data` nests
  every detail under the reverse-DNS key `com.pingidentity/auth-challenge` (MCP
  `_meta`-style namespacing), so a client can tell this gateway's -32081 from any other
  vendor's server-defined error in the vendor-specific -32000..-32099 range:

  ```json
  {
    "jsonrpc": "2.0",
    "id": 42,
    "error": {
      "code": -32081,
      "message": "Token expired",
      "data": {
        "com.pingidentity/auth-challenge": {
          "www_authenticate": "Bearer error=\"invalid_token\", error_description=\"Token expired\"",
          "status": 401,
          "scheme": "Bearer",
          "error": "invalid_token",
          "error_description": "Token expired"
        }
      }
    }
  }
  ```

- `error.message` is the challenge's `error_description` parameter, or
  `"Authentication required"` if the header carries none.
- Inside the `com.pingidentity/auth-challenge` object: `www_authenticate` is the
  verbatim header value, `status` is the original HTTP status, `scheme` is the auth
  scheme token, and each attribute pair of the challenge is broken out as its own
  field (lowercased keys, quotes/escapes resolved) — so a client can recompose a
  different `www-authenticate` header without parsing the verbatim string.
- The transport-level `www-authenticate` header is removed from the response.

The conversion applies to all three RESPONSE-phase paths that can deliver a 4xx +
`www-authenticate` to the client:
- the result of a REQUEST-phase P1AZ DENY,
- the backend MCP response denied during RESPONSE-phase authorization,
- or a genuine MCP backend response with a `www-authenticate`,

**Never converted**: These remain as transport-level errors:
- HTTP 429 (rate limiting is not a step-up-able challenge),
- 5xx, 4xx without a `www-authenticate` header,
- fail-closed errors (502/429 when the P1AZ call itself fails).


## Prerequisites

- The same Lambda must be configured as **both** the REQUEST and RESPONSE interceptor -- response authorization and deny-header propagation both depend on the RESPONSE interceptor being invoked. If only the REQUEST interceptor is configured, PERMIT/DENY decisions still work, but responses are never authorized and deny response headers (e.g. `www-authenticate`) are not returned to the client.
- The Bedrock AgentCore Gateway interceptor must be configured with `passRequestHeaders: true` so that request headers (including `Authorization` and the `x-paz-state` / `x-paz-response-headers` carriers) are passed to the Lambda in both phases.
- The P1AZ environment must have a sideband API route configured to match the incoming request URLs, and must support the outbound/response phase (`POST /sideband/response`) for response authorization to take effect.
- Any custom headers that P1AZ policies modify on PERMIT must be added to the target's `allowedRequestHeaders` in the Gateway configuration. The `Authorization` header is automatically propagated from the interceptor Lambda without needing to be in the allowlist.
- The `x-paz-state` and `x-paz-response-headers` carrier headers must both be in the target's `allowedRequestHeaders` allowlist so they survive from the REQUEST phase into the RESPONSE interceptor's `gatewayRequest.headers`.

## Build

Requires [cargo-lambda](https://www.cargo-lambda.info/):

```bash
# Install cargo-lambda
cargo install cargo-lambda

# Build for ARM64 (Graviton) -- recommended for cost and performance
cargo lambda build --release --arm64 --bin bedrock

# The deployable binary is at: target/lambda/bedrock/bootstrap
```

Without cargo-lambda, build inside an Amazon Linux 2023 container on an ARM
machine (or with Docker's arm64 emulation), which links against the same glibc
as the Lambda runtime:

```bash
make docker-package   # -> target/lambda/bedrock/bootstrap.zip
```

## Deploy

1. Zip the bootstrap binary:
   ```bash
   cd target/lambda/bedrock && zip bootstrap.zip bootstrap
   ```
2. Create or update a Lambda function:
   - **Runtime**: `provided.al2023`
   - **Architecture**: `arm64`
   - **Handler**: `bootstrap`
   - **Environment variables**: Set `SERVICE_URL` and `SECRET_HEADER_VALUE` (optionally `AUTH_ERROR_MODE`, see [Configuration](#configuration))
3. Configure the Lambda as **both** the REQUEST and RESPONSE interceptor on your Bedrock AgentCore Gateway (see [Prerequisites](#prerequisites)).

## Logging

Logging uses the `tracing` framework and is controlled via the `RUST_LOG` environment variable.

| Level | What's Logged |
|---|---|
| `error` | Configuration failures, unrecoverable errors |
| `warn` | P1AZ returned 4xx/5xx errors, unexpected response formats |
| `info` | Handler invoked, PERMIT/DENY decision, P1AZ response status |
| `debug` | P1AZ URL, request method, response timing |
| `trace` | Full serialized sideband request body, full P1AZ response body, full Bedrock response body |

Examples:
```bash
RUST_LOG=info                                          # Production default
RUST_LOG=debug                                         # Operational troubleshooting
RUST_LOG=trace                                         # Full request/response inspection
RUST_LOG=aws_bedrock_lambda_authorizer=trace           # Trace only this crate
```

## Project Layout

The codebase separates handler-specific logic from shared sideband protocol logic:

- **`src/models.rs`** -- Shared sideband protocol types (handler-agnostic)
- **`src/helpers.rs`** -- Shared utilities for header conversion, URL building, JSON-RPC formatting
- **`src/sideband_client.rs`** -- Shared HTTP client for P1AZ sideband calls
- **`src/config.rs`** -- Configuration from environment variables
- **`src/handlers/bedrock.rs`** -- Bedrock AgentCore event types and transform logic
- **`src/bin/bedrock.rs`** -- Lambda entrypoint for Bedrock AgentCore
- **`src/ciba.rs`** -- (fork) CIBA approval flow: provider client, request fingerprints, approve/redeem/spend
- **`src/approval_store.rs`** -- (fork) DynamoDB approval table over SigV4-signed JSON API calls, plus an in-memory store for tests

## Current Limitations

- **Streaming responses are never authorized**: chunked `text/event-stream` responses (`gatewayResponse.isStreamingResponse: true`, or the field absent) are passed through unchanged rather than authorized -- only a response with `isStreamingResponse: false` and a `statusCode` is sent to `/sideband/response`.
- **No retry on P1AZ errors**: P1AZ 5xx responses are returned as errors immediately.
- **No circuit breaker**: P1AZ 429 (rate limit) responses are returned as-is without suppressing subsequent requests.
- **Placeholder source IP/port**: The sideband request uses `0.0.0.0:1`.
- **Hardcoded `Client-Token` header**: Only PingOne Authorize AAM is supported (not PingAuthorize's `PDG-TOKEN`).
- **Denied Headers vulnerability**: The `x-paz-response-headers` mechanism to forward the headers included in the authorization DENY responses to the RESPONSE phase is not protected with any cryptography to make it spoof- or tamper-proof.
