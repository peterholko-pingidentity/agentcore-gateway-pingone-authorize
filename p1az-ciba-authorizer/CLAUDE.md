# CLAUDE.md -- Maintainer Documentation

Maintainer-facing documentation for the AWS Bedrock Gateway Lambda Authorizer. For background, installation, configuration, build, and deploy instructions, see [README.md](README.md).

## How It Works

This Lambda function is deployed as **both** a Bedrock AgentCore Gateway **REQUEST interceptor** and a **RESPONSE interceptor** (the same binary handles both phases; it distinguishes them by the presence of `gatewayResponse` in the event).

**REQUEST phase.** When an MCP client (or AI agent) invokes a tool through the Gateway, this Lambda:

1. **Receives** the full MCP JSON-RPC request from the Bedrock AgentCore Gateway (including headers and body).
2. **Translates** the request into the P1AZ [sideband protocol](https://docs.pingidentity.com/pingone/authorization_using_pingone_authorize/p1_az_api_access_management.html) `InboundRequest` format.
3. **Calls** PingOne Authorize for an authorization decision (`POST /sideband/request`)
4. Based on the response:
   - **PERMIT**: Returns a `transformedGatewayRequest` -- the (possibly modified) request is forwarded to the backend MCP server.
   - **DENY**: Returns a `transformedGatewayResponse` -- the Gateway's instruction to respond to the client with the denial.
   - **ERROR**: Returns a `transformedGatewayResponse` -- the Gateway's instruction to respond to the client with the error.

On PERMIT, the REQUEST phase also stashes P1AZ's `state` value (the sideband spec's
opaque request-correlation token, `InboundRequestResult.state`) in an `x-paz-state`
header on the forwarded request, so the RESPONSE phase can replay it.

**Auth error mode (`AUTH_ERROR_MODE`, optional).** By default a challenge reaches the
client as a transport-level HTTP 4xx with a `www-authenticate` header. When
`AUTH_ERROR_MODE=jsonrpc` is set, every path that would deliver such a challenge
converts it to an **in-band** response: HTTP 200 with a JSON-RPC error body of code
`-32081` and `error.message` = the challenge's `error_description` parameter (fallback
"Authentication required"). `error.data` nests everything under the reverse-DNS key
`com.pingidentity/auth-challenge` (MCP `_meta`-style vendor namespacing, so a client
can tell this gateway's -32081 from any other vendor's server-defined error):
`www_authenticate` (verbatim header), `status` (original HTTP status), `scheme`, and
one field per challenge attribute pair (lowercased keys, quotes/escapes resolved) --
fully recomposable without parsing the verbatim string. The `www-authenticate` header
(and any stale `content-length`) never rides the transport to the client; other headers
(e.g. `mcp-session-id`) are preserved. The two conversion sites: the RESPONSE-phase
forward of a genuine backend response, and the RESPONSE-phase deny-header re-hydration.
The REQUEST phase is mode-invariant: a challenge DENY always keeps its transport-level
4xx short-circuit + `x-paz-response-headers` carrier here, because Bedrock delivers a
short-circuit via the RESPONSE interceptor's output (runtime verified -- converting at
the REQUEST phase left the client with an empty response). Never
converted: 429, 5xx, 4xx without `www-authenticate`, fail-closed 502/429, and
streaming/unknown pass-throughs. Unset/empty keeps the transport-level behavior. Any
other value panics at init. Error-code vocabulary: `-32080` generic P1AZ authorization
error (wrapped deny bodies), `-32081` auth challenge, `-32603` internal/infra errors.

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
      |               (+ x-paz-state header)
      |-- DENY ----> transformedGatewayResponse --> Client (short-circuit)
      |               + transformedGatewayRequest carrying x-paz-response-headers
      |-- ERROR ---> transformedGatewayResponse --> Client (502/429)
```

**RESPONSE phase.** The RESPONSE interceptor runs for both a genuine backend
response (following a PERMIT on REQUEST phase) and a DENY short-circuit (which never reaches the
backend, but Bedrock still invokes the RESPONSE interceptor to let it attach deny
headers). The two are told apart by which carrier header survived into
`gatewayRequest.headers`:

- **`x-paz-state` present** (PERMIT path) -- this is a genuine backend response.
  It's translated into the sideband protocol's `OutboundResponse` format (with
  `state` echoed back) and sent to `POST /sideband/response`. Unlike the REQUEST
  phase there is no PERMIT/DENY branch here -- the client always receives a
  response, but policy may transform it -- so the (possibly transformed)
  `OutboundResponseResult` is forwarded to the client verbatim. If the call to
  P1AZ errors, the Lambda **fails closed** (502, or 429 on rate limiting) rather
  than returning an unauthorized response.
  - Authorization only happens for a genuinely complete, non-streaming
    response: if `gatewayResponse.isStreamingResponse` is `true` or absent
    (Bedrock doesn't always report it), the response is passed through
    **unauthorized** rather than risk authorizing a partial chunk. If it's
    explicitly `false` but no `statusCode` is present, it also passes through
    unauthorized.
  - The sideband protocol requires a non-empty `headers` object on
    `OutboundResponse`, but Bedrock Gateway doesn't guarantee it sends the
    RESPONSE interceptor any response headers. If `gatewayResponse.headers` is
    absent or empty, this Lambda synthesizes a `content-type: application/json`
    header before authorizing.
- **`x-paz-state` absent, `x-paz-response-headers` present** (DENY path) --
  Bedrock forbids a REQUEST interceptor's `transformedGatewayResponse` from
  carrying headers, so a DENY's response headers (e.g. `www-authenticate` on a
  401) can't be returned directly by the REQUEST phase. Instead, the REQUEST
  phase emits a `transformedGatewayRequest` that mirrors the original request and
  adds an `x-paz-response-headers` header containing the base64-encoded JSON of
  the deny headers. That mirrored request is never forwarded (the accompanying
  `transformedGatewayResponse` short-circuits the call), but the RESPONSE
  interceptor still sees the carrier in `gatewayRequest.headers`, decodes it, and
  sets those headers on the outgoing `transformedGatewayResponse` -- which, as a
  RESPONSE interceptor, is allowed to carry headers -- preserving the response's
  status code and body. **No `/sideband/response` call is made** for a denied
  request's response.
- **Neither present** -- passes the response through unchanged.

```
Bedrock AgentCore Gateway
      |
      v
[This Lambda, RESPONSE phase]
      |
      |-- x-paz-state present --------> POST /sideband/response --> PingOne Authorize
      |                                        |
      |                     <-- (possibly transformed) OutboundResponseResult --
      |                     --> transformedGatewayResponse --> Client
      |
      |-- x-paz-response-headers only -> decode --> transformedGatewayResponse
      |                                              (+ preserved statusCode/body) --> Client
      |
      |-- neither ---------------------> pass through --> Client
```

## Project Layout

The codebase separates handler-specific logic from shared sideband protocol logic:

- **`src/models.rs`** -- Shared sideband protocol types (handler-agnostic)
- **`src/helpers.rs`** -- Shared utilities for header conversion, URL building, JSON-RPC formatting
- **`src/sideband_client.rs`** -- Shared HTTP client for P1AZ sideband calls
- **`src/config.rs`** -- Configuration from environment variables
- **`src/handlers/bedrock.rs`** -- Bedrock AgentCore event types and transform logic
- **`src/bin/bedrock.rs`** -- Lambda entrypoint for Bedrock AgentCore
- **`src/ciba.rs`** -- (fork) CIBA approval flow
- **`src/approval_store.rs`** -- (fork) DynamoDB approval table (SigV4 over reqwest) and an in-memory store

## CIBA approval flow (fork)

Enabled by `CibaConfig::from_env()` (any `CIBA_AUTHORIZATION_ENDPOINT`); the
entrypoint then calls `handle_request_with_ciba(.., Some(&ciba))`. With `None`
-- and through `handle_request`, whose signature is unchanged -- the behavior is
exactly upstream's, so upstream tests and fixtures still apply verbatim.

Only the REQUEST phase changes (`handle_request_phase_with_ciba`, `send_approved`);
the RESPONSE phase is untouched. The flow is MCP 2026-07-28 multi round-trip
requests:
- a pending approval answers an `input_required` **result** with a sealed
  `requestState`;
- the client retries the identical call with it;
- `Ciba::redeem` holds each invocation up to `hold_seconds`, polling the provider.

The authorizer's own short-circuits (`input_required` results, `-32080` refusals
with `data.reason` and a plain-words message) are HTTP 200s with no headers and no
carrier, so the RESPONSE phase passes them through ("neither present").

Invariants worth keeping:

- `params.requestState` and `params.inputResponses` are removed (and the raw body
  re-serialized) **before** `/sideband/request`. `params._meta` is left alone: it
  is the protocol's envelope, and the Gateway may check it against the
  `MCP-Protocol-Version` header.
- The trusted `x-ciba-approval` / `x-ciba-approver` headers are stripped from
  every client request and from the forwarded request. Only `send_approved` sets
  them, after `Ciba::redeem` succeeded.
- `requestState` is HMAC-SHA256-sealed with `CIBA_STATE_KEY` (`seal`/`unseal`).
  `Ciba::open_state` refuses it unless the seal, the caller's subject, the request
  fingerprint and the expiry all match. Its contents are readable (integrity
  only), so it must never carry secrets.
- The idempotency key is SHA-256 of the caller's subject + `mcp-session-id` + raw
  body, computed before anything is removed. A gateway retry of the same request
  matches; a client retry (new JSON-RPC `id`) doesn't. The subject is in it
  because 2026-07-28 has no sessions.
- `Ciba::spend` is the only writer of `spent#…` and uses a conditional put; a
  failed condition is a refusal unless the existing record has the same key.
- With table binding (PingOne), the `request#…` record is checked **before**
  polling the provider, so a mismatched request can't use up the approval.
- `hold_seconds` plus a sideband call, a provider poll and two DynamoDB calls
  must fit the Lambda timeout (60 s in the demo for a 20 s hold).
- `requested_expiry` stays under a stock client's 10 retries × `hold_seconds`,
  so the approval expires with a clear refusal before the client gives up.
- On PERMIT, `build_bedrock_response` drops the `Authorization` header when it
  equals the client's (a policy-changed one is still forwarded). AgentCore
  forwards an interceptor's `Authorization` to the target in place of the
  target's credential provider, so echoing the Gateway token back broke targets
  with on-behalf-of token exchange ("Token exchange failed.", no tools listed).
- RESPONSE-phase pass-throughs echo `gatewayResponse` (`pass_through`): AgentCore
  sends an empty `mcp` output to the client as an empty `{}` body.
- `RESPONSE_AUTHORIZATION=off` (`config::response_authorization_from_env`) drops
  `x-paz-state` from every output (`drop_state_carrier`, in the binary): the
  carrier only reaches the RESPONSE phase when the targets allowlist it, the
  Gateway then forwards it to them, and at ~6 KB it is over AgentCore's 4 KB
  limit for a forwarded header value.

Tests: `tests/ciba_flow_test.rs` (end to end against wiremock playing the
sideband API and the provider, with the in-memory store) and
`tests/dynamodb_store_test.rs` (request shape and SigV4 headers against a mock
DynamoDB endpoint).

## Example Bedrock AgentCore Event

Below is an example event passed to the Lambda by the Bedrock AgentCore Gateway:

```json
{
  "interceptorInputVersion": "1.0",
  "mcp": {
    "gatewayRequest": {
        "path": "/mcp",
        "httpMethod": "POST",
        "headers": {
            "referer": "http://localhost:6274/",
            "x-amzn-tls-version": "TLSv1.3",
            "sec-fetch-site": "cross-site",
            "origin": "http://localhost:6274",
            "x-amzn-vpce-policy-url": "",
            "authorization": "Bearer ey...REDACTED...mA",
            "x-amzn-tls-cipher-suite": "TLS_AES_128_GCM_SHA256",
            "sec-ch-ua-mobile": "?0",
            "content-type": "application/json",
            "Content-Length": "164",
            "sec-fetch-mode": "cors",
            "x-amzn-vpce-config": "",
            "accept-language": "en-US,en;q=0.9",
            "X-Forwarded-Proto": "https",
            "Host": "mcp-protocol-lab-gateway-v3-4ab20jawt3.gateway.bedrock-agentcore.us-east-1.amazonaws.com",
            "x-amzn-vpc-id": "",
            "priority": "u=1, i",
            "X-Forwarded-Port": "443",
            "X-Amzn-Trace-Id": "Root=1-69d73a18-3dda03e45b13a84878ca3d72",
            "accept": "application/json, text/event-stream",
            "sec-ch-ua": "\"Chromium\";v=\"146\", \"Not-A.Brand\";v=\"24\", \"Google Chrome\";v=\"146\"",
            "mcp-protocol-version": "2025-11-25",
            "sec-ch-ua-platform": "\"macOS\"",
            "X-Forwarded-For": "136.62.193.165",
            "x-amzn-vpce-id": "",
            "accept-encoding": "gzip, deflate, br, zstd",
            "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
            "sec-fetch-dest": "empty"
        },
        "body": {
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "mcp-protocol-lab___echo_payload",
                "_meta": {
                    "progressToken": 3
                },
                "arguments": {
                    "note": "this is a note"
                }
            },
            "jsonrpc": "2.0"
        },
        "context": null
    },
    "gatewayResponse": null,
    "rawGatewayRequest": {
        "body": "{\"method\":\"tools/call\",\"params\":{\"name\":\"mcp-protocol-lab___echo_payload\",\"arguments\":{\"note\":\"this is a note\"},\"_meta\":{\"progressToken\":3}},\"jsonrpc\":\"2.0\",\"id\":3}"
    }
  }
}
```
