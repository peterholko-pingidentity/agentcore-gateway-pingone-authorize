# AgentCore Gateway → PingOne Authorize

An AWS Bedrock **AgentCore Gateway REQUEST interceptor** Lambda that submits every
inbound gateway request to **PingOne Authorize** for a policy decision, and
**blocks** the request when the decision is not `PERMIT`.

The interceptor runs before the gateway forwards a call to its target (an MCP
server or HTTP target). It turns the gateway into a policy enforcement point
(PEP) and delegates the authorization decision to PingOne Authorize as the policy
decision point (PDP).

```
MCP client ──▶ AgentCore Gateway ──▶ [ REQUEST interceptor (this Lambda) ]
                                              │
                                              ├─▶ PingOne Authorize (PDP)
                                              │      └─ PERMIT / DENY / …
                                              │
                       PERMIT ◀──────────────┤  allow  → forward to target
                       else   ◀──────────────┘  block  → short-circuit with error
```

## How it works

For each invocation the Lambda:

1. **Extracts** the inbound request from the AgentCore Gateway interceptor event
   (path, HTTP method, the full MCP/JSON-RPC body, and — when present — the
   decoded claims of the `Authorization` bearer token).
2. **Builds a generic decision request** containing that full request context.
   It makes **no assumption** about your PingOne policy or Trust Framework; it
   forwards everything so any policy can reference whatever attributes it needs.
3. **Calls the PingOne Authorize decision endpoint** over HTTPS, authenticating
   with a worker-app access token (client-credentials) or a static token.
4. **Enforces the decision**:
   - `PERMIT` → returns `transformedGatewayRequest`, so the gateway forwards the
     call to the target unchanged.
   - `DENY` / `NOT_APPLICABLE` / `INDETERMINATE` / anything unexpected → returns
     `transformedGatewayResponse`, which **short-circuits the gateway**: the
     target is never called and the caller receives a JSON-RPC error (HTTP `403`
     by default).

Returning a `transformedGatewayResponse` from a REQUEST interceptor is the
documented AgentCore mechanism for responding immediately without invoking the
target. See
[Using interceptors with Gateway](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-interceptors.html).

### Fail-closed by design

If `PINGONE_DECISION_ENDPOINT_URL` is unset, or PingOne is unreachable or returns
an error, the request is **blocked** by default. Set `PINGONE_FAIL_OPEN=true` to
allow requests through when the PDP cannot be consulted.

## The decision request body

The Lambda forwards a full snapshot of the request so any PingOne configuration
can consume it:

```json
{
  "attributes": {
    "path": "/mcp",
    "httpMethod": "POST",
    "body": {
      "jsonrpc": "2.0",
      "id": 7,
      "method": "tools/call",
      "params": { "name": "transfer_funds", "arguments": { "amount": 100 } }
    },
    "token": {
      "subject": "user-123",
      "client_id": "abc",
      "scope": "openid",
      "issuer": "https://auth.pingone.com/<envId>",
      "audience": "..."
    }
  }
}
```

The wrapping key (`attributes` above) is configurable via
`PINGONE_ATTRIBUTES_KEY`. Set it to your decision endpoint's expected key, or to
an empty string to send the context as the top-level object.

### Setting `PINGONE_ATTRIBUTES_KEY` and mapping the attributes

This is the setting that most often trips people up, because it must agree with
how your PingOne decision endpoint and Trust Framework attributes are defined.
Two independent things have to line up:

1. **The top-level key** (`PINGONE_ATTRIBUTES_KEY`) — the single wrapper object
   the decision endpoint reads request attributes from. Pick the value that
   matches your endpoint:

   | `PINGONE_ATTRIBUTES_KEY` | Body the Lambda sends | Use when your endpoint expects… |
   | --- | --- | --- |
   | `attributes` *(default)* | `{ "attributes": { …context } }` | attributes nested under `attributes` |
   | `parameters` | `{ "parameters": { …context } }` | a differently-named wrapper |
   | `` *(empty string)* | `{ …context }` | a flat, top-level attribute map |

2. **The attribute paths** — inside that wrapper, each Trust Framework attribute
   you want to evaluate resolves to a JSON path into the context. With the
   default key `attributes`, the example body above exposes these paths:

   | JSON path (resolver) | Example value | Typical policy use |
   | --- | --- | --- |
   | `attributes.path` | `/mcp` | Gateway request path |
   | `attributes.httpMethod` | `POST` | HTTP method |
   | `attributes.body.method` | `tools/call` | MCP/JSON-RPC method |
   | `attributes.body.params.name` | `transfer_funds` | Tool being invoked |
   | `attributes.body.params.arguments.amount` | `100` | A specific tool argument |
   | `attributes.token.subject` | `user-123` | Authenticated subject (`sub`) |
   | `attributes.token.client_id` | `abc` | Calling client |
   | `attributes.token.scope` | `openid` | Granted scopes |
   | `attributes.token.issuer` | `https://auth.pingone.com/<envId>` | Token issuer |

   If you set `PINGONE_ATTRIBUTES_KEY` to `parameters`, drop the `attributes.`
   prefix in favor of `parameters.` (e.g. `parameters.body.params.name`). If you
   set it to an empty string, drop the prefix entirely (e.g. `body.params.name`).

> **Note:** The `token.*` attributes are included only if `passRequestHeaders`
> is set to `true` in the interceptor configuration — otherwise the gateway does
> not pass request headers to the Lambda, and those paths will be absent.

## Configuration

All configuration is via Lambda environment variables.

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `PINGONE_DECISION_ENDPOINT_URL` | **Yes** | — | Full runtime URL of the decision endpoint (shown in the PingOne console), e.g. `https://auth.pingone.com/<envId>/as/decision/<decisionEndpointId>`. |
| `PINGONE_TOKEN_ENDPOINT` | For worker token | — | OAuth token endpoint for the client-credentials grant. |
| `PINGONE_CLIENT_ID` | For worker token | — | Worker-app client ID. |
| `PINGONE_CLIENT_SECRET` | For worker token | — | Worker-app client secret. |
| `PINGONE_TOKEN_SCOPE` | No | — | Optional scope requested for the worker token. |
| `PINGONE_ACCESS_TOKEN` | No | — | Static bearer token as an alternative to the grant (useful for testing). |
| `PINGONE_ATTRIBUTES_KEY` | No | `attributes` | Top-level key wrapping the request context; empty string sends a flat body. |
| `PINGONE_HTTP_TIMEOUT` | No | `5` | Network timeout (seconds) for calls to PingOne. |
| `PINGONE_FAIL_OPEN` | No | `false` | `true` allows requests through when the PDP cannot be consulted. |
| `PINGONE_DENY_STATUS_CODE` | No | `403` | HTTP status code returned to the caller for a blocked request. |

Authentication precedence: a client-credentials grant (all of
`PINGONE_TOKEN_ENDPOINT`, `PINGONE_CLIENT_ID`, `PINGONE_CLIENT_SECRET`) is used if
configured, with the token cached in memory until shortly before it expires;
otherwise `PINGONE_ACCESS_TOKEN` is used; otherwise the endpoint is called with no
`Authorization` header.

## Deployment

The Lambda uses only the Python standard library — no dependencies to package and
no layers required.

1. Create a Python 3.11+ Lambda function with handler
   `pingone_authorize_interceptor.lambda_handler`.
2. Upload `pingone_authorize_interceptor.py` (e.g. paste in the console, or
   `zip function.zip pingone_authorize_interceptor.py` and upload).
3. Set the environment variables from the table above (at minimum
   `PINGONE_DECISION_ENDPOINT_URL`).
4. Register the Lambda as the **REQUEST interceptor** on your AgentCore Gateway.
   To let policies use token claims, enable `passRequestHeaders` on the
   interceptor configuration.
5. Grant your gateway execution role permission to invoke this specific Lambda.

See the AWS docs for
[configuring interceptors](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-interceptors-configuration.html).

## Local testing

The handler is a plain function you can exercise without AWS:

```python
import json, pingone_authorize_interceptor as interceptor

event = {"mcp": {"gatewayRequest": {
    "path": "/mcp", "httpMethod": "POST",
    "headers": {"Authorization": "Bearer <jwt>"},
    "body": {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
             "params": {"name": "transfer_funds", "arguments": {"amount": 100}}}}}}

# Stub the PDP call to test enforcement without a live PingOne tenant:
interceptor.PINGONE_DECISION_ENDPOINT_URL = "https://example.test/decision"
interceptor._query_pingone_decision = lambda req: {"decision": "DENY"}

print(json.dumps(interceptor.lambda_handler(event, None), indent=2))
# -> mcp.transformedGatewayResponse with a JSON-RPC error (blocked)
```

## References

- [Using interceptors with Gateway](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-interceptors.html)
- [Types of interceptors (input/output payloads)](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-interceptors-types.html)
- [PingOne Authorize decision endpoints](https://docs.pingidentity.com/pingone/authorization_using_pingone_authorize/p1az_decision_endpoints.html)
