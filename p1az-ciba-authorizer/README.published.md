# AWS Bedrock Gateway Lambda Authorizer

> **NOTE: This is a prototype, not a production integration kit.**

A AWS Lambda authorizer that integrates [PingOne Authorize](https://www.pingidentity.com/en/platform/capabilities/authorization-management.html) (P1AZ) with [AWS Bedrock AgentCore Gateways](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway.html) to authorize MCP (Model Context Protocol) access and tool calls.

---
# Install and Configure

### A. PingOne Prerequisite

The Lambda Authorizer requires a credential in order to communicate with PingOne. Create the credential using these steps in the PingOne admin console.

1. Go to **Authorization** -> **API Gateways**
2. Copy the **Service URL** at the top of the page and save for later
3. Click the plus **(+)** button to add a new API Gateway configuration
4. Use the name `AWS Bedrock` or similar
5. Click the plus **(+)** button to add a credential
6. Copy the generated credential and save for later

### B. Lambda Install

Upload and install the Lambda Authorizer following these steps in the AWS admin console.

1. Go to **Lambda** and click **Create Function**.
2. Use these settings:
   a. Author from scratch
   b. Function name `p1az-bedrock-authorizer` or similar
   c. Runtime **Amazon Linux 2023**
   d. ARM64 architecture
3. Upload the zip:
   a. In the **Update** actions menu, select **Update from a .zip file**
   b. Upload **bootstrap.zip**
4. Change the handler:
   a. In **Runtime settings**, click **Edit**
   b. For **Handler** replace with `bootstrap`

### C. Lambda Configuration

In the AWS admin console:

1. Go to the Lambda function you created earlier
2. In the **Environment Variables** section near the bottom of the **Code** panel, click **Add environment variables**
3. Add an environment variable for each of the rows in the table below
   a. Click **Add environment variable**
   b. For **Key**, enter the variable name from the table below
   c. For **Value**, paste the value that you copied from the PingOne admin console

The Lambda is configured via environment variables:

| Variable | Required | Default | Description |
|---|---|---|---|
| `SERVICE_URL` | Yes | -- | PingOne API Access Management service URL (e.g., `https://http-access-api.pingone.com/v1/environments/<env-id>`) |
| `SECRET_HEADER_VALUE` | Yes | -- | API Gateway credential for PingOne authentication |
| `AUTH_ERROR_MODE` | How auth challenges are returned to clients -- see [Auth error modes](#auth-error-modes). Any other value than the supported modes aborts at startup. |
| `RUST_LOG` | No | `info` | Logging level. Use `aws_bedrock_lambda_authorizer=trace` for full request/response dumps. |

### D. Bedrock Gateway Configuration

Configure the Bedrock Gateway to use the Lambda Authorizer following these steps in the AWS admin console.

1. Go to **Bedrock AgentCore** -> **Gateways** and click your gateway
2. Click **Edit**
3. Under **Gateway details** expand the section **Additional configurations**
4. Ensure the **Enable response streaming** is NOT CHECKED
5. For **Request Interceptor Lambda ARN**, select the name of the Lambda function you created earlier
6. For **Pass request header** select **True**
7. For **Response Interceptor Lambda ARN**, select the name of the Lambda function you created earlier
8. For **Pass request header** select **True**

---
# Developer Integration Notes

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
them into an **in-band** challenge instead.

Developers should handle JSON-RPC errors with code `-32081`, confirm they are
Ping-supplied authorization challenges by looking at `error.data.com.pingidentity/auth-challenge`,
and then extract the embedded `www-authenticate` header (or its parts, if necessary.)

Response details:

- **HTTP 200** with a JSON-RPC error body of code `-32081`, whose `error.data` nests
  every detail under the reverse-DNS key `com.pingidentity/auth-challenge` (MCP
  `_meta`-style namespacing), so a client can tell this gateway's `-32081` from any other
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

- `error.message` is the human description of the auth challenge
  (copied from `error_description` parameter, if present).
- Inside the `com.pingidentity/auth-challenge` object: `www_authenticate` is the
  verbatim header value, `status` is the original HTTP status, `scheme` is the auth
  scheme token, and each attribute pair of the challenge is broken out as its own
  field (lowercased keys, quotes/escapes resolved) — so a client can recompose a
  different `www-authenticate` header without parsing the verbatim string.

---
# Troubleshooting

Inspect AWS CloudWatch logs to troubleshoot the Lambda integration with PingOne.

1. Navigate to **CloudWatch** -> **Log management** and find the log group for the Lambda function you created
2. Inspect the log stream for one of the error messages below

* `WARN P1AZ returned non-200 status status=401`

When PingOne returns an HTTP 401 to the Lambda, this is most likely a mismatch of the service URL and gateway credential.
Go to the PingOne admin console to create a new API Gateway credential and copy it to the environment variables in the Lambda configuration.

* `INFO Authorization decision: DENY response_code=404 response_status=Not Found`

The MCP client's request is being denied because the Bedrock Gateway URL is not known to PingOne.

1. In the AWS admin console go to **Bedrock AgentCore** -> **Gateways** and click your gateway
2. Copy the **Gateway resource URL**
3. In the PingOne admin console, go to **Authorization** -> **API Services** and click the API Service that represents your Bedrock Gateway
4. In the 3-dot menu, click **Edit**
5. Paste the URL from step 2 into the list of **Base URLs**
6. Click **Save**
7. Click **Deploy**

* `INFO Authorization decision: DENY response_code=401 response_status=Unauthorized`

The MCP client's request is being denied for another reason. Use the PingOne audit history to troubleshoot.

1. In the PingOne admin console, go to **Monitoring** -> **Audit**
2. In the **Filter Type** drop down menu select **Event Type**
3. In the **Filter** drop down menu select **HTTP Request Policy Evaluated**
4. Click **Run**
5. Inspect the **HTTP Request Policy Evaluated** events by clicking **View** in the **Details** column
6. Look for `evaluationResult` for clues