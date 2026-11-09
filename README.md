# Authorizing AgentCore Gateway tool calls with PingOne Authorize and CIBA approvals

This repo holds the code for a demo you can set up in your own PingOne environment and AWS account, in front of your
own MCP servers. An AI agent on Amazon Bedrock AgentCore Runtime calls MCP tools through AgentCore Gateway. A Lambda
interceptor sends every tool call to PingOne Authorize, and a call that needs the user's approval waits for a CIBA
approval on the user's other device.

The steps below are the same as the [setup guide](https://aws-agentcore-ping.pingtapdemos.com/) on the web. They follow
the demo's own configuration. Names such as `agent-obo` and `users:delete` are
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
  first: some older servers refuse what the Gateway passes on (see the [known issue](#known-issue) in step 6).
- The authorizer Lambda package `bootstrap.zip`, built from the [`p1az-ciba-authorizer`](p1az-ciba-authorizer/)
  source for arm64 with `make docker-package` or `cargo lambda build --release --arm64 --bin bedrock`.
- An agent whose MCP client supports protocol version `2026-07-28`: MCP Python SDK 2.0 or later, or Strands Agents
  1.64 or later with its `MCPClient`. These clients complete approvals on their own
  ([step 11](#11-update-the-agent)). The agent also calls AgentCore
  Identity for its Gateway token. The demo's Strands agent, in [`agent/`](agent/), is the reference.

### Values used below

| Placeholder | What it is |
| --- | --- |
| `<ENV_ID>` | Your PingOne environment ID. Examples use `auth.pingone.com`; use your Region's domain (`.eu`, `.ca`, `.asia`) if it differs. |
| `<ISSUER>` | `https://auth.pingone.com/<ENV_ID>/as` |
| `<DISCOVERY_URL>` | `<ISSUER>/.well-known/openid-configuration` |
| `<AGENT_AUD>`, `<GATEWAY_AUD>` | Audiences you choose for the agent runtime and the Gateway, for example `https://agent.example.com` and `https://mcp-gateway.example.com`. The demo uses the runtime's and Gateway's own URLs. Any https URI works if PingOne and AWS use the same value. |
| `<MCP_URL>` | Each MCP server's URL, which is also its audience |
| `<REGION>`, `<ACCOUNT_ID>` | Your AWS Region and account |

## 1. Create the resources and claim mappings

Each token in the chain is minted for one resource. The claim mappings carry the user's identity from token to token and record who is acting.

1. Sign on to the PingOne admin console and go to **Applications > Resources**.
2. Create these custom resources. For each one, enter the audience, add the scopes, and on the agent runtime and Gateway resources turn on the application permissions claim so tokens carry `p1.permissions`.

   | Resource | Audience | Scopes | Permissions claim |
   | --- | --- | --- | --- |
   | agent-runtime | `<AGENT_AUD>` | `agent:invoke` | On |
   | gateway | `<GATEWAY_AUD>` | `mcp:tools` | On |
   | actor | an https URI of your choice, for example `https://actor.example.com` | `actor` | Off |
   | one per MCP server | `<MCP_URL>` | the scopes that server checks, for example `crm:users.read`, `crm:users.write`, `crm:users.delete` | Off |
3. Add the attribute mappings below on each resource's **Attributes** tab. Replace the client IDs once you have created the applications in step 2.

   | Resource | Attribute | Value |
   | --- | --- | --- |
   | agent-runtime | `may_act` | `${{'sub': '<AGENT_APP_ID>'}}` |
   | gateway | `sub` | `${#root.context.requestData.subjectToken.sub}` |
   | gateway | `act` (required) | First-hop expression below |
   | gateway | `may_act` | `${{'sub': '<GATEWAY_APP_ID>'}}` |
   | gateway | `username` | `${user.username}`, used as the CIBA `login_hint` |
   | each MCP server | `sub` | `${#root.context.requestData.subjectToken.sub}` |
   | each MCP server | `act` (required) | Second-hop expression below |

   **gateway: `act` (first hop)**

   ```
   ${(#root.context.requestData.grantType == 'client_credentials') ? 'noActor' : ((#root.context.requestData.subjectToken.may_act.sub == #root.context.requestData.actorToken.client_id) ? #root.context.requestData.subjectToken.may_act : null)}
   ```

   **each MCP server: `act` (second hop)**

   ```
   ${(#root.context.requestData.grantType == 'client_credentials') ? 'noActor' : ((#root.context.requestData.subjectToken.may_act.sub == #root.context.requestData.actorToken.client_id) ? {'sub': #root.context.requestData.actorToken.client_id, 'act': #root.context.requestData.subjectToken.act} : null)}
   ```
4. Mark both `act` mappings as required (`"required": true` on the resource attribute). A required claim whose expression returns `null` makes PingOne refuse the token, so an exchange by an actor the subject token didn't name in `may_act` fails instead of producing a token without `act`.

## 2. Create the applications

1. Go to **Applications > Applications** and create the four applications below. Use **Client Secret Basic** as the token endpoint authentication method on all of them except the chat app, which can use whatever your frontend needs.

   | Application | Type and grants | Resource access |
   | --- | --- | --- |
   | Chat app | OIDC Web App: Authorization Code, PKCE required (S256), your redirect URI | agent-runtime: `agent:invoke`, plus `openid` |
   | Agent | AI Agent (or a machine-to-machine service app): Client Credentials and Token Exchange | gateway: `mcp:tools`; actor: `actor` |
   | Gateway exchange | Machine-to-machine service app: Client Credentials and Token Exchange | each MCP server: all its scopes; actor: `actor` |
   | Approvals | OIDC Web App with the CIBA grant | `openid` |
2. Copy each application's client ID into the `may_act` mappings from step 1: the agent's ID on agent-runtime, the Gateway exchange app's ID on gateway.
3. Keep the client secrets of the agent, Gateway exchange and approvals apps. AWS needs them in steps 5 and 10.

## 3. Define the permissions and roles

The policy decides with the user's application permissions, which reach the Gateway token as `p1.permissions`.

1. On the agent-runtime and gateway resources, add an application resource named `users` with the permissions `read`, `write` and `delete`. Tokens list them as `users:read`, `users:write` and `users:delete`.
2. Create application roles and give each the permissions it allows. The demo uses:

   - **help-desk**: `read`, `write`
   - **iam-admin**: `read`, `write`, `delete`
3. Assign the roles to your users. Each user who can approve needs a username (sent as the CIBA `login_hint`) and an email address or device that receives the approval.

## 4. Set up CIBA approvals

1. In DaVinci, create a flow that a CIBA request triggers and that lets the user approve or decline. The demo's flow looks the user up by username and emails an approve and decline link that shows the binding message.
2. Assign the flow to the approvals app with a DaVinci flow policy.
3. Check the CIBA limits you'll configure in step 10: PingOne accepts a binding message of up to 8 characters (the authorizer sends `APR-` and four digits) and a requested expiry of up to 300 seconds.

> [!NOTE]
> The authorizer also supports PingFederate as the CIBA provider. PingFederate 11.2 or later binds the approval to the request with `authorization_details` instead of the DynamoDB record.

## 5. Create the AgentCore Identity credential providers

Two OAuth credential providers do the two token exchanges. Both use PingOne's discovery document and get an actor token with client credentials for the `actor` scope.

1. Create `agent-obo` with the agent app's credentials:

   **agent-obo.json**

   ```json
   {
     "name": "agent-obo",
     "credentialProviderVendor": "CustomOauth2",
     "oauth2ProviderConfigInput": {
       "customOauth2ProviderConfig": {
         "oauthDiscovery": { "discoveryUrl": "<DISCOVERY_URL>" },
         "clientId": "<AGENT_APP_ID>",
         "clientSecret": "<AGENT_APP_SECRET>",
         "clientAuthenticationMethod": "CLIENT_SECRET_BASIC",
         "onBehalfOfTokenExchangeConfig": {
           "grantType": "TOKEN_EXCHANGE",
           "tokenExchangeGrantTypeConfig": {
             "actorTokenContent": "M2M",
             "actorTokenScopes": ["actor"]
           }
         }
       }
     }
   }
   ```

   **Create it**

   ```bash
   aws bedrock-agentcore-control create-oauth2-credential-provider --cli-input-json file://agent-obo.json
   ```
2. Create `gateway-obo` the same way with the Gateway exchange app's client ID and secret.

## 6. Create the Gateway and its targets

1. Create the Gateway's IAM role, trusted by `bedrock-agentcore.amazonaws.com`. It needs `bedrock-agentcore:*` for the credential providers, `secretsmanager:GetSecretValue` on `arn:aws:secretsmanager:<REGION>:<ACCOUNT_ID>:secret:bedrock-agentcore-identity!*`, and later `lambda:InvokeFunction` on the authorizer (step 10).
2. Create the Gateway with a PingOne JWT authorizer and MCP protocol version `2026-07-28` only. It accepts any token whose scopes include `mcp:tools`. Approvals rely on that version's multi round-trip requests, so older clients can't connect. Your MCP servers can stay on older versions: the Gateway negotiates with each one separately. A server that checks the newer request fields can still fail, though (see the [known issue](#known-issue) below).

   **gateway.json**

   ```json
   {
     "name": "mcp-gateway",
     "roleArn": "arn:aws:iam::<ACCOUNT_ID>:role/mcp-gateway",
     "protocolType": "MCP",
     "protocolConfiguration": {
       "mcp": { "supportedVersions": ["2026-07-28"] }
     },
     "authorizerType": "CUSTOM_JWT",
     "authorizerConfiguration": {
       "customJWTAuthorizer": {
         "discoveryUrl": "<DISCOVERY_URL>",
         "allowedAudience": ["<GATEWAY_AUD>"],
         "allowedScopes": ["mcp:tools"]
       }
     }
   }
   ```

   **Create it**

   ```bash
   aws bedrock-agentcore-control create-gateway --cli-input-json file://gateway.json
   ```

   Note the `gatewayUrl` in the response (`https://<GATEWAY_ID>.gateway.bedrock-agentcore.<REGION>.amazonaws.com/mcp`). You need it in step 8.
3. Add one target per MCP server. The target exchanges the Gateway token through `gateway-obo` for the server's own token. Allow the `x-paz-response-headers` header, which carries a policy denial's reason from the request phase to the response phase.

   **target-crm.json**

   ```json
   {
     "gatewayIdentifier": "<GATEWAY_ID>",
     "name": "crm",
     "targetConfiguration": {
       "mcp": { "mcpServer": { "endpoint": "<MCP_URL>", "listingMode": "DYNAMIC" } }
     },
     "credentialProviderConfigurations": [{
       "credentialProviderType": "OAUTH",
       "credentialProvider": {
         "oauthCredentialProvider": {
           "providerArn": "<GATEWAY_OBO_ARN>",
           "scopes": ["crm:users.read", "crm:users.write", "crm:users.delete"],
           "grantType": "TOKEN_EXCHANGE",
           "customParameters": {
             "subject_token_type": "urn:ietf:params:oauth:token-type:access_token"
           }
         }
       }
     }],
     "metadataConfiguration": { "allowedRequestHeaders": ["x-paz-response-headers"] }
   }
   ```

   **Create it**

   ```bash
   aws bedrock-agentcore-control create-gateway-target --cli-input-json file://target-crm.json
   ```

> [!IMPORTANT]
> Always send the `subject_token_type` override. AgentCore's default token type is the generic JWT type, which PingOne rejects.

<a id="known-issue"></a>

> [!IMPORTANT]
> **Known issue: some older MCP servers refuse every request**
>
> AgentCore Gateway currently passes the client's `2026-07-28` fields in `params._meta` (`io.modelcontextprotocol/protocolVersion`, `clientInfo` and `clientCapabilities`) on to MCP servers it talks to at an older version. A server that ignores those fields works, like the demo's Slack server. A server that checks them against the request's headers refuses the request, with errors such as "Header MCP-Protocol-Version does not match the request body" or "Missing required header Mcp-Method". With `listingMode` `DYNAMIC`, the agent's whole tool list then fails.
>
> Snowflake's managed MCP server, which supports protocol version 2025-11-25, is one of these, so the demo leaves it off the Gateway for now. The authorizer can't remove the fields, because the Gateway requires them in the interceptor's output. We've reported the issue to AWS. Until it's fixed, try each MCP server through the Gateway before you rely on it.

## 7. Deploy the agent on AgentCore Runtime

1. Create a workload identity for the agent:

   **Create it**

   ```bash
   aws bedrock-agentcore-control create-workload-identity --name user-admin-agent
   ```
2. Give the runtime's execution role these actions in addition to model access and logs:

   - `bedrock-agentcore:GetWorkloadAccessTokenForJWT` on the workload identity directory and its workload identities
   - `bedrock-agentcore:GetResourceOauth2Token` on the token vault, the `agent-obo` provider and the workload identities
   - `secretsmanager:GetSecretValue` on the provider's client secret
3. Create the runtime with a PingOne JWT authorizer for `<AGENT_AUD>`, and allow the `Authorization` header so the agent receives the user's token:

   **Runtime settings (excerpt)**

   ```json
   "authorizerConfiguration": {
     "customJWTAuthorizer": {
       "discoveryUrl": "<DISCOVERY_URL>",
       "allowedAudience": ["<AGENT_AUD>"]
     }
   },
   "requestHeaderConfiguration": { "requestHeaderAllowlist": ["Authorization"] }
   ```
4. Your chat app calls `InvokeAgentRuntime` with `Authorization: Bearer <the user's PingOne token>`.

## 8. Set up PingOne Authorize API Access Management

API Access Management receives each Gateway request from the authorizer Lambda through its sideband API and applies your policy.

1. Add an API gateway of the API gateway integration type, and create a credential for it. The credential is the Lambda's `SECRET_HEADER_VALUE` in step 10.
2. Add an API service:

   1. For the base URL, enter the Gateway URL without `/mcp`: `https://<GATEWAY_ID>.gateway.bedrock-agentcore.<REGION>.amazonaws.com`.
   2. For the authorization server, choose PingOne SSO and the gateway resource from step 1.
   3. Turn on custom access control.
3. Add one operation, **MCP JSON-RPC**: method `POST`, exact path `/mcp`, custom access control. Every MCP request goes there.
4. In the Trust Framework, add the attributes the policy reads. API Access Management provides the body as a string and the headers as `{"name": ["value"]}`.

   | Attribute | Resolves from | JSON path | Type | Default |
   | --- | --- | --- | --- | --- |
   | `mcp-body` | `PingOne.API Access Management.HTTP.Request.Body` |   | JSON |   |
   | `mcp-method` | `mcp-body` | `$.method` | String | empty |
   | `mcp-tool` | `mcp-body` | `$.params.name` | String | empty |
   | `mcp-target-user` | `mcp-body` | `$.params.arguments.user_name` | String | empty |
   | `mcp-target-email` | `mcp-body` | `$.params.arguments.email` | String | empty |
   | `ciba-approval` | `PingOne.API Access Management.HTTP.Request.Headers` | `$['x-ciba-approval'][0]` | String | `none` |

   The user's permissions come from `PingOne.API Access Management.Identity.Access Token.Permissions`, which API Access Management fills from the validated Gateway token.

## 9. Write the policy

Add one policy to the operation's **Inbound Request** custom policy set, with the **First applicable** combining algorithm. The set combines your policy with the generated "Permit by default" rules using deny-overrides, so only your denials change the outcome. These are the demo's rules. Gateway tool names have the form `<target>___<tool>`, so match them with **ends with**.

| # | When | Effect |
| --- | --- | --- |
| 1 | `mcp-method` isn't `tools/call` (initialize, tools/list) | Permit |
| 2 | A read tool, and permissions lack `users:read` | Deny |
| 3 | A read tool (`___find_users`, `___get_user`) | Permit |
| 4 | A delete tool, and permissions lack `users:delete` | Deny |
| 5 | A write tool, and permissions lack `users:write` | Deny |
| 6 | `___create_user` with an email at your domain | Permit |
| 7 | A write or delete whose `mcp-target-user` isn't one of the managed accounts | Deny |
| 8 | A delete tool, and `ciba-approval` isn't `approved` | Ask for approval |
| 9 | Writes, and approved deletes | Permit |
| 10 | Anything else | Deny |

1. Give every deny rule an `auth-challenge` statement that applies to **Deny**, with the reason in `errorDescription`. The sideband API returns no other statements, so this is how the reason reaches the user.

   **auth-challenge payload for a denial (rule 4)**

   ```json
   {
     "httpStatus": 403,
     "error": "insufficient_scope",
     "errorDescription": "Your PingOne role does not allow you to delete or deactivate users (it lacks users:delete)"
   }
   ```
2. Make rule 8 an unconditional deny whose `auth-challenge` asks for the `ciba-approval` ACR. The authorizer starts a CIBA request instead of passing this challenge on.

   **auth-challenge payload that asks for approval (rule 8)**

   ```json
   {
     "httpStatus": 401,
     "error": "insufficient_user_authentication",
     "acrValues": ["ciba-approval"],
     "errorDescription": "Deleting an account needs your approval on your other device"
   }
   ```
3. Deploy the API service. Deploy again after every policy change.

> [!NOTE]
> Keep every other deny rule ahead of the approval rule, so nobody is asked to approve a call the policy would refuse anyway. If the policy still asks for approval after one was given, the authorizer refuses the call with `approval_not_accepted` instead of asking again.

## 10. Deploy the authorizer Lambda

1. Create the DynamoDB table for approval records and turn on expiry:

   **Create the table**

   ```bash
   aws dynamodb create-table --table-name mcp-ciba \
     --attribute-definitions AttributeName=pk,AttributeType=S \
     --key-schema AttributeName=pk,KeyType=HASH --billing-mode PAY_PER_REQUEST
   ```

   **Turn on expiry**

   ```bash
   aws dynamodb update-time-to-live --table-name mcp-ciba \
     --time-to-live-specification Enabled=true,AttributeName=ttl
   ```
2. Create the Lambda's role, trusted by `lambda.amazonaws.com`, with CloudWatch Logs and `dynamodb:GetItem` and `dynamodb:PutItem` on the table.
3. Create the function from `bootstrap.zip`: runtime `provided.al2023`, architecture `arm64`, handler `bootstrap`, timeout 60 seconds, 256 MB. A call that needs approval is held for up to `CIBA_HOLD_SECONDS` while the Lambda polls PingOne, and an approved call is then checked with the sideband API and recorded in DynamoDB, so keep the timeout well above the hold.

   **Create the function**

   ```bash
   aws lambda create-function --function-name mcp-authorizer \
     --runtime provided.al2023 --architectures arm64 --handler bootstrap \
     --timeout 60 --memory-size 256 \
     --role arn:aws:iam::<ACCOUNT_ID>:role/mcp-authorizer \
     --zip-file fileb://bootstrap.zip --environment file://authorizer-env.json
   ```

   **authorizer-env.json**

   ```json
   {
     "Variables": {
       "SERVICE_URL": "https://http-access-api.pingone.com/v1/environments/<ENV_ID>",
       "SECRET_HEADER_VALUE": "<API gateway credential from step 8>",
       "AUTH_ERROR_MODE": "jsonrpc",
       "RESPONSE_AUTHORIZATION": "off",
       "CIBA_PROVIDER": "pingone",
       "CIBA_AUTHORIZATION_ENDPOINT": "<ISSUER>/cibaAuthorization",
       "CIBA_TOKEN_ENDPOINT": "<ISSUER>/token",
       "CIBA_CLIENT_ID": "<APPROVALS_APP_ID>",
       "CIBA_CLIENT_SECRET": "<APPROVALS_APP_SECRET>",
       "CIBA_TABLE": "mcp-ciba",
       "CIBA_LOGIN_HINT_CLAIM": "username",
       "CIBA_STATE_KEY": "<random secret, 32 bytes or more>",
       "CIBA_HOLD_SECONDS": "20",
       "CIBA_REQUESTED_EXPIRY": "180",
       "RUST_LOG": "info"
     }
   }
   ```

   **Generate a state key**

   ```bash
   openssl rand -hex 32
   ```

   | Variable | Why this value |
   | --- | --- |
   | `AUTH_ERROR_MODE=jsonrpc` | A policy denial reaches the agent as HTTP 200 with JSON-RPC `-32081`, whose message is the rule's reason. |
   | `RESPONSE_AUTHORIZATION=off` | No outbound policy runs. With it on, the authorizer passes state to the response phase in a header of about 6 KB, over AgentCore's 4 KB limit for a forwarded header. |
   | `CIBA_LOGIN_HINT_CLAIM=username` | The DaVinci flow finds the user by username, which the gateway resource's `username` claim provides. |
   | `CIBA_STATE_KEY` | Signs the `requestState` the authorizer hands the client, so a client can't forge or change it. Required with CIBA. Use a random value of 32 bytes or more, keep it secret, and keep it the same across deployments: changing it voids approvals in progress. |
   | `CIBA_HOLD_SECONDS=20` | How long each call waits for the user's answer before returning `input_required`. Stock clients retry at most 10 times, almost at once, so the hold sets how long a client keeps waiting in total. |
   | `CIBA_REQUESTED_EXPIRY=180` | Gives the user three minutes to find the email, and ends the approval before a stock client stops retrying ([step 11](#11-update-the-agent)). PingOne allows up to 300. |
4. Add `lambda:InvokeFunction` on the function to the Gateway's role.
5. Make the function the Gateway's request and response interceptor, with request headers passed in. Add this to the Gateway with `update-gateway`, keeping its other settings:

   **interceptorConfigurations**

   ```json
   "interceptorConfigurations": [{
     "interceptor": { "lambda": { "arn": "arn:aws:lambda:<REGION>:<ACCOUNT_ID>:function:mcp-authorizer" } },
     "interceptionPoints": ["REQUEST", "RESPONSE"],
     "inputConfiguration": { "passRequestHeaders": true }
   }]
   ```

> [!IMPORTANT]
> `update-gateway` replaces the whole configuration, `protocolConfiguration` included. Send the authorizer, role and `protocolConfiguration` from step 6 again with the interceptor. Without `protocolConfiguration`, the Gateway falls back to its older default protocol versions and approvals stop working.

## 11. Update the agent

1. Exchange the user's token for a Gateway token on each invocation:

   **Python (boto3)**

   ```python
   import boto3

   identity = boto3.client("bedrock-agentcore")
   workload = identity.get_workload_access_token_for_jwt(
       workloadName="user-admin-agent", userToken=user_jwt)["workloadAccessToken"]
   gateway_token = identity.get_resource_oauth2_token(
       workloadIdentityToken=workload,
       resourceCredentialProviderName="agent-obo",
       scopes=["mcp:tools"],
       oauth2Flow="ON_BEHALF_OF_TOKEN_EXCHANGE",
       customParameters={"subject_token_type": "urn:ietf:params:oauth:token-type:access_token"},
   )["accessToken"]
   ```
2. Connect to the Gateway with an MCP client that supports protocol version `2026-07-28`. Strands Agents 1.64 or later with its stock `MCPClient`, or the MCP Python SDK 2.0 or later with `mcp.Client`, completes approvals with no extra code. Set a read timeout longer than `CIBA_HOLD_SECONDS`.

   **Python (Strands Agents 1.64, MCP SDK 2.x)**

   ```python
   import httpx2
   from mcp.client.streamable_http import streamable_http_client
   from strands import Agent
   from strands.tools.mcp import MCPClient

   def transport():
       http = httpx2.AsyncClient(
           headers={"Authorization": f"Bearer {gateway_token}"},
           timeout=httpx2.Timeout(30, read=60),
       )
       return streamable_http_client(gateway_url, http_client=http)

   with MCPClient(transport) as gateway:
       agent = Agent(tools=gateway.list_tools_sync())
       agent("Delete Carol Martinez")
   ```

   MCP SDK 2.x uses `httpx2`, which trusts the operating system's certificate store rather than `certifi`. If your runtime image has no CA bundle, pass `verify=ssl.create_default_context(cafile=certifi.where())` to `httpx2.AsyncClient`.
3. Know what happens on the wire. When a call needs approval and the user hasn't answered within `CIBA_HOLD_SECONDS`, the Gateway returns an `input_required` result instead of an error. `requestState` is sealed by the authorizer and opaque to the client. The approval code is in `_meta`.

   **Approval pending (HTTP 200)**

   ```json
   {
     "jsonrpc": "2.0",
     "id": 7,
     "result": {
       "resultType": "input_required",
       "requestState": "<sealed>",
       "_meta": {
         "com.pingidentity/approval": {
           "bindingMessage": "APR-4821",
           "expiresIn": 180
         }
       }
     }
   }
   ```

   The client sends the same call again with a new JSON-RPC `id`, the same arguments, and `requestState` in `params`. The authorizer holds each retry again. It forwards the call once the user approves, returns `input_required` with the same `requestState` while they haven't answered, and refuses the call if they decline or the approval expires.

   **Automatic retry**

   ```json
   {
     "jsonrpc": "2.0",
     "id": 8,
     "method": "tools/call",
     "params": {
       "name": "crm___delete_user",
       "arguments": { "user_name": "carol.martinez" },
       "requestState": "<sealed>"
     }
   }
   ```

   The authorizer accepts a `requestState` only from the same user, for the same tool and arguments, before it expires, and only once.
4. Optionally, show the approval code in your app, so the user can match it to the approval request. Stock retry loops don't expose it. To read it, drive the rounds yourself with the MCP SDK's `session.call_tool(name, arguments, allow_input_required=True)`: on an `InputRequiredResult`, show `bindingMessage` from its `meta`, then call again with `request_state=result.request_state`. The demo agent in [`agent/`](agent/) does this. Your app gets the code when the first hold ends, up to `CIBA_HOLD_SECONDS` after the call, while the email goes out at once. If the user approves within the hold, the call just succeeds, with no code to show.
5. Show refusals in plain words. Both arrive as HTTP 200 JSON-RPC errors:

   - `-32081`: a policy denial. `error.message` is the rule's `errorDescription`.
   - `-32080`: the authorizer refused. `error.data.reason` says why, for example `approval_denied`, `approval_expired`, `approval_already_used` or `approval_mismatch`.

> [!NOTE]
> Stock MCP clients retry an `input_required` call at most 10 times, with almost no pause, so the authorizer's hold sets the pace. With `CIBA_HOLD_SECONDS=20`, the first call and 10 retries wait about 220 seconds in total. A `CIBA_REQUESTED_EXPIRY` of 180 seconds ends the approval first, so a user who never answers gets `approval_expired` instead of the client's generic "too many rounds" error. If you change the hold, keep the expiry well below 11 times the hold.

## Test the setup

Sign in as users with each role and try these prompts. Test with real users: a client credentials token has no user to exchange for, so the targets list no tools.

| User | Prompt | Expected result |
| --- | --- | --- |
| help-desk | "Look up Carol Martinez" | The tool runs. The MCP server receives a token with its own audience and `act` naming the Gateway and the agent. |
| help-desk | "Delete Carol Martinez" | Refused with `-32081` and rule 4's reason. The MCP server is never called. |
| iam-admin | "Delete Carol Martinez" | The user gets an approval request with a code such as `APR-4821`. While they haven't answered, the client receives `input_required` and retries on its own. Once they approve, the delete runs. |
| iam-admin | "Delete Carol Martinez", then decline | Refused with `-32080` and `approval_denied`. The MCP server is never called. |
| iam-admin | Send an approved call's `requestState` again, or change its arguments | Refused with `-32080`. The MCP server is never called. |
| any | Connect with an MCP SDK 1.x client | The client fails to connect with "Unsupported protocol version from the server: 2026-07-28". The Gateway answers its `initialize` with the only version it supports. |

## Troubleshooting

**Users see no tools, and the Gateway logs "Token exchange failed."**

Check the target's `subject_token_type` override, the Gateway exchange app's resource access, and the `may_act` mapping on the gateway resource. An interceptor that returns an `Authorization` header replaces the target's credential provider. The authorizer only returns one when the policy changed it.

**Every reply is an empty `{}`**

The response interceptor returned nothing. AgentCore sends an empty interceptor output to the client as `{}`. Use the authorizer from this repo, which passes unchanged responses through explicitly.

**Calls fail after you turn on response authorization**

The `x-paz-state` header is over AgentCore's 4 KB limit for a forwarded header. Keep `RESPONSE_AUTHORIZATION=off` and leave `x-paz-state` out of `allowedRequestHeaders`.

**The agent can't connect: "Unsupported protocol version from the server: 2026-07-28"**

The client doesn't support `2026-07-28`. Use MCP SDK 2.0 or later (Strands Agents 1.64 or later).

**Listing tools fails, or a target answers "Header MCP-Protocol-Version does not match the request body"**

That MCP server checks the `2026-07-28` fields the Gateway passes on to it. "Missing required header Mcp-Method" from the server has the same cause. See the [known issue](#known-issue) in step 6.

**The client stops with a generic error while the user is still deciding**

The client ran out of retries before the approval expired. Keep `CIBA_HOLD_SECONDS` at 20 and `CIBA_REQUESTED_EXPIRY` at 180, the Lambda timeout at 60 seconds, and the client's read timeout above the hold.

**The approval expires before the user finds it**

Raise `CIBA_HOLD_SECONDS` and `CIBA_REQUESTED_EXPIRY` together, keeping the expiry below the client's total wait ([step 11](#11-update-the-agent)), the hold below the Lambda timeout, and the expiry at or below 300, PingOne's maximum.

**A policy change has no effect**

Deploy the API service again.

**The agent says only "Request denied"**

The deny rule has no `auth-challenge` statement, or `x-paz-response-headers` isn't in the target's `allowedRequestHeaders`.

## Earlier version

This repo used to hold a Python interceptor that called the PingOne Authorize decision endpoint
(`pingone_authorize_interceptor.py`). It's still in the history at commit `14ebe74`.

---

*Based on the demo as deployed on 5 November 2026, with MCP protocol version 2026-07-28: AgentCore Gateway with the Slack MCP target, PingOne Authorize API Access Management, and PingOne CIBA by email. The Snowflake target is off until the known issue in step 6 is fixed.*
