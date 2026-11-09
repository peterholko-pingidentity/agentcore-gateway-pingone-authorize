"""Exchange 1: the user's PingOne token -> a Gateway token, through AgentCore Identity's on-behalf-of exchange.

docs/contracts.md: provider acgw-spike-agent-obo, ON_BEHALF_OF_TOKEN_EXCHANGE, and always the subject_token_type
override (AgentCore's default `jwt` type is rejected by PingOne). The result has aud = Gateway URL and
act = {sub: <agent app>}.
"""
import asyncio

ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
BASELINE_SCOPES = ("mcp:tools", "users:read", "users:write")


class TokenExchanger:
    def __init__(self, client, provider, workload_name):
        """`client` is a boto3 bedrock-agentcore (data plane) client."""
        self._client, self.provider, self.workload_name = client, provider, workload_name

    async def workload_token_for(self, user_jwt):
        """A workload access token bound to `user_jwt` (Runtime does this itself for the inbound token)."""
        response = await asyncio.to_thread(
            self._client.get_workload_access_token_for_jwt, workloadName=self.workload_name, userToken=user_jwt)
        return response["workloadAccessToken"]

    async def gateway_token(self, workload_token, scopes=BASELINE_SCOPES):
        """Exchange the user token bound to `workload_token` for a Gateway token with `scopes`."""
        response = await asyncio.to_thread(
            self._client.get_resource_oauth2_token,
            workloadIdentityToken=workload_token,
            resourceCredentialProviderName=self.provider,
            scopes=list(scopes),
            oauth2Flow="ON_BEHALF_OF_TOKEN_EXCHANGE",
            customParameters={"subject_token_type": ACCESS_TOKEN_TYPE},
        )
        return response["accessToken"]
