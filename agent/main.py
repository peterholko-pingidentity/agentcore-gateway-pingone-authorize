"""AgentCore Runtime entry point (HTTP protocol: POST /invocations, GET /ping on port 8080).

Request: {"prompt": "..."} with the user's PingOne token as `Authorization: Bearer` (allowlisted header).
Response: text/event-stream of the events in docs/contracts.md, ending with {"type": "done"}.
"""
import logging
import os

from bedrock_agentcore.runtime import BedrockAgentCoreApp
from bedrock_agentcore.runtime.context import BedrockAgentCoreContext

from acgw.app import Config, Services, handle

logging.basicConfig(level=logging.INFO)
app = BedrockAgentCoreApp()
services = Services(Config.from_env())


@app.entrypoint
async def invoke(payload, context):
    headers = context.request_headers or {}
    async for event in handle(payload, headers.get("Authorization"), BedrockAgentCoreContext.get_workload_access_token(),
                              context.session_id, services):
        yield event


if __name__ == "__main__":
    app.run(host=os.environ.get("AGENT_HOST", "0.0.0.0"), port=int(os.environ.get("AGENT_PORT", "8080")))
