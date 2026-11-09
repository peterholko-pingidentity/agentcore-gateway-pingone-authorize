"""One invocation: the user's token -> Gateway token -> Gateway tools -> Strands agent, streamed as contract events."""
import json
import logging
import os
from collections import OrderedDict
from dataclasses import dataclass, field
from functools import cached_property

import boto3
from strands import Agent
from strands.models import BedrockModel
from strands.tools.executors import SequentialToolExecutor

from . import events
from .gateway import list_tools, open_session
from .identity import TokenExchanger
from .tools import EVENT_KEY, GatewayTool, Turn

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are the identity help-desk agent in a Ping Identity + AWS demo. You look up, create, \
change and remove user accounts in Slack and Snowflake using your tools. Every tool call runs as the signed-in \
user, with their PingOne permissions.

- Use the tools; never claim something changed unless a tool result says so.
- Tools that act on one user take `user_name`, that system's username: pass it directly, never an internal ID. \
Use find_users only when you need to search (for example by email).
- Deleting or deactivating an account needs a one-time approval: just call the tool. The system emails the \
user an approval request with a code, waits for it, and retries; you never need to ask for the approval yourself.
- If a tool result says the user isn't permitted, or that a policy denied the action, explain why in one or \
two plain sentences and don't retry.
- Tool names look like <system>___<action>; refer to systems by their plain names (Slack, Snowflake). \
"whoami" is a diagnostic system that echoes the identity it received.
- Be brief: this is a chat window."""


@dataclass
class Config:
    gateway_url: str
    issuer: str  # PingOne issuer, https://auth.pingone.<tld>/<env>/as
    provider: str = "acgw-spike-agent-obo"
    workload_name: str = "acgw-agent"
    model_id: str = "us.anthropic.claude-sonnet-5-5"
    region: str = "us-east-2"
    login_hints: dict = field(default_factory=dict)

    @classmethod
    def from_env(cls):
        e = os.environ
        return cls(
            gateway_url=e["GATEWAY_URL"],
            issuer=e["PINGONE_ISSUER"],
            provider=e.get("AGENT_OBO_PROVIDER", cls.provider),
            workload_name=e.get("WORKLOAD_NAME", cls.workload_name),
            model_id=e.get("MODEL_ID", cls.model_id),
            region=e.get("AWS_REGION") or e.get("AWS_DEFAULT_REGION") or cls.region,
            login_hints=json.loads(e.get("LOGIN_HINTS") or "{}"),
        )


class Services:
    """AWS clients and the model, created once per process."""

    def __init__(self, config):
        self.config = config
        self.session = boto3.Session(region_name=config.region)

    @cached_property
    def exchanger(self):
        client = self.session.client("bedrock-agentcore")
        return TokenExchanger(client, self.config.provider, self.config.workload_name)

    @cached_property
    def model(self):
        return BedrockModel(model_id=self.config.model_id, boto_session=self.session)


# Conversation history per (runtime session, user): Runtime keeps one microVM per session, so memory suffices.
_HISTORY = OrderedDict()
_MAX_SESSIONS = 200


async def handle(payload, authorization, workload_token, session_id, services):
    """Async generator of contract events for one invocation; always ends with `done`.

    `authorization` is the inbound `Authorization` header (the user's PingOne token, already validated by
    Runtime's JWT authorizer). `workload_token` is Runtime's WorkloadAccessToken header, None when run locally.
    """
    try:
        async for event in _turn(payload, authorization, workload_token, session_id, services):
            yield event
    except Exception as e:  # noqa: BLE001 - every failure reaches the chat as an error event
        logger.exception("invocation failed")
        yield events.error(f"{type(e).__name__}: {e}")
    yield events.done()


async def _turn(payload, authorization, workload_token, session_id, services):
    prompt = (payload or {}).get("prompt")
    if not prompt:
        yield events.error('The request needs a "prompt".')
        return
    if not authorization or not authorization.lower().startswith("bearer "):
        yield events.error("No user token: call the agent with the user's PingOne token as a Bearer token.")
        return
    user_token = authorization.split(" ", 1)[1].strip()
    user_claims = events.claims(user_token)
    yield events.identity("user", user_claims)

    # Exchange 1. On Runtime the WorkloadAccessToken header is already bound to the user's token; locally the
    # agent asks AgentCore Identity for one.
    exchanger = services.exchanger
    workload_token = workload_token or await exchanger.workload_token_for(user_token)
    gateway_token = await exchanger.gateway_token(workload_token)
    yield events.identity("gateway", events.claims(gateway_token))

    config = services.config
    async with open_session(config.gateway_url, gateway_token) as session:  # one MCP session per invocation
        turn = Turn(user_claims=user_claims, session=session, login_hints=config.login_hints)
        tools = [GatewayTool(turn, spec) for spec in await list_tools(session)]
        key = (session_id or "", user_claims.get("sub"))
        agent = Agent(
            model=services.model,
            tools=tools,
            system_prompt=SYSTEM_PROMPT,
            messages=list(_HISTORY.get(key, [])),
            callback_handler=None,
            tool_executor=SequentialToolExecutor(),  # one tool_call ... tool_result at a time in the chat
        )
        async for event in agent.stream_async(prompt):
            if isinstance(event.get("data"), str):
                yield events.text(event["data"])
            elif "tool_stream_event" in event:
                data = event["tool_stream_event"].get("data")
                if isinstance(data, dict) and EVENT_KEY in data:
                    yield data[EVENT_KEY]
        _remember(key, agent.messages)


def _remember(key, messages):
    _HISTORY[key] = list(messages)
    _HISTORY.move_to_end(key)
    while len(_HISTORY) > _MAX_SESSIONS:
        _HISTORY.popitem(last=False)
