"""The text/event-stream events the chat app reads (docs/contracts.md, "Agent <-> chat app").

Each function returns one event object; the entrypoint writes it as one `data:` line. Identity events carry
decoded claims only, never a raw token.
"""
import jwt

IDENTITY_CLAIMS = ("sub", "aud", "scope", "act", "p1.permissions", "delete_approval")


def claims(token):
    """Claims of a token that AgentCore or PingOne has already validated (the signature is not re-checked)."""
    return jwt.decode(token, options={"verify_signature": False})


def text(delta):
    return {"type": "text", "delta": delta}


def tool_call(tool, arguments):
    return {"type": "tool_call", "tool": tool, "arguments": arguments}


def tool_result(tool, ok, summary):
    return {"type": "tool_result", "tool": tool, "ok": ok, "summary": summary}


def identity(hop, token_claims):
    """`hop` is user, gateway or server. Only the contract's claims leave the agent."""
    return {"type": "identity", "hop": hop, "claims": {k: token_claims[k] for k in IDENTITY_CLAIMS if k in token_claims}}


def approval_required(code, action, approver, expires_in=None):
    """`expires_in`: seconds until the approval request expires, when the Gateway said (optional in the contract)."""
    event = {"type": "approval_required", "code": code, "action": action, "approver": approver}
    if expires_in is not None:
        event["expiresIn"] = expires_in
    return event


def approval_result(approved):
    return {"type": "approval_result", "approved": approved}


def denied(tool, reason):
    return {"type": "denied", "tool": tool, "reason": reason}


def error(message):
    return {"type": "error", "message": message}


def done():
    return {"type": "done"}
