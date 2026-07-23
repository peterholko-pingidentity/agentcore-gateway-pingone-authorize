import base64
import hashlib
import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


logger = logging.getLogger()
logger.setLevel(logging.INFO)

SENSITIVE_KEY_PARTS = (
    "authorization",
    "cookie",
    "secret",
    "token",
    "password",
    "api-key",
    "apikey",
)

# --- PingOne Authorize configuration (set via Lambda environment variables) ---

# Full runtime URL of the PingOne Authorize decision endpoint. The PingOne
# console shows this URL when you create a decision endpoint, e.g.
# https://auth.pingone.com/<envId>/as/decision/<decisionEndpointId>
PINGONE_DECISION_ENDPOINT_URL = os.environ.get("PINGONE_DECISION_ENDPOINT_URL", "")

# Optional static bearer token for the decision endpoint (handy for testing).
PINGONE_ACCESS_TOKEN = os.environ.get("PINGONE_ACCESS_TOKEN", "")

# Optional client-credentials grant used to mint a worker-app access token when
# the decision endpoint is protected. All three must be set to be used.
PINGONE_TOKEN_ENDPOINT = os.environ.get("PINGONE_TOKEN_ENDPOINT", "")
PINGONE_CLIENT_ID = os.environ.get("PINGONE_CLIENT_ID", "")
PINGONE_CLIENT_SECRET = os.environ.get("PINGONE_CLIENT_SECRET", "")
PINGONE_TOKEN_SCOPE = os.environ.get("PINGONE_TOKEN_SCOPE", "")

# Top-level key that wraps the request context in the decision request body.
# PingOne decision endpoints commonly expect the request attributes under an
# "attributes" object; set this to your decision endpoint's expected key, or to
# an empty string to send the context as the top-level object.
PINGONE_ATTRIBUTES_KEY = os.environ.get("PINGONE_ATTRIBUTES_KEY", "attributes")

# Network timeout (seconds) for calls to PingOne.
PINGONE_HTTP_TIMEOUT = float(os.environ.get("PINGONE_HTTP_TIMEOUT", "5"))

# Only a PERMIT decision is allowed through. If PingOne is unreachable or returns
# an unexpected response, fail closed (deny) by default. Set to "true" to allow
# the request through when the PDP cannot be consulted.
PINGONE_FAIL_OPEN = os.environ.get("PINGONE_FAIL_OPEN", "false").lower() == "true"

# HTTP status code the gateway returns to the caller for a blocked request.
PINGONE_DENY_STATUS_CODE = int(os.environ.get("PINGONE_DENY_STATUS_CODE", "403"))

# Cached worker-app token: (access_token, expires_at_epoch_seconds).
_cached_token: tuple[str, float] | None = None


def _is_sensitive_key(key: str) -> bool:
    normalized = key.lower()
    return any(part in normalized for part in SENSITIVE_KEY_PARTS)


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "***REDACTED***" if _is_sensitive_key(str(key)) else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _case_insensitive_get(mapping: dict[str, Any], name: str) -> Any:
    for key, value in mapping.items():
        if key.lower() == name.lower():
            return value
    return None


def _decode_jwt_metadata(authorization: str | None) -> dict[str, Any] | None:
    if not authorization:
        return None

    token = authorization.removeprefix("Bearer ").strip()
    parts = token.split(".")
    if len(parts) < 2:
        return {"sha256": hashlib.sha256(token.encode()).hexdigest()}

    try:
        payload_segment = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_segment))
    except Exception as exc:
        return {
            "sha256": hashlib.sha256(token.encode()).hexdigest(),
            "decode_error": str(exc),
        }

    return {
        "sha256": hashlib.sha256(token.encode()).hexdigest(),
        "issuer": payload.get("iss"),
        "subject": payload.get("sub"),
        "audience": payload.get("aud"),
        "client_id": payload.get("client_id") or payload.get("clientId"),
        "scope": payload.get("scope"),
        "expires_at": payload.get("exp"),
    }


def _get_worker_token() -> str | None:
    """Return a bearer token for the decision endpoint, if one is configured.

    Prefers a client-credentials grant (with a small in-memory cache) and falls
    back to a static token. Returns None when the decision endpoint requires no
    auth.
    """
    global _cached_token

    if PINGONE_TOKEN_ENDPOINT and PINGONE_CLIENT_ID and PINGONE_CLIENT_SECRET:
        now = time.time()
        if _cached_token and _cached_token[1] > now + 30:
            return _cached_token[0]

        form: dict[str, str] = {"grant_type": "client_credentials"}
        if PINGONE_TOKEN_SCOPE:
            form["scope"] = PINGONE_TOKEN_SCOPE
        data = urllib.parse.urlencode(form).encode()

        basic = base64.b64encode(
            f"{PINGONE_CLIENT_ID}:{PINGONE_CLIENT_SECRET}".encode()
        ).decode()
        request = urllib.request.Request(
            PINGONE_TOKEN_ENDPOINT,
            data=data,
            method="POST",
            headers={
                "Authorization": f"Basic {basic}",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
        )
        with urllib.request.urlopen(request, timeout=PINGONE_HTTP_TIMEOUT) as resp:
            token_body = json.loads(resp.read().decode())

        access_token = token_body.get("access_token")
        if not access_token:
            raise RuntimeError("token endpoint response missing access_token")
        expires_in = float(token_body.get("expires_in", 300))
        _cached_token = (access_token, now + expires_in)
        return access_token

    return PINGONE_ACCESS_TOKEN or None


def _build_decision_request(
    gateway_request: dict[str, Any],
    body: dict[str, Any],
    jwt_metadata: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build a generic decision request body from the inbound gateway request.

    This makes no assumption about the PingOne Authorize policy or Trust
    Framework: it forwards the full request context so any policy can reference
    whatever attributes it needs (via the attribute-provider mappings you define
    in PingOne). The context includes the complete MCP/JSON-RPC body, the request
    path and HTTP method, and — when a bearer token is present — its decoded
    claims.

    The whole context is placed under a single top-level key (default
    ``"attributes"``, overridable with PINGONE_ATTRIBUTES_KEY). If that key is
    set to an empty string, the context is sent as the top-level object instead,
    covering decision endpoints that expect a flat attribute map.
    """
    context: dict[str, Any] = {
        "path": gateway_request.get("path"),
        "httpMethod": gateway_request.get("httpMethod"),
        "body": body,
    }
    if jwt_metadata:
        # Expose the token claims without the raw token or its hash.
        claims = {
            key: value
            for key, value in jwt_metadata.items()
            if key not in ("sha256", "decode_error") and value is not None
        }
        if claims:
            context["token"] = claims

    if PINGONE_ATTRIBUTES_KEY == "":
        return context
    return {PINGONE_ATTRIBUTES_KEY: context}


def _query_pingone_decision(decision_request: dict[str, Any]) -> dict[str, Any]:
    """POST the decision request to PingOne Authorize and return the parsed body."""
    token = _get_worker_token()
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(
        PINGONE_DECISION_ENDPOINT_URL,
        data=json.dumps(decision_request).encode(),
        method="POST",
        headers=headers,
    )
    with urllib.request.urlopen(request, timeout=PINGONE_HTTP_TIMEOUT) as resp:
        return json.loads(resp.read().decode())


def _passthrough_response(body: dict[str, Any]) -> dict[str, Any]:
    """Allow the request: gateway forwards it to the target unchanged."""
    return {
        "interceptorOutputVersion": "1.0",
        "mcp": {
            "transformedGatewayRequest": {
                "body": body,
            }
        },
    }


def _block_response(
    body: dict[str, Any],
    reason: str,
    decision: str | None = None,
) -> dict[str, Any]:
    """Block the request by short-circuiting with a JSON-RPC error response.

    Returning a ``transformedGatewayResponse`` from a REQUEST interceptor causes
    the gateway to respond immediately without ever calling the target.
    """
    request_id = body.get("id") if isinstance(body, dict) else None

    error_data: dict[str, Any] = {"reason": reason}
    if decision is not None:
        error_data["decision"] = decision

    return {
        "interceptorOutputVersion": "1.0",
        "mcp": {
            "transformedGatewayResponse": {
                "statusCode": PINGONE_DENY_STATUS_CODE,
                "body": {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {
                        # -32001 is a server-defined error in the JSON-RPC
                        # implementation-defined range.
                        "code": -32001,
                        "message": "Request denied by PingOne Authorize",
                        "data": error_data,
                    },
                },
            }
        },
    }


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    mcp = event.get("mcp") or {}
    gateway_request = mcp.get("gatewayRequest") or {}
    headers = gateway_request.get("headers") or {}
    body = gateway_request.get("body") or {}
    authorization = _case_insensitive_get(headers, "authorization")
    jwt_metadata = _decode_jwt_metadata(authorization)

    logger.info(
        "AgentCore Gateway request interceptor received event: %s",
        json.dumps(
            {
                "request_id": getattr(context, "aws_request_id", None),
                "top_level_keys": sorted(event.keys()),
                "mcp_keys": sorted(mcp.keys()),
                "request_path": gateway_request.get("path"),
                "http_method": gateway_request.get("httpMethod"),
                "mcp_method": body.get("method") if isinstance(body, dict) else None,
                "header_names": sorted(headers.keys()),
                "authorization_metadata": jwt_metadata,
                "event": _redact(event),
            },
            default=str,
        ),
    )

    if not PINGONE_DECISION_ENDPOINT_URL:
        logger.error("PINGONE_DECISION_ENDPOINT_URL is not configured")
        if PINGONE_FAIL_OPEN:
            return _passthrough_response(body)
        return _block_response(body, reason="authorization_not_configured")

    decision_request = _build_decision_request(gateway_request, body, jwt_metadata)

    try:
        decision_body = _query_pingone_decision(decision_request)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        logger.error(
            "PingOne Authorize returned HTTP %s: %s", exc.code, detail[:2000]
        )
        if PINGONE_FAIL_OPEN:
            return _passthrough_response(body)
        return _block_response(body, reason="pdp_http_error")
    except Exception as exc:
        logger.error("Failed to reach PingOne Authorize: %s", exc)
        if PINGONE_FAIL_OPEN:
            return _passthrough_response(body)
        return _block_response(body, reason="pdp_unreachable")

    decision = str(decision_body.get("decision", "")).upper()
    logger.info(
        "PingOne Authorize decision: %s",
        json.dumps(
            {
                "decision": decision,
                "statements": decision_body.get("statements"),
                "id": decision_body.get("id"),
            },
            default=str,
        ),
    )

    if decision == "PERMIT":
        return _passthrough_response(body)

    # DENY, NOT_APPLICABLE, INDETERMINATE, or anything unexpected -> block.
    return _block_response(body, reason="policy_decision", decision=decision or "UNKNOWN")
