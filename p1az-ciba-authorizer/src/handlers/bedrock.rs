use crate::ciba::{self, Ciba};
use crate::config::AuthErrorMode;
use crate::helpers;
use crate::models::{
    AuthorizerError, InboundRequest, InboundRequestResult, OutboundResponse, OutboundResponseResult,
};
use crate::sideband_client::SidebandClient;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{error, info, trace};

// ---------------------------------------------------------------------------
// Bedrock Event Types (input from Bedrock AgentCore Gateway)
// ---------------------------------------------------------------------------

/// The top-level event received from Bedrock AgentCore Gateway.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BedrockEvent {
    pub interceptor_input_version: String,
    pub mcp: McpInput,
}

/// The MCP section of the Bedrock event.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct McpInput {
    pub gateway_request: Option<GatewayRequest>,
    /// Present only when this Lambda is invoked as a RESPONSE interceptor. Its
    /// presence is the discriminator between the REQUEST and RESPONSE phases.
    pub gateway_response: Option<GatewayResponse>,
    pub raw_gateway_request: Option<RawGatewayRequest>,
}

/// The gateway response passed to a RESPONSE interceptor.
///
/// For streaming responses, only the first event carries `status_code`/`headers`
/// (see `is_streaming_response`); subsequent events carry only `body`. A
/// response is only eligible for authorization when `is_streaming_response` is
/// explicitly `Some(false)` -- see `authorize_response`.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GatewayResponse {
    #[serde(default)]
    pub status_code: Option<u16>,
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
    #[serde(default)]
    pub body: Option<serde_json::Value>,
    #[serde(default)]
    pub is_streaming_response: Option<bool>,
}

/// The parsed gateway request from the Bedrock event.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GatewayRequest {
    pub path: String,
    pub http_method: String,
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
    #[serde(default)]
    pub body: Option<serde_json::Value>,
    #[allow(dead_code)]
    #[serde(default)]
    pub context: Option<serde_json::Value>,
}

/// The raw gateway request containing the original body string.
#[derive(Deserialize, Debug)]
pub struct RawGatewayRequest {
    #[serde(default)]
    pub body: Option<String>,
}

// ---------------------------------------------------------------------------
// Bedrock Response Types (output to Bedrock AgentCore Gateway)
// ---------------------------------------------------------------------------

/// The top-level response returned to Bedrock AgentCore Gateway.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BedrockResponse {
    pub interceptor_output_version: String,
    pub mcp: McpOutput,
}

/// The MCP section of the Bedrock response.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct McpOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transformed_gateway_request: Option<TransformedRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transformed_gateway_response: Option<TransformedResponse>,
}

/// A transformed request to forward to the backend MCP server (PERMIT).
#[derive(Serialize, Debug)]
pub struct TransformedRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
    pub body: serde_json::Value,
}

/// A transformed response to short-circuit back to the client (DENY/ERROR).
///
/// `headers` is only set in the RESPONSE interceptor phase -- Bedrock forbids a
/// REQUEST interceptor's `transformedGatewayResponse` from carrying headers.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TransformedResponse {
    pub status_code: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
    pub body: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Transform Functions
// ---------------------------------------------------------------------------

/// Top-level handler: traces the raw event, deserializes, authorizes, and
/// returns a Bedrock response. All logging lives in the library crate so
/// that `RUST_LOG=aws_bedrock_lambda_authorizer=trace` captures everything.
pub async fn handle_request(
    raw_event: serde_json::Value,
    client: &SidebandClient,
    auth_error_mode: AuthErrorMode,
) -> BedrockResponse {
    handle_request_with_ciba(raw_event, client, auth_error_mode, None).await
}

/// [`handle_request`] with the optional CIBA approval flow (this fork's
/// addition; see [`crate::ciba`]). With `ciba` set to `None` the behavior is
/// exactly upstream's.
///
/// REQUEST phase with CIBA (MCP 2026-07-28 multi round-trip requests):
/// 1. The round-trip fields (`params.requestState`, `params.inputResponses`)
///    are removed from the request, and the trusted approval headers from the
///    client's headers.
/// 2. A retry carrying a `requestState` is checked ([`Ciba::open_state`]) and
///    its approval awaited ([`Ciba::redeem`]); a pending one answers
///    `input_required` again, a refused or invalid one a refusal.
/// 3. Otherwise the request goes to `/sideband/request` as upstream. A DENY
///    whose challenge carries the CIBA marker starts an approval
///    ([`Ciba::start_approval`]) and awaits it the same way instead of reaching
///    the client.
/// 4. An approved request goes to `/sideband/request` again with the trusted
///    approval headers; a PERMIT records the approval as spent and forwards the
///    request without them, and a renewed CIBA challenge is refused with
///    `approval_not_accepted`.
pub async fn handle_request_with_ciba(
    raw_event: serde_json::Value,
    client: &SidebandClient,
    auth_error_mode: AuthErrorMode,
    ciba: Option<&Ciba>,
) -> BedrockResponse {
    info!("Handler invoked");
    trace!(event = %raw_event, "Bedrock event received");

    // Deserialize into our typed event
    let bedrock_event: BedrockEvent = match serde_json::from_value(raw_event) {
        Ok(e) => e,
        Err(e) => {
            error!(error = %e, "Failed to deserialize Bedrock event");
            return build_error_response(
                serde_json::Value::Null,
                502,
                &format!("Failed to deserialize Bedrock event: {e}"),
            );
        }
    };

    // RESPONSE interceptor phase: `gatewayResponse` is present.
    if bedrock_event.mcp.gateway_response.is_some() {
        return handle_response(&bedrock_event, client, auth_error_mode).await;
    }

    if let Some(ciba) = ciba {
        return handle_request_phase_with_ciba(bedrock_event, client, ciba).await;
    }

    // REQUEST interceptor phase: transform Bedrock event -> Sideband InboundRequest
    let inbound_result = build_inbound_request(&bedrock_event);

    // Call P1AZ (only if transform succeeded)
    let sideband_result = match inbound_result {
        Ok(req) => client.send_inbound_request(&req).await,
        Err(e) => Err(e),
    };

    // Map result -> Bedrock response (this never fails - errors become error responses)
    build_bedrock_response(&bedrock_event, sideband_result)
}

/// The REQUEST phase with the CIBA approval flow; see [`handle_request_with_ciba`].
async fn handle_request_phase_with_ciba(
    mut event: BedrockEvent,
    client: &SidebandClient,
    ciba: &Ciba,
) -> BedrockResponse {
    let request_id = extract_request_id(&event);
    let claims = ciba::caller_claims(&event);
    let subject = ciba::claim(&claims, &ciba.config.subject_claim).unwrap_or("");
    // Computed before anything is removed: a gateway retry of this exact
    // request has the same raw body (and caller).
    let idempotency_key = ciba::idempotency_key(&event, subject);
    let request_state = ciba::strip_request_state(&mut event);
    if let Some(headers) = event.mcp.gateway_request.as_mut().and_then(|r| r.headers.as_mut()) {
        ciba::strip_trusted_headers(headers, &ciba.config);
    }
    let body = event
        .mcp
        .gateway_request
        .as_ref()
        .and_then(|r| r.body.clone())
        .unwrap_or(serde_json::Value::Null);

    // A client retry carrying the requestState we issued: wait for its approval.
    if let Some(token) = request_state {
        let state = match ciba.open_state(&token, &body, &claims) {
            Ok(state) => state,
            Err(reason) => return ciba::refusal(&request_id, reason),
        };
        return match ciba
            .redeem(&state, &idempotency_key, &body, &claims, &request_id, false)
            .await
        {
            Ok(approved) => {
                send_approved(event, client, ciba, &approved, &state.reference, &idempotency_key, &request_id).await
            }
            Err(response) => response,
        };
    }

    let sideband_result = match build_inbound_request(&event) {
        Ok(req) => client.send_inbound_request(&req).await,
        Err(e) => Err(e),
    };

    let challenge = matches!(&sideband_result, Ok(result) if result.response.as_ref().is_some_and(|deny| ciba.is_ciba_challenge(deny)));
    if challenge {
        let state = match ciba.start_approval(&body, &claims).await {
            Ok(state) => state,
            Err(reason) => return ciba::refusal(&request_id, reason),
        };
        return match ciba
            .redeem(&state, &idempotency_key, &body, &claims, &request_id, true)
            .await
        {
            Ok(approved) => {
                send_approved(event, client, ciba, &approved, &state.reference, &idempotency_key, &request_id).await
            }
            Err(response) => response,
        };
    }

    forward_without_trusted_headers(&event, sideband_result, ciba)
}

/// Ask the policy again for an approved request, with the trusted approval
/// headers; on PERMIT, record the approval as spent and forward the request.
async fn send_approved(
    mut event: BedrockEvent,
    client: &SidebandClient,
    ciba: &Ciba,
    approved: &ciba::Approval,
    reference: &str,
    idempotency_key: &str,
    request_id: &serde_json::Value,
) -> BedrockResponse {
    if let Some(headers) = event.mcp.gateway_request.as_mut().and_then(|r| r.headers.as_mut()) {
        ciba::add_trusted_headers(headers, &ciba.config, &approved.approver);
    }
    let sideband_result = match build_inbound_request(&event) {
        Ok(req) => client.send_inbound_request(&req).await,
        Err(e) => Err(e),
    };
    if let Ok(result) = &sideband_result {
        match &result.response {
            // The policy still asks for an approval after one was given;
            // starting another would loop.
            Some(deny) if ciba.is_ciba_challenge(deny) => {
                return ciba::refusal(request_id, "approval_not_accepted");
            }
            None if !approved.already_spent => {
                if let Err(response) = ciba
                    .spend(reference, idempotency_key, &approved.approver, request_id)
                    .await
                {
                    return response;
                }
            }
            _ => {}
        }
    }
    forward_without_trusted_headers(&event, sideband_result, ciba)
}

/// Upstream's response for the sideband decision, minus the trusted approval
/// headers: they are for the policy only, never for the target.
fn forward_without_trusted_headers(
    event: &BedrockEvent,
    sideband_result: Result<InboundRequestResult, AuthorizerError>,
    ciba: &Ciba,
) -> BedrockResponse {
    let mut response = build_bedrock_response(event, sideband_result);
    if let Some(headers) = response
        .mcp
        .transformed_gateway_request
        .as_mut()
        .and_then(|r| r.headers.as_mut())
    {
        ciba::strip_trusted_headers(headers, &ciba.config);
    }
    response
}

/// Convert a Bedrock AgentCore event into a sideband `InboundRequest`.
///
/// # Field Mapping
/// - `method` = `gatewayRequest.httpMethod`
/// - `url` = `"https://" + Host_header + gatewayRequest.path`
/// - `http_version` = `"1.1"`
/// - `source_ip` = `"0.0.0.0"` (placeholder)
/// - `source_port` = `1` (placeholder)
/// - `headers` = `gatewayRequest.headers` converted to sideband array format
/// - `body` = `rawGatewayRequest.body`
///
/// # Errors
/// - `Transform` error if `gatewayRequest` is missing
/// - `Transform` error if headers are missing (passRequestHeaders not configured)
/// - `Transform` error if the `Host` header is missing
pub fn build_inbound_request(event: &BedrockEvent) -> Result<InboundRequest, AuthorizerError> {
    let gateway_request = event
        .mcp
        .gateway_request
        .as_ref()
        .ok_or_else(|| AuthorizerError::Transform("gatewayRequest is missing".to_string()))?;

    let headers = gateway_request.headers.as_ref().ok_or_else(|| {
        AuthorizerError::Transform(
            "headers is missing -- ensure passRequestHeaders is enabled on the interceptor"
                .to_string(),
        )
    })?;

    let url = request_url(gateway_request)?;
    let sideband_headers = helpers::headers_to_sideband_array(headers);

    let body = event
        .mcp
        .raw_gateway_request
        .as_ref()
        .and_then(|r| r.body.clone());

    Ok(InboundRequest {
        method: gateway_request.http_method.clone(),
        url,
        http_version: "1.1".to_string(),
        source_ip: "0.0.0.0".to_string(),
        source_port: 1,
        headers: sideband_headers,
        body,
    })
}

/// Build the `https://<Host>/<path>` URL for a gateway request.
///
/// # Errors
/// - `Transform` error if `headers` or the `Host` header is missing.
fn request_url(gateway_request: &GatewayRequest) -> Result<String, AuthorizerError> {
    let headers = gateway_request.headers.as_ref().ok_or_else(|| {
        AuthorizerError::Transform(
            "headers is missing -- ensure passRequestHeaders is enabled on the interceptor"
                .to_string(),
        )
    })?;

    let host = helpers::find_header(headers, "Host").ok_or_else(|| {
        AuthorizerError::Transform("Host header is missing from the request".to_string())
    })?;

    Ok(helpers::build_url("https", host, &gateway_request.path))
}

/// (fork) Remove the `x-paz-state` carrier from a REQUEST-phase PERMIT, so the
/// RESPONSE phase passes the response through unauthorized. Used with
/// `RESPONSE_AUTHORIZATION=off`; see [`crate::config::response_authorization_from_env`].
pub fn drop_state_carrier(response: &mut BedrockResponse) {
    if let Some(headers) = response
        .mcp
        .transformed_gateway_request
        .as_mut()
        .and_then(|r| r.headers.as_mut())
    {
        helpers::remove_header(headers, helpers::REQUEST_STATE_CARRIER);
    }
}

/// Convert a sideband result (or error) into a Bedrock response.
///
/// This function never fails -- errors are converted into error responses.
///
/// # Response Mapping
/// - **PERMIT** (`Ok`, no `response` field): `transformedGatewayRequest` with headers + body
/// - **DENY** (`Ok`, has `response` field): `transformedGatewayResponse` with status + JSON-RPC body.
///   In [`AuthErrorMode::JsonRpc`], the 4xx DENY carrying `www-authenticate` keeps its
///   transport shape here (so the carrier path stays runtime-proven) and is converted
///   to an HTTP 200 in-band challenge by the RESPONSE phase's re-hydration.
/// - **SidebandHttp 429**: `transformedGatewayResponse` with 429 + JSON-RPC error
/// - **SidebandHttp other / Network / Json**: `transformedGatewayResponse` with 502 + JSON-RPC error
pub fn build_bedrock_response(
    event: &BedrockEvent,
    result: Result<InboundRequestResult, AuthorizerError>,
) -> BedrockResponse {
    let request_id = extract_request_id(event);

    let response = match result {
        Ok(sideband_result) => {
            if let Some(deny) = sideband_result.response {
                // DENY
                info!(
                    response_code = %deny.response_code,
                    response_status = %deny.response_status,
                    "Authorization decision: DENY"
                );

                let status_code = deny.response_code.parse::<u16>().unwrap_or(403);

                let body =
                    build_deny_body(&deny.body, status_code, &deny.response_status, &request_id);

                // Stash the deny headers (e.g. www-authenticate) for the RESPONSE
                // phase. Bedrock forbids headers on a REQUEST interceptor's
                // `transformedGatewayResponse`, so we mirror the original request
                // and smuggle the encoded headers through `x-paz-response-headers`.
                // The response short-circuits, so the mirrored request is never
                // forwarded to the backend.
                let transformed_gateway_request = if deny.headers.is_empty() {
                    None
                } else {
                    Some(build_deny_carrier_request(event, &deny.headers))
                };

                BedrockResponse {
                    interceptor_output_version: "1.0".to_string(),
                    mcp: McpOutput {
                        transformed_gateway_request,
                        transformed_gateway_response: Some(TransformedResponse {
                            status_code,
                            headers: None,
                            body,
                        }),
                    },
                }
            } else {
                // PERMIT
                info!("Authorization decision: PERMIT");

                let mut flat_headers =
                    helpers::sideband_array_to_flat_headers(&sideband_result.headers);
                // (fork) An Authorization header in the interceptor's output overrides the
                // target's credential provider: the Gateway forwards it to the target as is.
                // Echoing the client's own token back would replace the outbound credential
                // (e.g. an on-behalf-of token exchange), so only forward one the policy changed.
                let original_authorization = event
                    .mcp
                    .gateway_request
                    .as_ref()
                    .and_then(|r| r.headers.as_ref())
                    .and_then(|h| helpers::find_header(h, "authorization"));
                if helpers::find_header(&flat_headers, "authorization") == original_authorization {
                    helpers::remove_header(&mut flat_headers, "authorization");
                }
                if let Some(state) = &sideband_result.state {
                    flat_headers.insert(helpers::REQUEST_STATE_CARRIER.to_string(), state.clone());
                }
                let body = match &sideband_result.body {
                    Some(body_str) => {
                        serde_json::from_str(body_str).unwrap_or(serde_json::Value::Null)
                    }
                    None => serde_json::Value::Null,
                };

                BedrockResponse {
                    interceptor_output_version: "1.0".to_string(),
                    mcp: McpOutput {
                        transformed_gateway_request: Some(TransformedRequest {
                            headers: Some(flat_headers),
                            body,
                        }),
                        transformed_gateway_response: None,
                    },
                }
            }
        }
        Err(err) => error_response(request_id, &err),
    };

    trace!(
        response = %serde_json::to_string(&response).unwrap_or_default(),
        "Bedrock response"
    );

    response
}

/// Map an [`AuthorizerError`] to a Bedrock error `transformedGatewayResponse`.
///
/// Shared by the REQUEST phase (`build_bedrock_response`) and the RESPONSE
/// phase (`authorize_response`) -- both fail closed on a sideband call error,
/// using the same status-code mapping: 429 stays 429, everything else is 502.
fn error_response(request_id: serde_json::Value, err: &AuthorizerError) -> BedrockResponse {
    let (status_code, message) = match err {
        AuthorizerError::SidebandHttp { status, message } => {
            if *status == 429 {
                (
                    429u16,
                    format!("Rate limited by authorization service: {message}"),
                )
            } else {
                (
                    502u16,
                    format!("Authorization service error (HTTP {status}): {message}"),
                )
            }
        }
        AuthorizerError::Network(e) => (502u16, format!("Authorization service unavailable: {e}")),
        AuthorizerError::Transform(msg) => (502u16, format!("Request transform error: {msg}")),
        AuthorizerError::Json(e) => (
            502u16,
            format!("Authorization service response parse error: {e}"),
        ),
        AuthorizerError::Config(msg) => (502u16, format!("Configuration error: {msg}")),
    };

    info!(
        status_code = status_code,
        error = %err,
        "Authorization decision: ERROR"
    );

    let body = helpers::build_jsonrpc_error(request_id, -32603, &message);

    BedrockResponse {
        interceptor_output_version: "1.0".to_string(),
        mcp: McpOutput {
            transformed_gateway_request: None,
            transformed_gateway_response: Some(TransformedResponse {
                status_code,
                headers: None,
                body,
            }),
        },
    }
}

/// Build a Bedrock error response without requiring a fully parsed `BedrockEvent`.
///
/// Used when the incoming event cannot be deserialized at all, so we have no
/// typed event to work with. The `request_id` should be extracted from the raw
/// JSON if possible, or `Value::Null` if not.
pub fn build_error_response(
    request_id: serde_json::Value,
    status_code: u16,
    message: &str,
) -> BedrockResponse {
    let body = helpers::build_jsonrpc_error(request_id, -32603, message);

    let response = BedrockResponse {
        interceptor_output_version: "1.0".to_string(),
        mcp: McpOutput {
            transformed_gateway_request: None,
            transformed_gateway_response: Some(TransformedResponse {
                status_code,
                headers: None,
                body,
            }),
        },
    };

    trace!(
        response = %serde_json::to_string(&response).unwrap_or_default(),
        "Bedrock response"
    );

    response
}

/// Build the body for a DENY response.
///
/// 1. If the deny body is present:
///    a. Try to parse as JSON.
///    b. If it's already a JSON-RPC error (has `jsonrpc` + `error` fields), use as-is.
///    c. Otherwise, wrap in a JSON-RPC error envelope ([`helpers::P1AZ_GENERIC_ERROR_CODE`]).
/// 2. If the deny body is absent:
///    a. Use "Service provider error HTTP {status} {reason}" as the error message.
fn build_deny_body(
    deny_body: &Option<String>,
    status_code: u16,
    response_status: &str,
    request_id: &serde_json::Value,
) -> serde_json::Value {
    let wrap = |message: &str| {
        helpers::build_jsonrpc_error(
            request_id.clone(),
            helpers::P1AZ_GENERIC_ERROR_CODE,
            message,
        )
    };

    match deny_body {
        Some(body_str) => {
            // Try to parse as JSON
            match serde_json::from_str::<serde_json::Value>(body_str) {
                Ok(parsed) => {
                    if helpers::is_jsonrpc_error(&parsed) {
                        // Already a proper JSON-RPC error -- pass through
                        parsed
                    } else {
                        // JSON but not JSON-RPC -- wrap it
                        wrap(body_str)
                    }
                }
                Err(_) => {
                    // Not valid JSON -- use the raw string as the message
                    wrap(body_str)
                }
            }
        }
        None => {
            // No body -- synthesize a message from the status and reason phrase.
            let reason = if response_status.is_empty() {
                helpers::reason_phrase(status_code)
            } else {
                response_status
            };
            wrap(&format!(
                "Service provider error HTTP {status_code} {reason}"
            ))
        }
    }
}

/// In `jsonrpc` auth-error mode, detect an upstream auth challenge -- an HTTP
/// 4xx response carrying a `www-authenticate` header -- and build the JSON-RPC
/// error body that replaces the original response.
///
/// On a challenge: removes `www-authenticate` and the now-stale
/// `content-length` from `headers` (the body is replaced), logs, and returns
/// `Some(body)`; the caller must then send HTTP 200 with that body. Returns
/// `None` when the mode is off, the status is not a convertible 4xx, or there
/// is no `www-authenticate` header -- the caller proceeds exactly as before.
///
/// 429 is explicitly NOT a challenge: rate limiting is not an auth error the
/// client can step up from, so it keeps its transport-level status.
fn maybe_convert_auth_error(
    auth_error_mode: AuthErrorMode,
    status_code: u16,
    headers: &mut HashMap<String, String>,
    request_id: &serde_json::Value,
) -> Option<serde_json::Value> {
    if auth_error_mode != AuthErrorMode::JsonRpc
        || !(400..500).contains(&status_code)
        || status_code == 429
    {
        return None;
    }

    let www_authenticate = helpers::find_header(headers, "www-authenticate")?.to_string();

    helpers::remove_header(headers, "www-authenticate");
    helpers::remove_header(headers, "content-length");

    info!(
        original_status_code = status_code,
        "AUTH_ERROR_MODE=jsonrpc: converting auth challenge to JSON-RPC error response"
    );

    Some(helpers::build_auth_challenge_error(
        request_id.clone(),
        status_code,
        &www_authenticate,
    ))
}

/// Extract the JSON-RPC `"id"` from the Bedrock event's `gatewayRequest.body`.
/// Returns `Value::Null` if not available.
fn extract_request_id(event: &BedrockEvent) -> serde_json::Value {
    event
        .mcp
        .gateway_request
        .as_ref()
        .and_then(|gr| gr.body.as_ref())
        .and_then(|body| body.get("id"))
        .cloned()
        .unwrap_or(serde_json::Value::Null)
}

/// Build the `transformedGatewayRequest` used to smuggle DENY response headers
/// to the RESPONSE interceptor phase.
///
/// It mirrors the original request's headers and body -- deliberately preserving
/// the whole request so a future response-authorization phase has the data it
/// needs -- and adds the [`helpers::RESPONSE_HEADERS_CARRIER`] header carrying
/// the base64-encoded deny headers. This request is never forwarded to the
/// backend because the accompanying `transformedGatewayResponse` short-circuits.
fn build_deny_carrier_request(
    event: &BedrockEvent,
    deny_headers: &[HashMap<String, String>],
) -> TransformedRequest {
    let mut headers = event
        .mcp
        .gateway_request
        .as_ref()
        .and_then(|gr| gr.headers.clone())
        .unwrap_or_default();

    let flat_deny_headers = helpers::sideband_array_to_flat_headers(deny_headers);
    headers.insert(
        helpers::RESPONSE_HEADERS_CARRIER.to_string(),
        helpers::encode_response_headers(&flat_deny_headers),
    );

    let body = event
        .mcp
        .gateway_request
        .as_ref()
        .and_then(|gr| gr.body.clone())
        .unwrap_or(serde_json::Value::Null);

    TransformedRequest {
        headers: Some(headers),
        body,
    }
}

/// Handle a RESPONSE interceptor invocation.
///
/// If [`helpers::REQUEST_STATE_CARRIER`] is present in `gatewayRequest.headers`
/// (stashed by the REQUEST phase on PERMIT), this is a genuine backend response
/// that needs authorizing against `/sideband/response` -- see
/// [`authorize_response`]. Otherwise, this is either a denied short-circuit
/// (which needs its deny headers re-hydrated, not authorized) or a response with
/// nothing to do -- see [`rehydrate_deny_headers`].
pub async fn handle_response(
    event: &BedrockEvent,
    client: &SidebandClient,
    auth_error_mode: AuthErrorMode,
) -> BedrockResponse {
    let state = event
        .mcp
        .gateway_request
        .as_ref()
        .and_then(|gr| gr.headers.as_ref())
        .and_then(|h| helpers::find_header(h, helpers::REQUEST_STATE_CARRIER))
        .map(str::to_string);

    let response = match state {
        Some(state) => authorize_response(event, &state, client, auth_error_mode).await,
        None => rehydrate_deny_headers(event, auth_error_mode),
    };

    trace!(
        response = %serde_json::to_string(&response).unwrap_or_default(),
        "Bedrock response"
    );

    response
}

/// (fork) Pass the RESPONSE phase through: echo `gatewayResponse` (status code,
/// headers, body) as the `transformedGatewayResponse`. AgentCore doesn't treat an
/// empty `mcp` as "unchanged": it sent the client an empty `{}` body. Without a
/// status code there is nothing to echo, and `mcp` stays empty as upstream had it.
fn pass_through(event: &BedrockEvent) -> BedrockResponse {
    let gateway_response = event.mcp.gateway_response.as_ref();
    let transformed = gateway_response.and_then(|gr| {
        Some(TransformedResponse {
            status_code: gr.status_code?,
            headers: gr.headers.clone(),
            body: gr.body.clone().unwrap_or(serde_json::Value::Null),
        })
    });
    BedrockResponse {
        interceptor_output_version: "1.0".to_string(),
        mcp: McpOutput {
            transformed_gateway_request: None,
            transformed_gateway_response: transformed,
        },
    }
}

/// Re-hydrate deny headers stashed during the REQUEST phase, or pass through.
///
/// If a [`helpers::RESPONSE_HEADERS_CARRIER`] header is present in
/// `gatewayRequest.headers` (stashed by the REQUEST phase on a DENY), decode it
/// and emit a `transformedGatewayResponse` that adds those headers to the
/// outgoing response while preserving its `statusCode` and `body`. In
/// [`AuthErrorMode::JsonRpc`], a re-hydrated 4xx response carrying
/// `www-authenticate` is converted into an HTTP 200 in-band challenge instead
/// (covers a rolling deploy where the REQUEST phase ran old code). Otherwise,
/// pass the response through unchanged ([`pass_through`]). Makes no P1AZ call.
fn rehydrate_deny_headers(event: &BedrockEvent, auth_error_mode: AuthErrorMode) -> BedrockResponse {
    let request_id = extract_request_id(event);

    let carrier = event
        .mcp
        .gateway_request
        .as_ref()
        .and_then(|gr| gr.headers.as_ref())
        .and_then(|h| helpers::find_header(h, helpers::RESPONSE_HEADERS_CARRIER));

    let decoded = carrier.and_then(helpers::decode_response_headers);

    let gateway_response = event.mcp.gateway_response.as_ref();
    let status_code = gateway_response.and_then(|gr| gr.status_code);

    // Nothing to restore, or no status code to build a response with -> pass through.
    let (decoded, status_code) = match (decoded, status_code) {
        (Some(decoded), Some(status_code)) if !decoded.is_empty() => (decoded, status_code),
        _ => {
            info!("RESPONSE phase: no deny headers to restore, passing through");
            return pass_through(event);
        }
    };

    // Merge decoded deny headers over the response's existing headers (decoded win).
    let mut headers = gateway_response
        .and_then(|gr| gr.headers.clone())
        .unwrap_or_default();
    headers.extend(decoded);

    let body = gateway_response
        .and_then(|gr| gr.body.clone())
        .unwrap_or(serde_json::Value::Null);

    // In jsonrpc mode, a re-hydrated 4xx challenge converts to an in-band HTTP
    // 200 -- e.g. a rolling deploy where the REQUEST phase ran old code and
    // stashed a carrier for a 401.
    if let Some(converted) =
        maybe_convert_auth_error(auth_error_mode, status_code, &mut headers, &request_id)
    {
        info!(
            header_count = headers.len(),
            "RESPONSE phase: converting re-hydrated deny headers to in-band auth challenge"
        );
        return BedrockResponse {
            interceptor_output_version: "1.0".to_string(),
            mcp: McpOutput {
                transformed_gateway_request: None,
                transformed_gateway_response: Some(TransformedResponse {
                    status_code: 200,
                    headers: Some(headers),
                    body: converted,
                }),
            },
        };
    }

    info!(
        header_count = headers.len(),
        "RESPONSE phase: restoring deny headers onto response"
    );

    BedrockResponse {
        interceptor_output_version: "1.0".to_string(),
        mcp: McpOutput {
            transformed_gateway_request: None,
            transformed_gateway_response: Some(TransformedResponse {
                status_code,
                headers: Some(headers),
                body,
            }),
        },
    }
}

/// Authorize a genuine backend response against P1AZ's `/sideband/response`.
///
/// Builds an [`OutboundResponse`] from `gatewayResponse` (carrying the replayed
/// `state`), sends it to P1AZ, and forwards the (possibly transformed) result to
/// the client verbatim -- there is no PERMIT/DENY branch on the response phase.
/// **Fails closed** (502, or 429 on rate limiting) if the P1AZ call errors.
///
/// Only a genuinely non-streaming response with a known status code can be
/// authorized:
/// - `is_streaming_response` is `Some(true)` or absent -- either a chunked
///   `text/event-stream` response (only its first event carries a status code)
///   or a Gateway that doesn't report the flag at all. Either way we can't be
///   sure this is the single, complete response, so it passes through
///   unauthorized rather than risk mis-authorizing a partial chunk.
/// - `is_streaming_response` is `Some(false)` but no status code is present --
///   passes through unchanged (defensive; shouldn't happen in practice).
///
/// The sideband protocol requires a non-empty `headers` object on
/// `OutboundResponse`, but Bedrock Gateway doesn't guarantee it sends the
/// RESPONSE interceptor any response headers. If `gatewayResponse.headers` is
/// absent or empty, a `content-type: application/json` header is synthesized
/// before authorizing.
async fn authorize_response(
    event: &BedrockEvent,
    state: &str,
    client: &SidebandClient,
    auth_error_mode: AuthErrorMode,
) -> BedrockResponse {
    let request_id = extract_request_id(event);

    let gateway_request = match event.mcp.gateway_request.as_ref() {
        Some(gr) => gr,
        None => {
            return error_response(
                request_id,
                &AuthorizerError::Transform("gatewayRequest is missing".to_string()),
            )
        }
    };

    let gateway_response = match event.mcp.gateway_response.as_ref() {
        Some(gr) => gr,
        None => {
            return error_response(
                request_id,
                &AuthorizerError::Transform("gatewayResponse is missing".to_string()),
            )
        }
    };

    if gateway_response.is_streaming_response != Some(false) {
        info!("RESPONSE phase: streaming (or unreported) response, passing through unauthorized");
        return pass_through(event);
    }

    let status_code = match gateway_response.status_code {
        Some(status_code) => status_code,
        None => {
            info!("RESPONSE phase: no status code to authorize, passing through");
            return pass_through(event);
        }
    };

    let url = match request_url(gateway_request) {
        Ok(url) => url,
        Err(e) => return error_response(request_id, &e),
    };

    let mut headers = gateway_response.headers.clone().unwrap_or_default();
    if headers.is_empty() {
        headers.insert("content-type".to_string(), "application/json".to_string());
    }
    let body = gateway_response
        .body
        .as_ref()
        .map(|b| serde_json::to_string(b).unwrap_or_default());

    let outbound = OutboundResponse {
        url,
        method: gateway_request.http_method.clone(),
        response_code: status_code.to_string(),
        response_status: helpers::reason_phrase(status_code).to_string(),
        http_version: "1.1".to_string(),
        headers: helpers::headers_to_sideband_array(&headers),
        body,
        state: Some(state.to_string()),
    };

    match client.send_outbound_response(&outbound).await {
        Ok(result) => build_authorized_response(result, status_code, auth_error_mode, &request_id),
        Err(e) => {
            info!(error = %e, "Response authorization: ERROR");
            error_response(request_id, &e)
        }
    }
}

/// Convert an [`OutboundResponseResult`] into the `transformedGatewayResponse`
/// forwarded to the client, falling back to the original `status_code` if P1AZ's
/// `response_code` doesn't parse.
///
/// In [`AuthErrorMode::JsonRpc`], a 4xx result carrying `www-authenticate` (a
/// backend auth challenge forwarded through P1AZ) is converted into an HTTP 200
/// in-band challenge; its headers keep everything except `www-authenticate` and
/// the now-stale `content-length`.
fn build_authorized_response(
    result: OutboundResponseResult,
    original_status_code: u16,
    auth_error_mode: AuthErrorMode,
    request_id: &serde_json::Value,
) -> BedrockResponse {
    let status_code = result
        .response_code
        .parse::<u16>()
        .unwrap_or(original_status_code);
    let mut headers = helpers::sideband_array_to_flat_headers(&result.headers);
    let body = match &result.body {
        Some(body_str) => serde_json::from_str(body_str).unwrap_or(serde_json::Value::Null),
        None => serde_json::Value::Null,
    };

    let (status_code, body) =
        match maybe_convert_auth_error(auth_error_mode, status_code, &mut headers, request_id) {
            Some(converted) => (200u16, converted),
            None => (status_code, body),
        };

    BedrockResponse {
        interceptor_output_version: "1.0".to_string(),
        mcp: McpOutput {
            transformed_gateway_request: None,
            transformed_gateway_response: Some(TransformedResponse {
                status_code,
                headers: Some(headers),
                body,
            }),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_bedrock_event(
        headers: Option<HashMap<String, String>>,
        body: Option<serde_json::Value>,
        raw_body: Option<String>,
    ) -> BedrockEvent {
        BedrockEvent {
            interceptor_input_version: "1.0".to_string(),
            mcp: McpInput {
                gateway_request: Some(GatewayRequest {
                    path: "/mcp".to_string(),
                    http_method: "POST".to_string(),
                    headers,
                    body,
                    context: None,
                }),
                gateway_response: None,
                raw_gateway_request: Some(RawGatewayRequest { body: raw_body }),
            },
        }
    }

    fn default_headers() -> HashMap<String, String> {
        let mut h = HashMap::new();
        h.insert(
            "Host".to_string(),
            "example.gateway.bedrock-agentcore.us-east-1.amazonaws.com".to_string(),
        );
        h.insert("content-type".to_string(), "application/json".to_string());
        h.insert("authorization".to_string(), "Bearer test-token".to_string());
        h
    }

    // --- build_inbound_request tests ---

    #[test]
    fn build_inbound_request_tools_call() {
        let body = json!({
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "echo_payload",
                "arguments": {"note": "test"}
            },
            "jsonrpc": "2.0"
        });
        let raw_body = serde_json::to_string(&body).unwrap();
        let event = make_bedrock_event(Some(default_headers()), Some(body), Some(raw_body.clone()));

        let result = build_inbound_request(&event).unwrap();
        assert_eq!(result.method, "POST");
        assert!(result.url.starts_with("https://"));
        assert!(result.url.contains("example.gateway.bedrock-agentcore"));
        assert!(result.url.ends_with("/mcp"));
        assert_eq!(result.http_version, "1.1");
        assert_eq!(result.source_ip, "0.0.0.0");
        assert_eq!(result.source_port, 1);
        assert!(!result.headers.is_empty());
        assert_eq!(result.body.unwrap(), raw_body);
    }

    #[test]
    fn build_inbound_request_tools_list() {
        let body = json!({
            "id": 1,
            "method": "tools/list",
            "jsonrpc": "2.0"
        });
        let raw_body = serde_json::to_string(&body).unwrap();
        let event = make_bedrock_event(Some(default_headers()), Some(body), Some(raw_body));

        let result = build_inbound_request(&event).unwrap();
        assert_eq!(result.method, "POST");
    }

    #[test]
    fn build_inbound_request_missing_gateway_request() {
        let event = BedrockEvent {
            interceptor_input_version: "1.0".to_string(),
            mcp: McpInput {
                gateway_request: None,
                gateway_response: None,
                raw_gateway_request: None,
            },
        };

        let err = build_inbound_request(&event).unwrap_err();
        match err {
            AuthorizerError::Transform(msg) => assert!(msg.contains("gatewayRequest")),
            other => panic!("Expected Transform error, got: {other:?}"),
        }
    }

    #[test]
    fn build_inbound_request_missing_headers() {
        let event = make_bedrock_event(None, None, None);

        let err = build_inbound_request(&event).unwrap_err();
        match err {
            AuthorizerError::Transform(msg) => assert!(msg.contains("passRequestHeaders")),
            other => panic!("Expected Transform error, got: {other:?}"),
        }
    }

    #[test]
    fn build_inbound_request_missing_host_header() {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        // No Host header

        let event = make_bedrock_event(Some(headers), None, None);

        let err = build_inbound_request(&event).unwrap_err();
        match err {
            AuthorizerError::Transform(msg) => assert!(msg.contains("Host")),
            other => panic!("Expected Transform error, got: {other:?}"),
        }
    }

    #[test]
    fn build_inbound_request_missing_raw_body() {
        let event = make_bedrock_event(Some(default_headers()), None, None);

        let result = build_inbound_request(&event).unwrap();
        assert!(result.body.is_none());
    }

    // --- build_bedrock_response tests ---

    fn make_permit_result(
        headers: Vec<HashMap<String, String>>,
        body: Option<String>,
    ) -> InboundRequestResult {
        InboundRequestResult {
            method: "POST".to_string(),
            url: "https://example.com/mcp".to_string(),
            http_version: "1.1".to_string(),
            source_ip: "0.0.0.0".to_string(),
            source_port: 1,
            headers,
            body,
            response: None,
            state: None,
        }
    }

    fn make_deny_result(
        response_code: &str,
        response_status: &str,
        body: Option<String>,
    ) -> InboundRequestResult {
        use crate::models::DeniedRequestResponse;
        InboundRequestResult {
            method: "POST".to_string(),
            url: "https://example.com/mcp".to_string(),
            http_version: "1.1".to_string(),
            source_ip: "0.0.0.0".to_string(),
            source_port: 1,
            headers: vec![],
            body: None,
            response: Some(DeniedRequestResponse {
                response_code: response_code.to_string(),
                response_status: response_status.to_string(),
                http_version: "1.1".to_string(),
                headers: vec![],
                body,
            }),
            state: Some("test-state".to_string()),
        }
    }

    /// A deny result whose response carries headers (sideband array format).
    fn make_deny_result_with_headers(
        response_code: &str,
        response_status: &str,
        deny_headers: Vec<(&str, &str)>,
    ) -> InboundRequestResult {
        use crate::models::DeniedRequestResponse;
        let headers = deny_headers
            .into_iter()
            .map(|(k, v)| {
                let mut m = HashMap::new();
                m.insert(k.to_string(), v.to_string());
                m
            })
            .collect();
        InboundRequestResult {
            method: "POST".to_string(),
            url: "https://example.com/mcp".to_string(),
            http_version: "1.1".to_string(),
            source_ip: "0.0.0.0".to_string(),
            source_port: 1,
            headers: vec![],
            body: None,
            response: Some(DeniedRequestResponse {
                response_code: response_code.to_string(),
                response_status: response_status.to_string(),
                http_version: "1.1".to_string(),
                headers,
                body: None,
            }),
            state: Some("test-state".to_string()),
        }
    }

    /// Build a RESPONSE-phase event: a `gatewayResponse` is present, and the
    /// request headers optionally carry the response-headers carrier.
    ///
    /// `is_streaming_response` defaults to `None` (Gateway didn't report it);
    /// use [`make_response_event_streaming`] to set it explicitly.
    /// (fork) A pass-through echoes the Gateway's response (AgentCore sends an
    /// empty `mcp` to the client as an empty `{}` body).
    fn assert_passed_through(response: &BedrockResponse, status_code: u16, body: serde_json::Value) {
        assert!(response.mcp.transformed_gateway_request.is_none());
        let echoed = response.mcp.transformed_gateway_response.as_ref().expect("an echoed response");
        assert_eq!(echoed.status_code, status_code);
        assert_eq!(echoed.body, body);
    }

    fn make_response_event(
        request_headers: Option<HashMap<String, String>>,
        response_status: Option<u16>,
        response_headers: Option<HashMap<String, String>>,
        response_body: Option<serde_json::Value>,
    ) -> BedrockEvent {
        make_response_event_streaming(
            request_headers,
            response_status,
            response_headers,
            response_body,
            None,
        )
    }

    /// Like [`make_response_event`], but with an explicit `is_streaming_response`.
    fn make_response_event_streaming(
        request_headers: Option<HashMap<String, String>>,
        response_status: Option<u16>,
        response_headers: Option<HashMap<String, String>>,
        response_body: Option<serde_json::Value>,
        is_streaming_response: Option<bool>,
    ) -> BedrockEvent {
        BedrockEvent {
            interceptor_input_version: "1.0".to_string(),
            mcp: McpInput {
                gateway_request: Some(GatewayRequest {
                    path: "/mcp".to_string(),
                    http_method: "POST".to_string(),
                    headers: request_headers,
                    body: Some(json!({"id": 1, "jsonrpc": "2.0", "method": "tools/call"})),
                    context: None,
                }),
                gateway_response: Some(GatewayResponse {
                    status_code: response_status,
                    headers: response_headers,
                    body: response_body,
                    is_streaming_response,
                }),
                raw_gateway_request: None,
            },
        }
    }

    #[test]
    fn build_response_permit() {
        let body = json!({"id": 3, "jsonrpc": "2.0", "method": "tools/call", "params": {}});
        let raw_body = serde_json::to_string(&body).unwrap();
        let event = make_bedrock_event(Some(default_headers()), Some(body), Some(raw_body.clone()));

        let sideband_headers = vec![{
            let mut m = HashMap::new();
            m.insert(
                "authorization".to_string(),
                "Bearer modified-token".to_string(),
            );
            m
        }];
        let result = make_permit_result(sideband_headers, Some(raw_body));

        let response = build_bedrock_response(&event, Ok(result));

        assert_eq!(response.interceptor_output_version, "1.0");
        assert!(response.mcp.transformed_gateway_request.is_some());
        assert!(response.mcp.transformed_gateway_response.is_none());

        let req = response.mcp.transformed_gateway_request.unwrap();
        let headers = req.headers.unwrap();
        assert_eq!(
            headers.get("authorization").unwrap(),
            "Bearer modified-token"
        );
        assert_eq!(req.body["id"], 3);
    }

    /// (fork) The client's own token, echoed back unchanged, is not forwarded: as an
    /// interceptor output it would override the target's credential provider.
    #[test]
    fn build_response_permit_drops_unchanged_authorization() {
        let body = json!({"id": 3, "jsonrpc": "2.0", "method": "tools/list"});
        let raw_body = serde_json::to_string(&body).unwrap();
        let event = make_bedrock_event(Some(default_headers()), Some(body), Some(raw_body.clone()));

        let sideband_headers = vec![
            HashMap::from([("Authorization".to_string(), "Bearer test-token".to_string())]),
            HashMap::from([("content-type".to_string(), "application/json".to_string())]),
        ];
        let result = make_permit_result(sideband_headers, Some(raw_body));

        let req = build_bedrock_response(&event, Ok(result))
            .mcp
            .transformed_gateway_request
            .unwrap();
        let headers = req.headers.unwrap();
        assert_eq!(helpers::find_header(&headers, "authorization"), None);
        assert_eq!(headers.get("content-type").unwrap(), "application/json");
    }

    /// (fork) With response authorization off, a PERMIT forwards no state carrier
    /// (the RESPONSE phase then passes the response through); other headers stay.
    #[test]
    fn drop_state_carrier_removes_only_the_carrier() {
        let body = json!({"id": 3, "jsonrpc": "2.0", "method": "tools/list"});
        let raw_body = serde_json::to_string(&body).unwrap();
        let event = make_bedrock_event(Some(default_headers()), Some(body), Some(raw_body.clone()));
        let sideband_headers =
            vec![HashMap::from([("content-type".to_string(), "application/json".to_string())])];
        let mut result = make_permit_result(sideband_headers, Some(raw_body));
        result.state = Some("opaque-state".to_string());

        let mut response = build_bedrock_response(&event, Ok(result));
        let headers = |r: &BedrockResponse| {
            r.mcp.transformed_gateway_request.as_ref().unwrap().headers.clone().unwrap()
        };
        assert!(headers(&response).contains_key(helpers::REQUEST_STATE_CARRIER));

        drop_state_carrier(&mut response);
        assert!(!headers(&response).contains_key(helpers::REQUEST_STATE_CARRIER));
        assert_eq!(headers(&response).get("content-type").unwrap(), "application/json");
    }

    #[test]
    fn build_response_permit_modified_body() {
        let original_body = json!({"id": 3, "jsonrpc": "2.0", "method": "tools/call"});
        let modified_body =
            json!({"id": 3, "jsonrpc": "2.0", "method": "tools/call", "extra": "added"});
        let modified_body_str = serde_json::to_string(&modified_body).unwrap();

        let event = make_bedrock_event(Some(default_headers()), Some(original_body), None);

        let result = make_permit_result(vec![], Some(modified_body_str));
        let response = build_bedrock_response(&event, Ok(result));

        let req = response.mcp.transformed_gateway_request.unwrap();
        assert_eq!(req.body["extra"], "added");
    }

    #[test]
    fn build_response_deny_401() {
        let body = json!({"id": 5, "jsonrpc": "2.0", "method": "tools/call"});
        let event = make_bedrock_event(Some(default_headers()), Some(body), None);

        let result = make_deny_result("401", "Unauthorized", None);
        let response = build_bedrock_response(&event, Ok(result));

        assert!(response.mcp.transformed_gateway_request.is_none());
        assert!(response.mcp.transformed_gateway_response.is_some());

        let resp = response.mcp.transformed_gateway_response.unwrap();
        assert_eq!(resp.status_code, 401);
        assert_eq!(resp.body["error"]["code"], helpers::P1AZ_GENERIC_ERROR_CODE);
        assert_eq!(
            resp.body["error"]["message"],
            "Service provider error HTTP 401 Unauthorized"
        );
        assert_eq!(resp.body["id"], 5);
    }

    #[test]
    fn build_response_deny_403() {
        let body = json!({"id": 7, "jsonrpc": "2.0", "method": "tools/call"});
        let event = make_bedrock_event(Some(default_headers()), Some(body), None);

        let result = make_deny_result(
            "403",
            "Forbidden",
            Some(r#"{"error":"access denied"}"#.to_string()),
        );
        let response = build_bedrock_response(&event, Ok(result));

        let resp = response.mcp.transformed_gateway_response.unwrap();
        assert_eq!(resp.status_code, 403);
        // Body is JSON but not JSON-RPC, so it should be wrapped
        assert_eq!(resp.body["error"]["code"], helpers::P1AZ_GENERIC_ERROR_CODE);
        assert_eq!(resp.body["id"], 7);
    }

    #[test]
    fn build_response_deny_with_jsonrpc_body() {
        let body = json!({"id": 9, "jsonrpc": "2.0", "method": "tools/call"});
        let event = make_bedrock_event(Some(default_headers()), Some(body), None);

        let jsonrpc_error = json!({
            "jsonrpc": "2.0",
            "id": 9,
            "error": {
                "code": -32600,
                "message": "Policy denied access"
            }
        });
        let jsonrpc_error_str = serde_json::to_string(&jsonrpc_error).unwrap();

        let result = make_deny_result("403", "Forbidden", Some(jsonrpc_error_str));
        let response = build_bedrock_response(&event, Ok(result));

        let resp = response.mcp.transformed_gateway_response.unwrap();
        assert_eq!(resp.status_code, 403);
        // Should pass through the JSON-RPC error as-is
        assert_eq!(resp.body["jsonrpc"], "2.0");
        assert_eq!(resp.body["error"]["message"], "Policy denied access");
    }

    #[test]
    fn build_response_deny_with_non_json_body() {
        let body = json!({"id": 11, "jsonrpc": "2.0"});
        let event = make_bedrock_event(Some(default_headers()), Some(body), None);

        let result = make_deny_result("403", "Forbidden", Some("Access Denied".to_string()));
        let response = build_bedrock_response(&event, Ok(result));

        let resp = response.mcp.transformed_gateway_response.unwrap();
        assert_eq!(resp.body["error"]["code"], helpers::P1AZ_GENERIC_ERROR_CODE);
        assert_eq!(resp.body["error"]["message"], "Access Denied");
    }

    #[test]
    fn build_response_deny_no_body() {
        let body = json!({"id": 13, "jsonrpc": "2.0"});
        let event = make_bedrock_event(Some(default_headers()), Some(body), None);

        let result = make_deny_result("403", "Forbidden", None);
        let response = build_bedrock_response(&event, Ok(result));

        let resp = response.mcp.transformed_gateway_response.unwrap();
        assert_eq!(resp.body["error"]["code"], helpers::P1AZ_GENERIC_ERROR_CODE);
        assert_eq!(
            resp.body["error"]["message"],
            "Service provider error HTTP 403 Forbidden"
        );
    }

    #[test]
    fn build_response_sideband_http_429() {
        let body = json!({"id": 15, "jsonrpc": "2.0"});
        let event = make_bedrock_event(Some(default_headers()), Some(body), None);

        let err = AuthorizerError::SidebandHttp {
            status: 429,
            message: "Rate limit exceeded".to_string(),
        };
        let response = build_bedrock_response(&event, Err(err));

        let resp = response.mcp.transformed_gateway_response.unwrap();
        assert_eq!(resp.status_code, 429);
        assert_eq!(resp.body["error"]["code"], -32603);
        assert!(resp.body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Rate limited"));
    }

    #[test]
    fn build_response_sideband_http_500() {
        let body = json!({"id": 17, "jsonrpc": "2.0"});
        let event = make_bedrock_event(Some(default_headers()), Some(body), None);

        let err = AuthorizerError::SidebandHttp {
            status: 500,
            message: "Internal server error".to_string(),
        };
        let response = build_bedrock_response(&event, Err(err));

        let resp = response.mcp.transformed_gateway_response.unwrap();
        assert_eq!(resp.status_code, 502);
        assert_eq!(resp.body["error"]["code"], -32603);
    }

    #[test]
    fn build_response_network_error() {
        let body = json!({"id": 19, "jsonrpc": "2.0"});
        let event = make_bedrock_event(Some(default_headers()), Some(body), None);

        // Create a reqwest error by trying to build an invalid request
        let err = AuthorizerError::Transform("simulated network failure".to_string());
        let response = build_bedrock_response(&event, Err(err));

        let resp = response.mcp.transformed_gateway_response.unwrap();
        assert_eq!(resp.status_code, 502);
        assert_eq!(resp.body["error"]["code"], -32603);
    }

    #[test]
    fn build_response_transform_error() {
        let event = BedrockEvent {
            interceptor_input_version: "1.0".to_string(),
            mcp: McpInput {
                gateway_request: None,
                gateway_response: None,
                raw_gateway_request: None,
            },
        };

        let err = AuthorizerError::Transform("gatewayRequest is missing".to_string());
        let response = build_bedrock_response(&event, Err(err));

        let resp = response.mcp.transformed_gateway_response.unwrap();
        assert_eq!(resp.status_code, 502);
        assert!(resp.body["id"].is_null()); // No request id available
    }

    #[test]
    fn extract_request_id_from_event() {
        let body = json!({"id": 42, "jsonrpc": "2.0"});
        let event = make_bedrock_event(Some(default_headers()), Some(body), None);

        let id = extract_request_id(&event);
        assert_eq!(id, json!(42));
    }

    #[test]
    fn extract_request_id_null_when_missing() {
        let event = BedrockEvent {
            interceptor_input_version: "1.0".to_string(),
            mcp: McpInput {
                gateway_request: None,
                gateway_response: None,
                raw_gateway_request: None,
            },
        };

        let id = extract_request_id(&event);
        assert!(id.is_null());
    }

    #[test]
    fn bedrock_event_deserializes_from_json() {
        let json = r#"{
            "interceptorInputVersion": "1.0",
            "mcp": {
                "gatewayRequest": {
                    "path": "/mcp",
                    "httpMethod": "POST",
                    "headers": {
                        "Host": "example.com",
                        "content-type": "application/json"
                    },
                    "body": {"id": 1, "jsonrpc": "2.0", "method": "tools/list"},
                    "context": null
                },
                "gatewayResponse": null,
                "rawGatewayRequest": {
                    "body": "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"tools/list\"}"
                }
            }
        }"#;

        let event: BedrockEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.interceptor_input_version, "1.0");
        let gr = event.mcp.gateway_request.unwrap();
        assert_eq!(gr.path, "/mcp");
        assert_eq!(gr.http_method, "POST");
        assert!(gr.headers.is_some());
        assert!(gr.body.is_some());
        let raw = event.mcp.raw_gateway_request.unwrap();
        assert!(raw.body.is_some());
    }

    #[test]
    fn bedrock_response_serializes_permit_correctly() {
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), "Bearer token".to_string());

        let response = BedrockResponse {
            interceptor_output_version: "1.0".to_string(),
            mcp: McpOutput {
                transformed_gateway_request: Some(TransformedRequest {
                    headers: Some(headers),
                    body: json!({"id": 1, "jsonrpc": "2.0"}),
                }),
                transformed_gateway_response: None,
            },
        };

        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["interceptorOutputVersion"], "1.0");
        assert!(json["mcp"]["transformedGatewayRequest"].is_object());
        assert!(json["mcp"].get("transformedGatewayResponse").is_none());
    }

    #[test]
    fn bedrock_response_serializes_deny_correctly() {
        let response = BedrockResponse {
            interceptor_output_version: "1.0".to_string(),
            mcp: McpOutput {
                transformed_gateway_request: None,
                transformed_gateway_response: Some(TransformedResponse {
                    status_code: 403,
                    headers: None,
                    body: json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "error": {"code": -32600, "message": "Forbidden"}
                    }),
                }),
            },
        };

        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["interceptorOutputVersion"], "1.0");
        assert!(json["mcp"].get("transformedGatewayRequest").is_none());
        assert_eq!(json["mcp"]["transformedGatewayResponse"]["statusCode"], 403);
        // No headers on a REQUEST-phase deny response.
        assert!(json["mcp"]["transformedGatewayResponse"]
            .get("headers")
            .is_none());
    }

    // --- deny header carrier (REQUEST phase) tests ---

    #[test]
    fn deny_with_headers_emits_carrier_request() {
        let body = json!({"id": 5, "jsonrpc": "2.0", "method": "tools/call"});
        let event = make_bedrock_event(Some(default_headers()), Some(body), None);

        let result = make_deny_result_with_headers(
            "401",
            "Unauthorized",
            vec![
                ("www-authenticate", "Bearer realm=\"PingOne Authorize\""),
                ("content-length", "0"),
            ],
        );
        let response = build_bedrock_response(&event, Ok(result));

        // DENY still short-circuits with a response.
        let resp = response.mcp.transformed_gateway_response.as_ref().unwrap();
        assert_eq!(resp.status_code, 401);
        assert!(
            resp.headers.is_none(),
            "REQUEST-phase deny must not set headers"
        );

        // And it also carries the original request + encoded deny headers.
        let req = response.mcp.transformed_gateway_request.unwrap();
        let req_headers = req.headers.unwrap();
        // Original headers preserved.
        assert_eq!(req_headers.get("content-type").unwrap(), "application/json");
        assert_eq!(
            req_headers.get("authorization").unwrap(),
            "Bearer test-token"
        );
        // Body mirrored.
        assert_eq!(req.body["id"], 5);
        // Carrier present and decodes back to the deny headers.
        let carrier = req_headers.get(helpers::RESPONSE_HEADERS_CARRIER).unwrap();
        let decoded = helpers::decode_response_headers(carrier).unwrap();
        assert_eq!(
            decoded.get("www-authenticate").unwrap(),
            "Bearer realm=\"PingOne Authorize\""
        );
        assert_eq!(decoded.get("content-length").unwrap(), "0");
    }

    #[test]
    fn deny_without_headers_emits_no_carrier_request() {
        let body = json!({"id": 7, "jsonrpc": "2.0", "method": "tools/call"});
        let event = make_bedrock_event(Some(default_headers()), Some(body), None);

        let result = make_deny_result("403", "Forbidden", None);
        let response = build_bedrock_response(&event, Ok(result));

        assert!(response.mcp.transformed_gateway_response.is_some());
        assert!(
            response.mcp.transformed_gateway_request.is_none(),
            "No deny headers -> no carrier request"
        );
    }

    // --- AUTH_ERROR_MODE=jsonrpc conversion (REQUEST-phase DENY) tests ---

    /// A deny result whose response carries www-authenticate (with an
    /// error_description to exercise message extraction).
    fn make_challenge_deny_result(
        response_code: &str,
        response_status: &str,
        www_authenticate: &str,
    ) -> InboundRequestResult {
        use crate::models::DeniedRequestResponse;
        let mut header = HashMap::new();
        header.insert("www-authenticate".to_string(), www_authenticate.to_string());
        InboundRequestResult {
            method: "POST".to_string(),
            url: "https://example.com/mcp".to_string(),
            http_version: "1.1".to_string(),
            source_ip: "0.0.0.0".to_string(),
            source_port: 1,
            headers: vec![],
            body: None,
            response: Some(DeniedRequestResponse {
                response_code: response_code.to_string(),
                response_status: response_status.to_string(),
                http_version: "1.1".to_string(),
                headers: vec![header],
                body: None,
            }),
            state: Some("test-state".to_string()),
        }
    }

    #[test]
    fn build_response_deny_jsonrpc_mode_keeps_transport_deny_and_carrier() {
        // The REQUEST phase is mode-invariant: even in JsonRpc mode it emits the
        // transport-level 401 short-circuit + carrier, because Bedrock delivers
        // the short-circuit via the RESPONSE interceptor's output (runtime
        // verified). The conversion happens in the RESPONSE phase's re-hydration.
        let body = json!({"id": 5, "jsonrpc": "2.0", "method": "tools/call"});
        let event = make_bedrock_event(Some(default_headers()), Some(body), None);

        let header = "Bearer realm=\"PingOne Authorize\", error=\"invalid_token\", error_description=\"Token expired\"";
        let result = make_challenge_deny_result("401", "Unauthorized", header);
        let response = build_bedrock_response(&event, Ok(result));

        let resp = response.mcp.transformed_gateway_response.unwrap();
        assert_eq!(resp.status_code, 401);
        assert_eq!(
            resp.body["error"]["message"],
            "Service provider error HTTP 401 Unauthorized"
        );

        let req = response
            .mcp
            .transformed_gateway_request
            .expect("carrier emitted");
        let carrier = req.headers.unwrap();
        let encoded = carrier.get(helpers::RESPONSE_HEADERS_CARRIER).unwrap();
        let decoded = helpers::decode_response_headers(encoded).unwrap();
        assert_eq!(decoded.get("www-authenticate").unwrap(), header);
    }

    #[test]
    fn deny_401_jsonrpc_mode_two_phase_converts_to_200_auth_error() {
        // Full two-phase flow: REQUEST phase emits the carrier, RESPONSE phase
        // converts the re-hydrated 401 challenge to the in-band HTTP 200 error.
        let body = json!({"id": 5, "jsonrpc": "2.0", "method": "tools/call"});
        let event = make_bedrock_event(Some(default_headers()), Some(body), None);

        let header = "Bearer realm=\"PingOne Authorize\", error=\"invalid_token\", error_description=\"Token expired\"";
        let result = make_challenge_deny_result("401", "Unauthorized", header);
        let request_phase = build_bedrock_response(&event, Ok(result));

        // Build the RESPONSE-phase event from the REQUEST phase's actual output,
        // as Bedrock would: the carrier lands in gatewayRequest.headers and the
        // short-circuit is echoed in gatewayResponse.
        let carrier_request = request_phase.mcp.transformed_gateway_request.unwrap();
        let short_circuit = request_phase.mcp.transformed_gateway_response.unwrap();
        let mut req_headers = carrier_request.headers.unwrap();
        req_headers.insert(
            helpers::REQUEST_STATE_CARRIER.to_string(),
            "should-not-matter".to_string(),
        );
        let mut response_event = make_response_event_streaming(
            Some(req_headers),
            Some(short_circuit.status_code),
            None,
            Some(short_circuit.body),
            Some(false),
        );
        // No x-paz-state: the deny carrier alone routes to re-hydration.
        response_event
            .mcp
            .gateway_request
            .as_mut()
            .unwrap()
            .headers
            .as_mut()
            .unwrap()
            .remove(&helpers::REQUEST_STATE_CARRIER.to_string());
        // Align the echoed request id with the original request (id 5).
        response_event
            .mcp
            .gateway_request
            .as_mut()
            .unwrap()
            .body
            .as_mut()
            .unwrap()["id"] = json!(5);

        let response_phase = rehydrate_deny_headers(&response_event, AuthErrorMode::JsonRpc);
        let resp = response_phase.mcp.transformed_gateway_response.unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.body["error"]["code"], helpers::P1AZ_AUTH_ERROR_CODE);
        assert_eq!(resp.body["error"]["message"], "Token expired");
        let details = &resp.body["error"]["data"][helpers::AUTH_CHALLENGE_DATA_KEY];
        assert_eq!(details["status"], 401);
        assert_eq!(details["www_authenticate"], header);
        assert_eq!(resp.body["id"], 5);
    }

    #[test]
    fn maybe_convert_auth_error_strips_content_length() {
        let mut headers = HashMap::new();
        headers.insert(
            "www-authenticate".to_string(),
            "Bearer error_description=\"Token expired\"".to_string(),
        );
        headers.insert("content-length".to_string(), "42".to_string());
        headers.insert("mcp-session-id".to_string(), "abc".to_string());

        let body = maybe_convert_auth_error(
            AuthErrorMode::JsonRpc,
            401,
            &mut headers,
            &serde_json::Value::Null,
        )
        .expect("challenge must convert");

        assert_eq!(body["error"]["message"], "Token expired");
        assert!(!headers.contains_key("www-authenticate"));
        assert!(
            !headers.contains_key("content-length"),
            "stale length stripped"
        );
        assert_eq!(headers.get("mcp-session-id").unwrap(), "abc");
    }

    #[test]
    fn maybe_convert_auth_error_ignores_2xx() {
        let mut headers = HashMap::new();
        headers.insert("www-authenticate".to_string(), "Bearer".to_string());

        assert!(maybe_convert_auth_error(
            AuthErrorMode::JsonRpc,
            200,
            &mut headers,
            &serde_json::Value::Null,
        )
        .is_none());
        assert_eq!(
            headers.get("www-authenticate").unwrap(),
            "Bearer",
            "headers untouched when not converting"
        );
    }

    #[test]
    fn maybe_convert_auth_error_mode_off_returns_none() {
        let mut headers = HashMap::new();
        headers.insert("www-authenticate".to_string(), "Bearer".to_string());

        assert!(maybe_convert_auth_error(
            AuthErrorMode::Http,
            401,
            &mut headers,
            &serde_json::Value::Null,
        )
        .is_none());
        assert_eq!(headers.get("www-authenticate").unwrap(), "Bearer");
    }

    // --- rehydrate_deny_headers / handle_response (RESPONSE phase, no authorization) tests ---

    #[test]
    fn rehydrate_deny_headers_restores_deny_headers() {
        let mut deny_headers = HashMap::new();
        deny_headers.insert(
            "www-authenticate".to_string(),
            "Bearer realm=\"PingOne Authorize\"".to_string(),
        );
        let carrier = helpers::encode_response_headers(&deny_headers);

        let mut req_headers = HashMap::new();
        req_headers.insert(helpers::RESPONSE_HEADERS_CARRIER.to_string(), carrier);

        let mut resp_headers = HashMap::new();
        resp_headers.insert("mcp-session-id".to_string(), "abc".to_string());

        let event = make_response_event(
            Some(req_headers),
            Some(401),
            Some(resp_headers),
            Some(
                json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32600, "message": "Unauthorized"}}),
            ),
        );

        let response = rehydrate_deny_headers(&event, AuthErrorMode::Http);
        let resp = response.mcp.transformed_gateway_response.unwrap();
        assert_eq!(resp.status_code, 401);
        let headers = resp.headers.unwrap();
        // Restored deny header.
        assert_eq!(
            headers.get("www-authenticate").unwrap(),
            "Bearer realm=\"PingOne Authorize\""
        );
        // Existing response header preserved.
        assert_eq!(headers.get("mcp-session-id").unwrap(), "abc");
        // Carrier header itself is not leaked to the client.
        assert!(!headers.contains_key(helpers::RESPONSE_HEADERS_CARRIER));
        // Body preserved.
        assert_eq!(resp.body["error"]["message"], "Unauthorized");
    }

    #[test]
    fn rehydrate_deny_headers_passes_through_without_carrier() {
        let event = make_response_event(
            Some(default_headers()),
            Some(200),
            None,
            Some(json!({"jsonrpc": "2.0", "id": 1, "result": {}})),
        );

        let response = rehydrate_deny_headers(&event, AuthErrorMode::Http);
        assert_passed_through(&response, 200, json!({"jsonrpc": "2.0", "id": 1, "result": {}}));

        // Serializes as an explicit echo, not an empty `mcp`.
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["interceptorOutputVersion"], "1.0");
        assert_eq!(json["mcp"]["transformedGatewayResponse"]["statusCode"], 200);
        assert!(json["mcp"].get("transformedGatewayRequest").is_none());
    }

    #[test]
    fn rehydrate_deny_headers_passes_through_with_undecodable_carrier() {
        let mut req_headers = HashMap::new();
        req_headers.insert(
            helpers::RESPONSE_HEADERS_CARRIER.to_string(),
            "not valid base64 !!!".to_string(),
        );
        let event = make_response_event(
            Some(req_headers),
            Some(200),
            None,
            Some(json!({"jsonrpc": "2.0", "id": 1, "result": {}})),
        );

        let response = rehydrate_deny_headers(&event, AuthErrorMode::Http);
        assert_passed_through(&response, 200, json!({"jsonrpc": "2.0", "id": 1, "result": {}}));
    }

    // --- AUTH_ERROR_MODE=jsonrpc conversion (RESPONSE-phase re-hydration) tests ---

    #[test]
    fn rehydrate_deny_headers_jsonrpc_mode_converts_to_200_auth_error() {
        let mut deny_headers = HashMap::new();
        deny_headers.insert(
            "www-authenticate".to_string(),
            "Bearer error=\"invalid_token\", error_description=\"Token expired\"".to_string(),
        );
        let carrier = helpers::encode_response_headers(&deny_headers);

        let mut req_headers = HashMap::new();
        req_headers.insert(helpers::RESPONSE_HEADERS_CARRIER.to_string(), carrier);

        let mut resp_headers = HashMap::new();
        resp_headers.insert("mcp-session-id".to_string(), "abc".to_string());

        let event = make_response_event(
            Some(req_headers),
            Some(401),
            Some(resp_headers),
            Some(
                json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32600, "message": "Unauthorized"}}),
            ),
        );

        let response = rehydrate_deny_headers(&event, AuthErrorMode::JsonRpc);
        let resp = response.mcp.transformed_gateway_response.unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.body["error"]["code"], helpers::P1AZ_AUTH_ERROR_CODE);
        assert_eq!(resp.body["error"]["message"], "Token expired");
        let details = &resp.body["error"]["data"][helpers::AUTH_CHALLENGE_DATA_KEY];
        assert_eq!(details["status"], 401);
        assert_eq!(resp.body["id"], 1);

        let headers = resp.headers.unwrap();
        assert!(
            !headers.contains_key("www-authenticate"),
            "challenge must leave the transport"
        );
        assert_eq!(headers.get("mcp-session-id").unwrap(), "abc");
    }

    #[test]
    fn rehydrate_deny_headers_jsonrpc_mode_no_challenge_unchanged() {
        // Carrier without www-authenticate -> restored exactly as mode-unset.
        let mut deny_headers = HashMap::new();
        deny_headers.insert("content-length".to_string(), "0".to_string());
        let carrier = helpers::encode_response_headers(&deny_headers);

        let mut req_headers = HashMap::new();
        req_headers.insert(helpers::RESPONSE_HEADERS_CARRIER.to_string(), carrier);

        let event = make_response_event(
            Some(req_headers),
            Some(401),
            None,
            Some(
                json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32600, "message": "Unauthorized"}}),
            ),
        );

        let response = rehydrate_deny_headers(&event, AuthErrorMode::JsonRpc);
        let resp = response.mcp.transformed_gateway_response.unwrap();
        assert_eq!(resp.status_code, 401);
        assert_eq!(resp.body["error"]["message"], "Unauthorized");
    }

    #[test]
    fn rehydrate_deny_headers_jsonrpc_mode_non_4xx_unchanged() {
        // 200 status with a www-authenticate carrier -> restored, not converted.
        let mut deny_headers = HashMap::new();
        deny_headers.insert("www-authenticate".to_string(), "Bearer".to_string());
        let carrier = helpers::encode_response_headers(&deny_headers);

        let mut req_headers = HashMap::new();
        req_headers.insert(helpers::RESPONSE_HEADERS_CARRIER.to_string(), carrier);

        let event = make_response_event(
            Some(req_headers),
            Some(200),
            None,
            Some(json!({"jsonrpc": "2.0", "id": 1, "result": {}})),
        );

        let response = rehydrate_deny_headers(&event, AuthErrorMode::JsonRpc);
        let resp = response.mcp.transformed_gateway_response.unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.body["result"], json!({}));
    }

    #[test]
    fn rehydrate_deny_headers_jsonrpc_mode_429_unchanged() {
        let mut deny_headers = HashMap::new();
        deny_headers.insert("www-authenticate".to_string(), "Bearer".to_string());
        let carrier = helpers::encode_response_headers(&deny_headers);

        let mut req_headers = HashMap::new();
        req_headers.insert(helpers::RESPONSE_HEADERS_CARRIER.to_string(), carrier);

        let event = make_response_event(
            Some(req_headers),
            Some(429),
            None,
            Some(
                json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32603, "message": "Rate limited"}}),
            ),
        );

        let response = rehydrate_deny_headers(&event, AuthErrorMode::JsonRpc);
        let resp = response.mcp.transformed_gateway_response.unwrap();
        assert_eq!(resp.status_code, 429, "429 is never an auth challenge");
    }

    fn test_client(base_url: &str) -> SidebandClient {
        test_client_with_mode(base_url, AuthErrorMode::Http)
    }

    fn test_client_with_mode(base_url: &str, auth_error_mode: AuthErrorMode) -> SidebandClient {
        let config = crate::config::Config::new(
            base_url.to_string(),
            "test-secret".to_string(),
            auth_error_mode,
        );
        SidebandClient::new(&config)
    }

    #[tokio::test]
    async fn handle_request_routes_response_phase() {
        // gatewayResponse present, no x-paz-state -> RESPONSE phase re-hydration path.
        let json = r#"{
            "interceptorInputVersion": "1.0",
            "mcp": {
                "gatewayRequest": {
                    "path": "/mcp",
                    "httpMethod": "POST",
                    "headers": {"Host": "example.com"},
                    "body": {"id": 1, "jsonrpc": "2.0"}
                },
                "gatewayResponse": {
                    "statusCode": 200,
                    "headers": {"mcp-session-id": "s1"},
                    "body": {"jsonrpc": "2.0", "id": 1, "result": {}}
                },
                "rawGatewayRequest": {"body": "{}"}
            }
        }"#;
        let event: BedrockEvent = serde_json::from_str(json).unwrap();
        assert!(event.mcp.gateway_response.is_some());
        let client = test_client("http://unused.invalid");
        let response = handle_response(&event, &client, AuthErrorMode::Http).await;
        // No carrier -> pass through, no P1AZ call made.
        assert_passed_through(&response, 200, json!({"jsonrpc": "2.0", "id": 1, "result": {}}));
        let echoed = response.mcp.transformed_gateway_response.unwrap();
        assert_eq!(echoed.headers.unwrap().get("mcp-session-id").unwrap(), "s1");
    }

    // --- authorize_response (RESPONSE phase authorization) tests ---

    fn make_authorizable_response_event(status_code: u16) -> BedrockEvent {
        let mut req_headers = HashMap::new();
        req_headers.insert("Host".to_string(), "example.com".to_string());
        req_headers.insert(
            helpers::REQUEST_STATE_CARRIER.to_string(),
            "test-state".to_string(),
        );

        let mut resp_headers = HashMap::new();
        resp_headers.insert("mcp-session-id".to_string(), "s1".to_string());

        make_response_event_streaming(
            Some(req_headers),
            Some(status_code),
            Some(resp_headers),
            Some(json!({"jsonrpc": "2.0", "id": 1, "result": {"ok": true}})),
            Some(false),
        )
    }

    #[tokio::test]
    async fn handle_response_authorizes_and_forwards_permit_passthrough() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let result_body = serde_json::json!({
            "response_code": "200",
            "response_status": "OK",
            "headers": [{"mcp-session-id": "s1"}],
            "body": "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}"
        });

        Mock::given(method("POST"))
            .and(path("/sideband/response"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&result_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let event = make_authorizable_response_event(200);

        let response = handle_response(&event, &client, AuthErrorMode::Http).await;
        let resp = response.mcp.transformed_gateway_response.unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.body["result"]["ok"], true);
        assert_eq!(resp.headers.unwrap().get("mcp-session-id").unwrap(), "s1");
    }

    #[tokio::test]
    async fn handle_response_forwards_transformed_result() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let result_body = serde_json::json!({
            "response_code": "200",
            "response_status": "OK",
            "headers": [{"x-transformed": "yes"}],
            "body": "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"redacted\":true}}"
        });

        Mock::given(method("POST"))
            .and(path("/sideband/response"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&result_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let event = make_authorizable_response_event(200);

        let response = handle_response(&event, &client, AuthErrorMode::Http).await;
        let resp = response.mcp.transformed_gateway_response.unwrap();
        assert_eq!(resp.body["result"]["redacted"], true);
        assert_eq!(resp.headers.unwrap().get("x-transformed").unwrap(), "yes");
    }

    #[tokio::test]
    async fn handle_response_fails_closed_on_p1az_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/sideband/response"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let event = make_authorizable_response_event(200);

        let response = handle_response(&event, &client, AuthErrorMode::Http).await;
        let resp = response.mcp.transformed_gateway_response.unwrap();
        assert_eq!(resp.status_code, 502);
        assert_eq!(resp.body["error"]["code"], -32603);
        assert_eq!(resp.body["id"], 1);
    }

    #[tokio::test]
    async fn handle_response_fails_closed_429_on_rate_limit() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/sideband/response"))
            .respond_with(ResponseTemplate::new(429).set_body_string("rate limited"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let event = make_authorizable_response_event(200);

        let response = handle_response(&event, &client, AuthErrorMode::Http).await;
        let resp = response.mcp.transformed_gateway_response.unwrap();
        assert_eq!(resp.status_code, 429);
    }

    #[tokio::test]
    async fn handle_response_does_not_authorize_deny_short_circuit() {
        use wiremock::MockServer;

        // No mock registered for /sideband/response -- if authorize_response were
        // called, the request would fail with a connection error, not silently pass.
        let mock_server = MockServer::start().await;
        let client = test_client(&mock_server.uri());

        let mut deny_headers = HashMap::new();
        deny_headers.insert("www-authenticate".to_string(), "Bearer".to_string());
        let carrier = helpers::encode_response_headers(&deny_headers);

        let mut req_headers = HashMap::new();
        req_headers.insert(helpers::RESPONSE_HEADERS_CARRIER.to_string(), carrier);
        // Deliberately no x-paz-state header.

        let event = make_response_event(
            Some(req_headers),
            Some(401),
            None,
            Some(
                json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32600, "message": "Unauthorized"}}),
            ),
        );

        let response = handle_response(&event, &client, AuthErrorMode::Http).await;
        let resp = response.mcp.transformed_gateway_response.unwrap();
        assert_eq!(resp.status_code, 401);
        assert_eq!(
            resp.headers.unwrap().get("www-authenticate").unwrap(),
            "Bearer"
        );
    }

    // --- AUTH_ERROR_MODE=jsonrpc conversion (RESPONSE-phase authorized forward) tests ---

    /// Mount a mock P1AZ /sideband/response returning an `OutboundResponseResult`
    /// with the given status and header pairs.
    async fn mock_p1az_outbound_result(
        mock_server: &wiremock::MockServer,
        response_code: &str,
        headers: Vec<(&str, &str)>,
    ) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let sideband_headers: Vec<serde_json::Value> = headers
            .into_iter()
            .map(|(k, v)| serde_json::json!({k: v}))
            .collect();
        let response_status = response_code
            .parse::<u16>()
            .ok()
            .map(helpers::reason_phrase)
            .unwrap_or("");
        let result_body = serde_json::json!({
            "response_code": response_code,
            "response_status": response_status,
            "headers": sideband_headers,
            "body": "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32600,\"message\":\"upstream denial\"}}"
        });

        Mock::given(method("POST"))
            .and(path("/sideband/response"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&result_body))
            .expect(1)
            .mount(mock_server)
            .await;
    }

    #[tokio::test]
    async fn handle_response_converts_backend_401_challenge_in_jsonrpc_mode() {
        use wiremock::MockServer;

        let mock_server = MockServer::start().await;
        let header = "Bearer realm=\"PingOne Authorize\", error=\"invalid_token\", error_description=\"Token expired\"";
        mock_p1az_outbound_result(
            &mock_server,
            "401",
            vec![
                ("www-authenticate", header),
                ("mcp-session-id", "s1"),
                ("content-length", "58"),
            ],
        )
        .await;

        let client = test_client(&mock_server.uri());
        let event = make_authorizable_response_event(401);

        let response = handle_response(&event, &client, AuthErrorMode::JsonRpc).await;
        let resp = response.mcp.transformed_gateway_response.unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.body["error"]["code"], helpers::P1AZ_AUTH_ERROR_CODE);
        assert_eq!(resp.body["error"]["message"], "Token expired");
        let details = &resp.body["error"]["data"][helpers::AUTH_CHALLENGE_DATA_KEY];
        assert_eq!(details["status"], 401);
        assert_eq!(details["www_authenticate"], header);
        assert_eq!(resp.body["id"], 1);

        let headers = resp.headers.unwrap();
        assert_eq!(headers.get("mcp-session-id").unwrap(), "s1");
        assert!(!headers.contains_key("www-authenticate"));
        assert!(!headers.contains_key("content-length"));
    }

    #[tokio::test]
    async fn handle_response_jsonrpc_mode_backend_401_without_challenge_forwarded_verbatim() {
        use wiremock::MockServer;

        let mock_server = MockServer::start().await;
        mock_p1az_outbound_result(&mock_server, "401", vec![("mcp-session-id", "s1")]).await;

        let client = test_client(&mock_server.uri());
        let event = make_authorizable_response_event(401);

        let response = handle_response(&event, &client, AuthErrorMode::JsonRpc).await;
        let resp = response.mcp.transformed_gateway_response.unwrap();
        assert_eq!(
            resp.status_code, 401,
            "4xx without www-authenticate is forwarded verbatim"
        );
        assert_eq!(resp.body["error"]["message"], "upstream denial");
    }

    #[tokio::test]
    async fn handle_response_jsonrpc_mode_backend_5xx_not_converted() {
        use wiremock::MockServer;

        let mock_server = MockServer::start().await;
        mock_p1az_outbound_result(&mock_server, "502", vec![("www-authenticate", "Bearer")]).await;

        let client = test_client(&mock_server.uri());
        let event = make_authorizable_response_event(502);

        let response = handle_response(&event, &client, AuthErrorMode::JsonRpc).await;
        let resp = response.mcp.transformed_gateway_response.unwrap();
        assert_eq!(resp.status_code, 502, "5xx is never converted");
        assert_eq!(resp.body["error"]["message"], "upstream denial");
    }

    #[tokio::test]
    async fn handle_response_jsonrpc_mode_backend_429_not_converted() {
        use wiremock::MockServer;

        let mock_server = MockServer::start().await;
        mock_p1az_outbound_result(&mock_server, "429", vec![("www-authenticate", "Bearer")]).await;

        let client = test_client(&mock_server.uri());
        let event = make_authorizable_response_event(429);

        let response = handle_response(&event, &client, AuthErrorMode::JsonRpc).await;
        let resp = response.mcp.transformed_gateway_response.unwrap();
        assert_eq!(resp.status_code, 429, "429 is never an auth challenge");
        assert_eq!(resp.body["error"]["message"], "upstream denial");
    }

    #[tokio::test]
    async fn handle_response_mode_off_forwards_401_challenge() {
        use wiremock::MockServer;

        let mock_server = MockServer::start().await;
        let header = "Bearer realm=\"PingOne Authorize\"";
        mock_p1az_outbound_result(&mock_server, "401", vec![("www-authenticate", header)]).await;

        let client = test_client(&mock_server.uri());
        let event = make_authorizable_response_event(401);

        // Mode off: the challenge is forwarded on the transport, as today.
        let response = handle_response(&event, &client, AuthErrorMode::Http).await;
        let resp = response.mcp.transformed_gateway_response.unwrap();
        assert_eq!(resp.status_code, 401);
        assert_eq!(
            resp.headers.unwrap().get("www-authenticate").unwrap(),
            header
        );
    }

    #[tokio::test]
    async fn handle_response_jsonrpc_mode_rejects_successful_result_with_403() {
        use wiremock::MockServer;

        // Backend returned 200 (a successful tool result), but response
        // authorization rejects it with a 403 + www-authenticate before the
        // result is delivered to the client.
        let mock_server = MockServer::start().await;
        let header = "Bearer realm=\"PingOne Authorize\", error=\"insufficient_scope\", error_description=\"Missing tool scope\"";
        mock_p1az_outbound_result(
            &mock_server,
            "403",
            vec![("www-authenticate", header), ("mcp-session-id", "s1")],
        )
        .await;

        let client = test_client(&mock_server.uri());
        // Backend status 200: the successful result is discarded on conversion.
        let event = make_authorizable_response_event(200);

        let response = handle_response(&event, &client, AuthErrorMode::JsonRpc).await;
        let resp = response.mcp.transformed_gateway_response.unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.body["error"]["code"], helpers::P1AZ_AUTH_ERROR_CODE);
        assert_eq!(resp.body["error"]["message"], "Missing tool scope");
        let details = &resp.body["error"]["data"][helpers::AUTH_CHALLENGE_DATA_KEY];
        assert_eq!(details["status"], 403);
        assert_eq!(details["error"], "insufficient_scope");
        assert_eq!(details["www_authenticate"], header);
        assert_eq!(resp.body["id"], 1);

        let headers = resp.headers.unwrap();
        assert!(!headers.contains_key("www-authenticate"));
        assert_eq!(headers.get("mcp-session-id").unwrap(), "s1");
    }

    #[tokio::test]
    async fn handle_response_mode_off_rejects_successful_result_with_403() {
        use wiremock::MockServer;

        // Mode off: the same rejection forwards P1AZ's transformed result
        // verbatim -- the successful 200 tool result is still discarded, and
        // the client gets the transport-level 403 + www-authenticate.
        let mock_server = MockServer::start().await;
        let header = "Bearer realm=\"PingOne Authorize\", error=\"insufficient_scope\"";
        mock_p1az_outbound_result(&mock_server, "403", vec![("www-authenticate", header)]).await;

        let client = test_client(&mock_server.uri());
        let event = make_authorizable_response_event(200);

        let response = handle_response(&event, &client, AuthErrorMode::Http).await;
        let resp = response.mcp.transformed_gateway_response.unwrap();
        assert_eq!(resp.status_code, 403);
        assert_eq!(
            resp.headers.unwrap().get("www-authenticate").unwrap(),
            header
        );
    }

    fn make_authorizable_request_headers() -> HashMap<String, String> {
        let mut req_headers = HashMap::new();
        req_headers.insert("Host".to_string(), "example.com".to_string());
        req_headers.insert(
            helpers::REQUEST_STATE_CARRIER.to_string(),
            "test-state".to_string(),
        );
        req_headers
    }

    #[tokio::test]
    async fn authorize_response_passes_through_when_streaming_flag_true() {
        let event = make_response_event_streaming(
            Some(make_authorizable_request_headers()),
            Some(200),
            None,
            Some(json!({"partial": "chunk"})),
            Some(true),
        );

        let client = test_client("http://unused.invalid");
        let response = handle_response(&event, &client, AuthErrorMode::Http).await;
        // Not authorized (no P1AZ call: the client points nowhere), passed on as is.
        assert_passed_through(&response, 200, json!({"partial": "chunk"}));
    }

    #[tokio::test]
    async fn authorize_response_passes_through_when_streaming_flag_absent() {
        // `is_streaming_response` not reported by the Gateway at all -- treated
        // the same as streaming, since we can't be sure this is the complete
        // response.
        let event = make_response_event(
            Some(make_authorizable_request_headers()),
            Some(200),
            None,
            Some(json!({"jsonrpc": "2.0", "id": 1, "result": {}})),
        );

        let client = test_client("http://unused.invalid");
        let response = handle_response(&event, &client, AuthErrorMode::Http).await;
        assert_passed_through(&response, 200, json!({"jsonrpc": "2.0", "id": 1, "result": {}}));
    }

    #[tokio::test]
    async fn authorize_response_passes_through_when_no_status_code() {
        let event = make_response_event_streaming(
            Some(make_authorizable_request_headers()),
            None,
            None,
            Some(json!({"jsonrpc": "2.0", "id": 1, "result": {}})),
            Some(false),
        );

        let client = test_client("http://unused.invalid");
        let response = handle_response(&event, &client, AuthErrorMode::Http).await;
        assert!(response.mcp.transformed_gateway_response.is_none());
    }

    #[tokio::test]
    async fn authorize_response_synthesizes_content_type_when_no_response_headers() {
        use wiremock::matchers::{body_partial_json, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let result_body = serde_json::json!({
            "response_code": "200",
            "response_status": "OK",
            "headers": [{"content-type": "application/json"}],
            "body": "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}"
        });

        // Assert the outbound request's headers array is non-empty (the
        // synthesized content-type), since P1AZ's sideband protocol requires a
        // non-empty `headers` object.
        Mock::given(method("POST"))
            .and(path("/sideband/response"))
            .and(body_partial_json(serde_json::json!({
                "headers": [{"content-type": "application/json"}]
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(&result_body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let client = test_client(&mock_server.uri());
        let event = make_response_event_streaming(
            Some(make_authorizable_request_headers()),
            Some(200),
            None, // No response headers from the Gateway.
            Some(json!({"jsonrpc": "2.0", "id": 1, "result": {}})),
            Some(false),
        );

        let response = handle_response(&event, &client, AuthErrorMode::Http).await;
        let resp = response.mcp.transformed_gateway_response.unwrap();
        assert_eq!(resp.status_code, 200);
    }
}
