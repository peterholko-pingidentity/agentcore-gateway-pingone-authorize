//! CIBA approval flow (this fork's addition to the upstream authorizer).
//!
//! A PingOne Authorize policy asks for a human approval by denying a request
//! with an `auth-challenge` statement whose `acrValues` include the configured
//! marker ([`CibaConfig::challenge_acr`]). Instead of passing that challenge to
//! the client, the authorizer uses MCP 2026-07-28 multi round-trip requests:
//!
//! 1. it sends a CIBA request to the provider (PingFederate or PingOne) naming the
//!    caller (`login_hint`) and a short binding message, and -- with PingFederate
//!    -- describing the exact request in `authorization_details`;
//! 2. it waits up to [`CibaConfig::hold_seconds`] for the user, polling the
//!    provider; if the user approves in that time, the request goes on at once;
//! 3. otherwise it answers with an `input_required` result. Its `requestState`
//!    (HMAC-sealed: provider reference, caller, request fingerprint, expiry)
//!    names the approval, and `_meta["com.pingidentity/approval"]` carries the
//!    binding message for clients that show it;
//! 4. the client retries the identical call with that `requestState` (any MCP
//!    2026-07-28 client does this by itself). The authorizer checks the seal,
//!    caller and request, waits again, and once approved sends the request to the
//!    sideband API again with trusted approval headers (stripped from every
//!    client request) so the policy can permit it. It records the approval as
//!    spent in DynamoDB before forwarding, so the approval is used once.
//!
//! The provider holds the approval state (pending, approved, declined, expired);
//! the table holds the spent references and, with PingOne, which request each
//! reference was issued for.

use crate::approval_store::{ApprovalStore, Item};
use crate::config::{CibaConfig, RequestBinding};
use crate::handlers::bedrock::{BedrockEvent, BedrockResponse, McpOutput, TransformedResponse};
use crate::helpers;
use crate::models::DeniedRequestResponse;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

/// `_meta` key of an `input_required` result: what the user is asked to approve
/// (binding message, seconds left), for clients that show it.
pub const APPROVAL_META_KEY: &str = "com.pingidentity/approval";

/// HTTP status of the authorizer's own short-circuit responses: JSON-RPC
/// results and errors travel in-band, as MCP clients expect.
const SHORT_CIRCUIT_STATUS: u16 = 200;

const CIBA_GRANT_TYPE: &str = "urn:openid:params:grant-type:ciba";

type HmacSha256 = Hmac<Sha256>;

/// The CIBA approval flow: provider client, table and configuration.
pub struct Ciba {
    pub config: CibaConfig,
    http: reqwest::Client,
    pub store: ApprovalStore,
}

/// An approval that checked out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    /// `sub` of the user who approved.
    pub approver: String,
    /// The gateway re-invoked the interceptor for a request that was already
    /// approved and permitted: don't redeem or spend again.
    pub already_spent: bool,
}

/// What a sealed `requestState` carries between the rounds of one approval.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RequestState {
    /// The provider's `auth_req_id`.
    #[serde(rename = "ref")]
    pub reference: String,
    /// The caller it was issued to (the `subject_claim`; empty without one).
    pub sub: String,
    /// The request it was issued for ([`fingerprint`]).
    pub method: String,
    pub params_sha256: String,
    /// When the approval expires, in Unix seconds.
    pub exp: u64,
    /// Binding message shown on both devices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Polling interval the provider asked for, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
}

/// The provider's answer about an approval.
#[derive(Debug)]
pub enum PollOutcome {
    Approved(Value),
    Pending,
    SlowDown,
    Denied,
    Expired,
    Invalid,
}

/// What a backchannel authentication request returned.
#[derive(Debug)]
pub struct Started {
    pub auth_req_id: String,
    pub interval: Option<u64>,
    pub expires_in: Option<u64>,
}

impl Ciba {
    /// The flow with the given table (DynamoDB in Lambda, memory in tests).
    pub fn new(config: CibaConfig, store: ApprovalStore) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.http_timeout_secs))
            .build()
            .expect("HTTP client for the CIBA provider");
        Ciba { config, http, store }
    }

    /// The flow backed by the configured DynamoDB table.
    pub fn with_dynamodb(config: CibaConfig) -> Self {
        let store = ApprovalStore::dynamodb(&config);
        Ciba::new(config, store)
    }

    // --- provider calls ----------------------------------------------------

    async fn post_form(&self, url: &str, form: &[(&str, String)]) -> Result<(u16, Value), String> {
        let response = self
            .http
            .post(url)
            .basic_auth(&self.config.client_id, Some(&self.config.client_secret))
            .header("Accept", "application/json")
            .form(form)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        let text = response.text().await.map_err(|e| e.to_string())?;
        Ok((status, serde_json::from_str(&text).unwrap_or(Value::Null)))
    }

    /// Send the backchannel authentication request.
    pub async fn start(
        &self,
        login_hint: &str,
        binding_message: &str,
        authorization_details: Option<&Value>,
    ) -> Result<Started, String> {
        let mut form = vec![
            ("scope", self.config.scope.clone()),
            ("login_hint", login_hint.to_string()),
            ("binding_message", binding_message.to_string()),
            ("requested_expiry", self.config.requested_expiry.to_string()),
        ];
        if let Some(details) = authorization_details {
            form.push(("authorization_details", details.to_string()));
        }
        let (status, body) = self.post_form(&self.config.authorization_endpoint, &form).await?;
        match body.get("auth_req_id").and_then(Value::as_str) {
            Some(auth_req_id) if status == 200 => Ok(Started {
                auth_req_id: auth_req_id.to_string(),
                interval: body.get("interval").and_then(Value::as_u64),
                expires_in: body.get("expires_in").and_then(Value::as_u64),
            }),
            _ => Err(format!(
                "CIBA request returned HTTP {status}: {} {}",
                body.get("error").and_then(Value::as_str).unwrap_or(""),
                body.get("error_description").and_then(Value::as_str).unwrap_or("")
            )),
        }
    }

    /// Ask the provider's token endpoint about an approval. Errors are failures
    /// (bad client credentials, server errors), which callers treat as the
    /// provider being unavailable.
    pub async fn poll(&self, auth_req_id: &str) -> Result<PollOutcome, String> {
        let form = [("grant_type", CIBA_GRANT_TYPE.to_string()), ("auth_req_id", auth_req_id.to_string())];
        let (status, body) = self.post_form(&self.config.token_endpoint, &form).await?;
        if status == 200 && body.get("access_token").is_some() {
            return Ok(PollOutcome::Approved(body));
        }
        let error = body.get("error").and_then(Value::as_str).unwrap_or("");
        if matches!(status, 400 | 401 | 403) {
            match error {
                "authorization_pending" => return Ok(PollOutcome::Pending),
                "slow_down" => return Ok(PollOutcome::SlowDown),
                "access_denied" => return Ok(PollOutcome::Denied),
                "expired_token" => return Ok(PollOutcome::Expired),
                "invalid_grant" => return Ok(PollOutcome::Invalid),
                _ => {}
            }
        }
        Err(format!("CIBA token request returned HTTP {status}: {error}"))
    }

    // --- the flow ----------------------------------------------------------

    /// Whether a sideband DENY is the policy asking for a CIBA approval: a
    /// `www-authenticate` challenge whose `acr_values` include the marker.
    pub fn is_ciba_challenge(&self, deny: &DeniedRequestResponse) -> bool {
        let headers = helpers::sideband_array_to_flat_headers(&deny.headers);
        helpers::find_header(&headers, "www-authenticate").is_some_and(|header| {
            helpers::parse_www_authenticate(header)
                .param("acr_values")
                .is_some_and(|acr| acr.split_whitespace().any(|v| v == self.config.challenge_acr))
        })
    }

    /// Start a CIBA approval for this request. `Err` carries the refusal reason.
    pub async fn start_approval(&self, body: &Value, claims: &Value) -> Result<RequestState, &'static str> {
        let binding = self.config.request_binding();
        let login_hint = claim(claims, &self.config.login_hint_claim);
        let subject = claim(claims, &self.config.subject_claim);
        let problem = if !body.is_object() {
            Some("batched or empty request".to_string())
        } else if login_hint.is_none() {
            Some(format!("caller token has no {} claim", self.config.login_hint_claim))
        } else if binding == RequestBinding::Table && subject.is_none() {
            Some(format!("caller token has no {} claim", self.config.subject_claim))
        } else {
            None
        };
        if let Some(problem) = problem {
            error!(problem = %problem, "Cannot start a CIBA approval");
            return Err("approval_unavailable");
        }

        let message = binding_message(&self.config.binding_message_prefix);
        let details = (binding == RequestBinding::AuthorizationDetails)
            .then(|| json!([authorization_detail(&self.config, body)]));
        let started = self
            .start(login_hint.unwrap(), &message, details.as_ref())
            .await
            .map_err(|e| {
                error!(error = %e, "CIBA request failed");
                "ciba_unavailable"
            })?;

        let (method, params_sha256) = fingerprint(body);
        if binding == RequestBinding::Table {
            let record = [
                ("method", method.as_str()),
                ("params_sha256", params_sha256.as_str()),
                ("subject", subject.unwrap()),
            ];
            if let Err(e) = self.store.put(&request_key(&started.auth_req_id), &record).await {
                error!(error = %e, "Failed to record the request for a CIBA approval");
                return Err("approval_store_unavailable");
            }
        }

        let lifetime = started.expires_in.unwrap_or(self.config.requested_expiry);
        info!(
            reference_sha256 = %sha256_hex(started.auth_req_id.as_bytes()),
            binding_message = %message,
            expires_in = lifetime,
            "Started CIBA approval"
        );
        Ok(RequestState {
            reference: started.auth_req_id,
            sub: subject.unwrap_or("").to_string(),
            method,
            params_sha256,
            exp: now_secs() + lifetime,
            code: Some(message),
            interval: started.interval,
        })
    }

    /// The approval a client's `requestState` names, if this authorizer sealed it
    /// for this caller and this exact request and it hasn't expired. `Err`
    /// carries the refusal reason.
    pub fn open_state(&self, token: &str, body: &Value, claims: &Value) -> Result<RequestState, &'static str> {
        let Some(state) = unseal(token, &self.config.state_key) else {
            warn!("requestState rejected: altered, forged or malformed");
            return Err("approval_reference_invalid");
        };
        let (method, params_sha256) = fingerprint(body);
        let caller = claim(claims, &self.config.subject_claim).unwrap_or("");
        if state.sub != caller || state.method != method || state.params_sha256 != params_sha256 {
            warn!("requestState rejected: issued for a different request or caller");
            return Err("approval_mismatch");
        }
        if state.exp <= now_secs() {
            return Err("approval_expired");
        }
        Ok(state)
    }

    /// Wait for the approval `state` names: up to `hold_seconds`, polling the
    /// provider at its interval (first waiting one interval when the request was
    /// `just_started`). `Err` carries the response to return instead of going on
    /// to the sideband API: a refusal, or `input_required` while still pending.
    pub async fn redeem(
        &self,
        state: &RequestState,
        idempotency_key: &str,
        body: &Value,
        claims: &Value,
        request_id: &Value,
        just_started: bool,
    ) -> Result<Approval, BedrockResponse> {
        if !body.is_object() {
            return Err(refusal(request_id, "approval_reference_invalid"));
        }
        let reference = state.reference.as_str();
        let store_error = |e| {
            error!(error = %e, "Failed to read the CIBA table");
            refusal(request_id, "approval_store_unavailable")
        };

        let spent = self.store.get(&spent_key(reference)).await.map_err(store_error)?;
        if let Some(spent) = spent {
            if spent.get("idempotency_key").map(String::as_str) == Some(idempotency_key) {
                // The gateway re-invoked the interceptor for this same request.
                return Ok(Approval {
                    approver: spent.get("approver").cloned().unwrap_or_default(),
                    already_spent: true,
                });
            }
            return Err(refusal(request_id, "approval_already_used"));
        }

        if binding_is_table(&self.config) {
            // Checked before redeeming, so a mismatched request doesn't use up
            // the approval at the provider.
            let issued_for = self.store.get(&request_key(reference)).await.map_err(store_error)?;
            if !issued_for.is_some_and(|item| matches_request(&item, body, claim(claims, &self.config.subject_claim))) {
                warn!("CIBA approval rejected: issued for a different request or caller");
                return Err(refusal(request_id, "approval_mismatch"));
            }
        }

        let deadline = Instant::now() + Duration::from_secs(self.config.hold_seconds);
        let mut interval = state.interval.unwrap_or(self.config.poll_interval).max(1);
        let mut poll_now = !just_started;
        let outcome = loop {
            if poll_now {
                let outcome = self.poll(reference).await.map_err(|e| {
                    error!(error = %e, "CIBA token request failed");
                    refusal(request_id, "ciba_unavailable")
                })?;
                match outcome {
                    PollOutcome::Pending => {}
                    // CIBA asks clients to add 5 seconds to the interval on slow_down.
                    PollOutcome::SlowDown => interval += 5,
                    other => break other,
                }
            }
            if Instant::now() + Duration::from_secs(interval) > deadline {
                return Err(input_required(request_id, state, &self.config));
            }
            tokio::time::sleep(Duration::from_secs(interval)).await;
            poll_now = true;
        };
        let tokens = match outcome {
            PollOutcome::Approved(tokens) => tokens,
            PollOutcome::Denied => return Err(refusal(request_id, "approval_denied")),
            PollOutcome::Expired => return Err(refusal(request_id, "approval_expired")),
            PollOutcome::Invalid | PollOutcome::Pending | PollOutcome::SlowDown => {
                return Err(refusal(request_id, "approval_reference_invalid"))
            }
        };

        match verify_approval(&self.config, &tokens, claims, body) {
            Ok(approver) => Ok(Approval { approver, already_spent: false }),
            Err(problem) => {
                warn!(problem = problem, "CIBA approval rejected");
                Err(refusal(request_id, "approval_mismatch"))
            }
        }
    }

    /// Record a redeemed reference as spent before the request is forwarded.
    /// The conditional write makes the approval single-use even when two
    /// retries race: only one of them creates the record.
    pub async fn spend(
        &self,
        reference: &str,
        idempotency_key: &str,
        approver: &str,
        request_id: &Value,
    ) -> Result<(), BedrockResponse> {
        let key = spent_key(reference);
        let record = [("idempotency_key", idempotency_key), ("approver", approver)];
        let result = async {
            if self.store.put_if_absent(&key, &record).await? {
                return Ok(true);
            }
            let spent = self.store.get(&key).await?;
            Ok(spent.is_some_and(|item| item.get("idempotency_key").map(String::as_str) == Some(idempotency_key)))
        }
        .await;
        match result {
            Ok(true) => Ok(()),
            Ok(false) => Err(refusal(request_id, "approval_already_used")),
            Err(e) => {
                let e: crate::approval_store::StoreError = e;
                error!(error = %e, "Failed to record the CIBA approval as spent");
                Err(refusal(request_id, "approval_store_unavailable"))
            }
        }
    }
}

fn binding_is_table(config: &CibaConfig) -> bool {
    config.request_binding() == RequestBinding::Table
}

// --- the sealed requestState -------------------------------------------------

fn mac(key: &str, payload: &str) -> HmacSha256 {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(payload.as_bytes());
    mac
}

/// `requestState` for `state`: `<base64url JSON>.<hex HMAC-SHA256>`. Integrity
/// only: the contents (no secrets) are readable, but any change is detected.
pub fn seal(state: &RequestState, key: &str) -> String {
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(state).expect("requestState serializes"));
    let tag = hex::encode(mac(key, &payload).finalize().into_bytes());
    format!("{payload}.{tag}")
}

/// The state inside a token sealed with `key`; `None` when it was altered,
/// forged, or isn't one.
pub fn unseal(token: &str, key: &str) -> Option<RequestState> {
    let (payload, tag) = token.rsplit_once('.')?;
    let tag = hex::decode(tag).ok()?;
    mac(key, payload).verify_slice(&tag).ok()?;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

// --- request helpers ---------------------------------------------------------

/// Hex SHA-256.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// JSON with object keys sorted at every level and no whitespace, so equal
/// values hash equally whatever their key order.
pub fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let fields: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", Value::String(k.clone()), canonical_json(&map[k])))
                .collect();
            format!("{{{}}}", fields.join(","))
        }
        Value::Array(items) => format!("[{}]", items.iter().map(canonical_json).collect::<Vec<_>>().join(",")),
        other => other.to_string(),
    }
}

/// The request's params without `_meta` and the MCP round-trip fields
/// (`requestState`, `inputResponses`): what stays the same across retries.
pub fn request_params(body: &Value) -> Value {
    let mut params = body.get("params").cloned().filter(Value::is_object).unwrap_or_else(|| json!({}));
    if let Some(map) = params.as_object_mut() {
        for key in ["_meta", "requestState", "inputResponses"] {
            map.remove(key);
        }
    }
    params
}

/// What identifies a request for an approval: its method and a hash of its
/// params (for tools/call, the tool name and its arguments).
pub fn fingerprint(body: &Value) -> (String, String) {
    let method = body.get("method").and_then(Value::as_str).unwrap_or("").to_string();
    (method, sha256_hex(canonical_json(&request_params(body)).as_bytes()))
}

/// The `authorization_details` entry that binds an approval to this exact
/// request (PingFederate). `name` and `arguments` are for the provider to
/// describe the request to the user.
pub fn authorization_detail(config: &CibaConfig, body: &Value) -> Value {
    let (method, params_sha256) = fingerprint(body);
    let params = request_params(body);
    let mut detail = json!({
        "type": config.authorization_details_type,
        "method": method,
        "params_sha256": params_sha256,
    });
    for key in ["name", "arguments"] {
        if let Some(value) = params.get(key) {
            detail[key] = value.clone();
        }
    }
    detail
}

fn matches_request(item: &Item, body: &Value, subject: Option<&str>) -> bool {
    let (method, params_sha256) = fingerprint(body);
    item.get("method") == Some(&method)
        && item.get("params_sha256") == Some(&params_sha256)
        && subject.is_some_and(|s| item.get("subject").map(String::as_str) == Some(s))
}

/// Same value when the gateway re-invokes the interceptor for one request; a
/// client retry is a new JSON-RPC request (new `id`), so it gets a new key. The
/// caller's subject is part of it because MCP 2026-07-28 has no session to tell
/// two callers' identical requests apart.
pub fn idempotency_key(event: &BedrockEvent, subject: &str) -> String {
    let headers = event.mcp.gateway_request.as_ref().and_then(|r| r.headers.as_ref());
    let session = headers.and_then(|h| helpers::find_header(h, "mcp-session-id")).unwrap_or("");
    let raw = event
        .mcp
        .raw_gateway_request
        .as_ref()
        .and_then(|r| r.body.clone())
        .or_else(|| event.mcp.gateway_request.as_ref().and_then(|r| r.body.as_ref()).map(canonical_json))
        .unwrap_or_default();
    sha256_hex(format!("{subject}\n{session}\n{raw}").as_bytes())
}

/// Remove the MCP round-trip fields a client retry carries (`params.requestState`,
/// `params.inputResponses`) and return the `requestState`.
///
/// `None` when the request carries none; `Some("")` when it isn't a string. The
/// raw body is re-serialized without them, so neither PingOne Authorize nor the
/// target sees them.
///
/// `params._meta` is left alone. On 2026-07-28 the Gateway checks the forwarded
/// body's envelope (`_meta["io.modelcontextprotocol/…"]`) against the client's
/// `MCP-Protocol-Version` header and refuses the call without it -- although it
/// then forwards the same envelope to targets it talks an older version to (a
/// Gateway bug: a target that knows 2026-07-28, like Snowflake's, refuses that).
pub fn strip_request_state(event: &mut BedrockEvent) -> Option<String> {
    let request = event.mcp.gateway_request.as_mut()?;
    let params = request.body.as_mut()?.get_mut("params")?.as_object_mut()?;
    let state = params.remove("requestState");
    let responses = params.remove("inputResponses");
    if state.is_none() && responses.is_none() {
        return None;
    }
    let body = request.body.clone().unwrap_or(Value::Null);
    if let Some(raw) = event.mcp.raw_gateway_request.as_mut() {
        raw.body = Some(body.to_string());
    }
    state.map(|s| s.as_str().unwrap_or("").to_string())
}

/// Remove the trusted approval headers from a request: only the authorizer may set them.
pub fn strip_trusted_headers(headers: &mut HashMap<String, String>, config: &CibaConfig) {
    for name in [&config.approval_header, &config.approver_header] {
        while helpers::remove_header(headers, name).is_some() {}
    }
}

/// Mark an approved request for the policy.
pub fn add_trusted_headers(headers: &mut HashMap<String, String>, config: &CibaConfig, approver: &str) {
    headers.insert(config.approval_header.clone(), "approved".to_string());
    headers.insert(config.approver_header.clone(), approver.to_string());
}

/// Claims of the caller's bearer token (validated by the gateway and by
/// PingOne; read here without checking the signature). `{}` without a token.
pub fn caller_claims(event: &BedrockEvent) -> Value {
    let token = event
        .mcp
        .gateway_request
        .as_ref()
        .and_then(|r| r.headers.as_ref())
        .and_then(|h| helpers::find_header(h, "authorization"))
        .map(|v| v.trim_start_matches("Bearer ").trim_start_matches("bearer ").trim());
    jwt_claims(token)
}

/// Payload of a JWT without checking its signature; `{}` when it isn't one.
pub fn jwt_claims(token: Option<&str>) -> Value {
    token
        .and_then(|t| t.split('.').nth(1))
        .and_then(|payload| URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok())
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}))
}

/// A non-empty string claim.
pub fn claim<'a>(claims: &'a Value, name: &str) -> Option<&'a str> {
    claims.get(name).and_then(Value::as_str).filter(|s| !s.is_empty())
}

/// Who approved, or why the approval doesn't cover this caller and request.
///
/// The token response comes straight from the provider's token endpoint over
/// TLS to this authenticated client, so its ID token is read without checking
/// the signature. With table binding the request was already compared before
/// redeeming; only the approver is checked here.
pub fn verify_approval(
    config: &CibaConfig,
    tokens: &Value,
    caller_claims: &Value,
    body: &Value,
) -> Result<String, &'static str> {
    let id_token = jwt_claims(tokens.get("id_token").and_then(Value::as_str));
    let access_token = jwt_claims(tokens.get("access_token").and_then(Value::as_str));
    let approver = claim(&id_token, "sub").or_else(|| claim(&access_token, "sub"));
    let caller = claim(caller_claims, &config.subject_claim);
    let approver = match (approver, caller) {
        (Some(a), Some(c)) if a == c => a.to_string(),
        _ => return Err("approved_by_different_user"),
    };

    if config.request_binding() == RequestBinding::AuthorizationDetails {
        let granted = tokens
            .get("authorization_details")
            .or_else(|| access_token.get("authorization_details"))
            .and_then(Value::as_array);
        let (method, params_sha256) = fingerprint(body);
        let matches = granted.is_some_and(|details| {
            details.iter().any(|d| {
                d.get("type").and_then(Value::as_str) == Some(config.authorization_details_type.as_str())
                    && d.get("method").and_then(Value::as_str) == Some(method.as_str())
                    && d.get("params_sha256").and_then(Value::as_str) == Some(params_sha256.as_str())
            })
        });
        if !matches {
            return Err("approved_for_different_request");
        }
    }
    Ok(approver)
}

/// Table key recording that a reference was redeemed.
pub fn spent_key(reference: &str) -> String {
    format!("spent#{}", sha256_hex(reference.as_bytes()))
}

/// Table key of the request a reference was issued for (table binding).
pub fn request_key(reference: &str) -> String {
    format!("request#{}", sha256_hex(reference.as_bytes()))
}

/// `<prefix>-NNNN`, shown on both devices so the user can match them.
pub fn binding_message(prefix: &str) -> String {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.subsec_nanos());
    format!("{prefix}-{:04}", nanos % 10_000)
}

// --- responses ---------------------------------------------------------------

fn short_circuit(body: Value) -> BedrockResponse {
    BedrockResponse {
        interceptor_output_version: "1.0".to_string(),
        mcp: McpOutput {
            transformed_gateway_request: None,
            transformed_gateway_response: Some(TransformedResponse {
                status_code: SHORT_CIRCUIT_STATUS,
                headers: None,
                body,
            }),
        },
    }
}

/// Plain words for a refusal reason. Most MCP clients show the model only
/// `error.message`, so it has to say what happened.
pub fn refusal_message(reason: &str) -> &'static str {
    match reason {
        "approval_denied" => "The approval request was declined, so the call was not made.",
        "approval_expired" => "The approval request expired before anyone approved it, so the call was not made.",
        "approval_already_used" => "That approval was already used for another call.",
        "approval_mismatch" => "The approval doesn't match this call (another user, or different details).",
        "approval_reference_invalid" => "The approval reference wasn't recognized, so the call was refused.",
        "approval_not_accepted" => "The policy still asked for an approval after one was given, so the call was refused.",
        "approval_unavailable" => "An approval can't be requested for this call.",
        "ciba_unavailable" => "The approval service couldn't be reached, so the call was refused.",
        "approval_store_unavailable" => "The approval records couldn't be read, so the call was refused.",
        _ => "Request denied",
    }
}

/// Refuse the request: JSON-RPC `-32080` (upstream's generic authorization
/// error) with `data.reason` and a plain-words message.
pub fn refusal(request_id: &Value, reason: &str) -> BedrockResponse {
    info!(reason = reason, "CIBA approval: refused");
    short_circuit(json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": helpers::P1AZ_GENERIC_ERROR_CODE,
            "message": refusal_message(reason),
            "data": {"reason": reason},
        },
    }))
}

/// The MCP 2026-07-28 `input_required` result: retry this call with
/// `requestState`. Its `_meta` tells clients that show it what to approve.
pub fn input_required(request_id: &Value, state: &RequestState, config: &CibaConfig) -> BedrockResponse {
    let mut approval = json!({"expiresIn": state.exp.saturating_sub(now_secs())});
    if let Some(code) = &state.code {
        approval["bindingMessage"] = json!(code);
    }
    let mut meta = Map::new();
    meta.insert(APPROVAL_META_KEY.to_string(), approval);
    info!(binding_message = ?state.code, "CIBA approval pending: input_required");
    short_circuit(json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "resultType": "input_required",
            "requestState": seal(state, &config.state_key),
            "_meta": meta,
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CibaProvider;

    const KEY: &str = "0123456789abcdef0123456789abcdef";

    fn config(provider: CibaProvider) -> CibaConfig {
        CibaConfig::new(
            provider,
            "https://idp.test/ciba".into(),
            "https://idp.test/token".into(),
            "client".into(),
            "secret".into(),
            "table".into(),
        )
    }

    fn body(arguments: Value) -> Value {
        json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
               "params": {"name": "snowflake___delete_user", "arguments": arguments,
                          "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}}})
    }

    fn state() -> RequestState {
        RequestState {
            reference: "arid-1".into(),
            sub: "u1".into(),
            method: "tools/call".into(),
            params_sha256: "ab".repeat(32),
            exp: 1_900_000_000,
            code: Some("APR-0042".into()),
            interval: Some(5),
        }
    }

    #[test]
    fn canonical_json_sorts_keys_at_every_level() {
        let a = json!({"b": 1, "a": {"d": [1, {"y": 2, "x": 1}], "c": "s"}});
        assert_eq!(canonical_json(&a), r#"{"a":{"c":"s","d":[1,{"x":1,"y":2}]},"b":1}"#);
    }

    #[test]
    fn fingerprint_ignores_meta_round_trip_fields_and_key_order_but_not_arguments() {
        let a = body(json!({"user_name": "carol", "title": "CFO"}));
        let b = json!({"method": "tools/call", "params": {"arguments": {"title": "CFO", "user_name": "carol"},
                       "name": "snowflake___delete_user", "requestState": "x.y", "inputResponses": {}}});
        assert_eq!(fingerprint(&a), fingerprint(&b));
        assert_ne!(fingerprint(&a), fingerprint(&body(json!({"user_name": "erin"}))));
    }

    #[test]
    fn sealed_state_round_trips_and_detects_changes() {
        let token = seal(&state(), KEY);
        assert_eq!(unseal(&token, KEY), Some(state()));
        assert_eq!(unseal(&token, "another-key-another-key-another-k"), None);

        let (payload, tag) = token.rsplit_once('.').unwrap();
        let mut forged = state();
        forged.sub = "attacker".into();
        let forged_payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&forged).unwrap());
        assert_eq!(unseal(&format!("{forged_payload}.{tag}"), KEY), None);
        assert_eq!(unseal(&format!("{payload}.00"), KEY), None);
        assert_eq!(unseal("not-a-token", KEY), None);
    }

    #[test]
    fn strip_request_state_removes_round_trip_fields_but_keeps_meta() {
        let mut b = body(json!({"user_name": "carol"}));
        b["params"]["requestState"] = json!("tok");
        b["params"]["inputResponses"] = json!({});
        let mut event: BedrockEvent = serde_json::from_value(json!({
            "interceptorInputVersion": "1.0",
            "mcp": {"gatewayRequest": {"path": "/mcp", "httpMethod": "POST", "body": b},
                    "rawGatewayRequest": {"body": b.to_string()}}
        }))
        .unwrap();
        assert_eq!(strip_request_state(&mut event), Some("tok".to_string()));
        let params = &event.mcp.gateway_request.as_ref().unwrap().body.as_ref().unwrap()["params"];
        assert!(params.get("requestState").is_none() && params.get("inputResponses").is_none());
        assert_eq!(params["_meta"]["io.modelcontextprotocol/protocolVersion"], "2026-07-28");
        let raw = event.mcp.raw_gateway_request.as_ref().unwrap().body.as_ref().unwrap();
        assert!(!raw.contains("requestState") && raw.contains("protocolVersion"));
        assert_eq!(strip_request_state(&mut event), None);
    }

    #[test]
    fn authorization_detail_carries_fingerprint_and_display_fields() {
        let detail = authorization_detail(&config(CibaProvider::PingFederate), &body(json!({"user_name": "carol"})));
        assert_eq!(detail["type"], "mcp_request");
        assert_eq!(detail["method"], "tools/call");
        assert_eq!(detail["name"], "snowflake___delete_user");
        assert_eq!(detail["arguments"], json!({"user_name": "carol"}));
        assert_eq!(detail["params_sha256"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn binding_message_fits_both_providers() {
        let message = binding_message("APR");
        assert_eq!(message.len(), 8);
        assert!(message.starts_with("APR-"));
    }

    #[test]
    fn jwt_claims_reads_the_payload_or_returns_empty() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"u1"}"#);
        assert_eq!(jwt_claims(Some(&format!("h.{payload}.s")))["sub"], "u1");
        assert_eq!(jwt_claims(Some("not-a-jwt")), json!({}));
        assert_eq!(jwt_claims(None), json!({}));
    }

    #[test]
    fn verify_approval_checks_approver_and_details() {
        let cfg = config(CibaProvider::PingFederate);
        let b = body(json!({"user_name": "carol"}));
        let id_token = format!("h.{}.s", URL_SAFE_NO_PAD.encode(br#"{"sub":"u1"}"#));
        let tokens = json!({"access_token": "at", "id_token": id_token,
                            "authorization_details": [authorization_detail(&cfg, &b)]});
        assert_eq!(verify_approval(&cfg, &tokens, &json!({"sub": "u1"}), &b), Ok("u1".to_string()));
        assert_eq!(
            verify_approval(&cfg, &tokens, &json!({"sub": "u2"}), &b),
            Err("approved_by_different_user")
        );
        assert_eq!(
            verify_approval(&cfg, &tokens, &json!({"sub": "u1"}), &body(json!({"user_name": "erin"}))),
            Err("approved_for_different_request")
        );
        let pingone = config(CibaProvider::PingOne);
        let no_details = json!({"access_token": "at", "id_token": tokens["id_token"]});
        assert_eq!(verify_approval(&pingone, &no_details, &json!({"sub": "u1"}), &b), Ok("u1".to_string()));
    }

    #[test]
    fn refusals_are_in_band_with_plain_words() {
        let response = serde_json::to_value(refusal(&json!(3), "approval_denied")).unwrap();
        let out = &response["mcp"]["transformedGatewayResponse"];
        assert_eq!(out["statusCode"], 200);
        assert_eq!(out["body"]["error"]["code"], -32080);
        assert_eq!(out["body"]["error"]["data"]["reason"], "approval_denied");
        assert!(out["body"]["error"]["message"].as_str().unwrap().contains("declined"));
    }

    #[test]
    fn ciba_challenge_is_recognized_by_acr() {
        let ciba = Ciba::new(config(CibaProvider::PingOne), ApprovalStore::memory(300));
        let deny = |header: &str| DeniedRequestResponse {
            response_code: "401".into(),
            response_status: "Unauthorized".into(),
            http_version: "1.1".into(),
            headers: vec![HashMap::from([("www-authenticate".to_string(), header.to_string())])],
            body: None,
        };
        assert!(ciba.is_ciba_challenge(&deny(
            r#"Bearer error="insufficient_user_authentication", acr_values="ciba-approval""#
        )));
        assert!(!ciba.is_ciba_challenge(&deny(r#"Bearer error="insufficient_user_authentication", acr_values="mfa""#)));
        assert!(!ciba.is_ciba_challenge(&deny(r#"Bearer error="invalid_token""#)));
    }
}
