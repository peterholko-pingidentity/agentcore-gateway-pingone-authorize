//! End-to-end tests of the CIBA approval flow (this fork's addition), using MCP
//! 2026-07-28 multi round-trip requests.
//!
//! One wiremock server plays PingOne Authorize's sideband API and the CIBA
//! provider; the approval table is in memory. The simulated policy permits a
//! request only when it carries the trusted approval header, and otherwise
//! denies it with the CIBA challenge -- like an `auth-challenge` statement with
//! `acrValues: ["ciba-approval"]` on deletes.

use aws_bedrock_lambda_authorizer::{
    approval_store::{ApprovalStore, MemoryStore},
    ciba::{self, Ciba, RequestState},
    config::{AuthErrorMode, CibaConfig, CibaProvider, Config},
    handlers::bedrock,
    sideband_client::SidebandClient,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use std::time::Instant;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const REFERENCE: &str = "arid-1";
const KEY: &str = "test-state-key-test-state-key-test-state-key";
const CHALLENGE: &str = r#"Bearer error="insufficient_user_authentication", acr_values="ciba-approval""#;
const PROTOCOL_META: &str = "io.modelcontextprotocol/protocolVersion";

fn jwt(claims: Value) -> String {
    let segment = |v: Value| URL_SAFE_NO_PAD.encode(v.to_string());
    format!("{}.{}.sig", segment(json!({"alg": "none"})), segment(claims))
}

/// A 2026-07-28 tools/call; a retry carries `requestState`.
fn body(arguments: Value, request_state: Option<&str>, id: i64) -> Value {
    let mut params = json!({"name": "snowflake___delete_user", "arguments": arguments,
                            "_meta": {PROTOCOL_META: "2026-07-28"}});
    if let Some(state) = request_state {
        params["requestState"] = json!(state);
    }
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": params})
}

fn carol(request_state: Option<&str>, id: i64) -> Value {
    body(json!({"user_name": "carol"}), request_state, id)
}

fn event(body: &Value, sub: &str, extra_headers: &[(&str, &str)]) -> Value {
    let mut headers = json!({
        "Host": "gw.example.com",
        "authorization": format!("Bearer {}", jwt(json!({"sub": sub, "iss": "https://idp.test"}))),
        "mcp-protocol-version": "2026-07-28",
        "content-type": "application/json",
    });
    for (k, v) in extra_headers {
        headers[*k] = json!(v);
    }
    json!({
        "interceptorInputVersion": "1.0",
        "mcp": {
            "gatewayRequest": {"path": "/mcp", "httpMethod": "POST", "headers": headers, "body": body},
            "rawGatewayRequest": {"body": body.to_string()},
        }
    })
}

/// Simulated policy: permit (echoing the request, with a state) when the
/// trusted approval header is present; otherwise deny with `challenge`.
struct Policy {
    challenge: &'static str,
    honour_approval: bool,
}

impl Respond for Policy {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let mut inbound: Value = serde_json::from_slice(&request.body).unwrap();
        let approved = inbound["headers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h.get("x-ciba-approval").and_then(Value::as_str) == Some("approved"));
        if approved && self.honour_approval {
            inbound["state"] = json!("st-1");
        } else {
            inbound["response"] = json!({
                "response_code": "401", "response_status": "Unauthorized", "http_version": "1.1",
                "headers": [{"www-authenticate": self.challenge}],
            });
        }
        ResponseTemplate::new(200).set_body_json(inbound)
    }
}

struct Harness {
    server: MockServer,
    client: SidebandClient,
    ciba: Ciba,
}

impl Harness {
    /// No holding (`hold_seconds` 0): every pending approval answers at once.
    async fn new(provider: CibaProvider) -> Self {
        Self::build(provider, CHALLENGE, true, 0).await
    }

    async fn with_policy(provider: CibaProvider, challenge: &'static str, honour_approval: bool) -> Self {
        Self::build(provider, challenge, honour_approval, 0).await
    }

    async fn holding(provider: CibaProvider, hold_seconds: u64) -> Self {
        Self::build(provider, CHALLENGE, true, hold_seconds).await
    }

    async fn build(provider: CibaProvider, challenge: &'static str, honour_approval: bool, hold_seconds: u64) -> Self {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/sideband/request"))
            .respond_with(Policy { challenge, honour_approval })
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/ciba"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"auth_req_id": REFERENCE, "interval": 1, "expires_in": 180})),
            )
            .mount(&server)
            .await;
        let mut config = CibaConfig::new(
            provider,
            format!("{}/ciba", server.uri()),
            format!("{}/token", server.uri()),
            "ciba-client".into(),
            "ciba-secret".into(),
            "table".into(),
        );
        config.state_key = KEY.into();
        config.hold_seconds = hold_seconds;
        let client = SidebandClient::new(&Config::new(server.uri(), "test-secret".into(), AuthErrorMode::Http));
        let ciba = Ciba::new(config, ApprovalStore::memory(300));
        Harness { server, client, ciba }
    }

    /// The token endpoint answers `status` with `body` from now on.
    async fn token_answers(&self, status: u16, body: Value) {
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .mount(&self.server)
            .await;
    }

    async fn approved_by(&self, sub: &str, arguments: Value) {
        let detail = ciba::authorization_detail(&self.ciba.config, &body(arguments, None, 0));
        let tokens = json!({"access_token": "at", "id_token": jwt(json!({"sub": sub})),
                            "authorization_details": [detail]});
        self.token_answers(200, tokens).await;
    }

    async fn handle(&self, event: Value) -> Value {
        let response =
            bedrock::handle_request_with_ciba(event, &self.client, AuthErrorMode::Http, Some(&self.ciba)).await;
        serde_json::to_value(response).unwrap()
    }

    /// The first call: the policy asks for an approval; returns the requestState.
    async fn start(&self, sub: &str) -> String {
        let response = self.handle(event(&carol(None, 7), sub, &[])).await;
        state_of(&response).to_string()
    }

    async fn requests(&self, to: &str) -> Vec<Value> {
        self.server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.url.path() == to)
            .map(|r| serde_json::from_slice(&r.body).unwrap_or_else(|_| json!(String::from_utf8_lossy(&r.body))))
            .collect()
    }

    fn memory(&self) -> &MemoryStore {
        match &self.ciba.store {
            ApprovalStore::Memory(m) => m,
            _ => unreachable!(),
        }
    }
}

fn short_circuit(response: &Value) -> &Value {
    &response["mcp"]["transformedGatewayResponse"]
}

fn error_of(response: &Value) -> &Value {
    &short_circuit(response)["body"]["error"]
}

fn result_of(response: &Value) -> &Value {
    &short_circuit(response)["body"]["result"]
}

fn state_of(response: &Value) -> &str {
    result_of(response)["requestState"].as_str().expect("an input_required result")
}

fn forwarded(response: &Value) -> &Value {
    &response["mcp"]["transformedGatewayRequest"]
}

fn header_names(inbound: &Value) -> Vec<String> {
    inbound["headers"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|h| h.as_object().unwrap().keys().map(|k| k.to_lowercase()))
        .collect()
}

fn form(text: &Value) -> std::collections::HashMap<String, String> {
    url::form_urlencoded::parse(text.as_str().unwrap().as_bytes()).into_owned().collect()
}

fn reason(response: &Value) -> &str {
    error_of(response)["data"]["reason"].as_str().unwrap_or("")
}

// --- first call: the policy asks for an approval -------------------------------

#[tokio::test]
async fn ciba_challenge_answers_input_required_with_a_sealed_state() {
    let h = Harness::new(CibaProvider::PingFederate).await;
    let response = h.handle(event(&carol(None, 7), "user-123", &[])).await;

    assert_eq!(short_circuit(&response)["statusCode"], 200);
    assert_eq!(short_circuit(&response)["body"]["id"], 7);
    let result = result_of(&response);
    assert_eq!(result["resultType"], "input_required");
    let approval = &result["_meta"][ciba::APPROVAL_META_KEY];
    let code = approval["bindingMessage"].as_str().unwrap();
    assert!(code.starts_with("APR-") && code.len() == 8);
    let expires_in = approval["expiresIn"].as_u64().unwrap();
    assert!((178..=180).contains(&expires_in), "{expires_in}");

    let state = ciba::unseal(state_of(&response), KEY).unwrap();
    let (method_, params_sha256) = ciba::fingerprint(&carol(None, 7));
    assert_eq!(state.reference, REFERENCE);
    assert_eq!(state.sub, "user-123");
    assert_eq!((state.method.as_str(), state.params_sha256.as_str()), (method_.as_str(), params_sha256.as_str()));
    assert_eq!(state.code.as_deref(), Some(code));

    let start = form(&h.requests("/ciba").await[0]);
    assert_eq!(start["login_hint"], "user-123");
    assert_eq!(start["binding_message"], code);
    assert_eq!(start["requested_expiry"], "180");
    let details: Value = serde_json::from_str(&start["authorization_details"]).unwrap();
    assert_eq!(details[0], ciba::authorization_detail(&h.ciba.config, &carol(None, 7)));
    // With no holding there is no poll on the first call.
    assert!(h.requests("/token").await.is_empty());
    assert!(h.memory().writes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn pingone_start_records_the_request_and_sends_no_details() {
    let h = Harness::new(CibaProvider::PingOne).await;
    let response = h.handle(event(&carol(None, 7), "user-123", &[])).await;
    assert_eq!(result_of(&response)["resultType"], "input_required");

    let start = form(&h.requests("/ciba").await[0]);
    assert!(!start.contains_key("authorization_details"));
    let record = h.memory().item(&ciba::request_key(REFERENCE)).unwrap();
    let (method_, params_sha256) = ciba::fingerprint(&carol(None, 7));
    assert_eq!(record["method"], method_);
    assert_eq!(record["params_sha256"], params_sha256);
    assert_eq!(record["subject"], "user-123");
}

#[tokio::test]
async fn client_supplied_approval_headers_are_stripped() {
    let h = Harness::new(CibaProvider::PingFederate).await;
    let response = h
        .handle(event(&carol(None, 7), "user-123", &[("X-Ciba-Approval", "approved"), ("x-ciba-approver", "x")]))
        .await;
    // Without the authorizer's own header the policy asks for an approval.
    assert_eq!(result_of(&response)["resultType"], "input_required");
    let names = header_names(&h.requests("/sideband/request").await[0]);
    assert!(!names.contains(&"x-ciba-approval".to_string()));
    assert!(!names.contains(&"x-ciba-approver".to_string()));
}

#[tokio::test]
async fn other_challenges_reach_the_client_as_upstream() {
    let h = Harness::with_policy(CibaProvider::PingFederate, r#"Bearer error="invalid_token""#, true).await;
    let response = h.handle(event(&carol(None, 7), "user-123", &[])).await;
    assert_eq!(short_circuit(&response)["statusCode"], 401);
    assert!(h.requests("/ciba").await.is_empty());
    // Upstream's deny-header carrier is still produced.
    assert!(forwarded(&response)["headers"]["x-paz-response-headers"].is_string());
}

#[tokio::test]
async fn caller_without_login_hint_claim_is_refused_in_band() {
    let h = Harness::new(CibaProvider::PingFederate).await;
    let mut e = event(&carol(None, 7), "user-123", &[]);
    e["mcp"]["gatewayRequest"]["headers"]["authorization"] = json!("Bearer not-a-jwt");
    let response = h.handle(e).await;
    assert_eq!(short_circuit(&response)["statusCode"], 200);
    assert_eq!(error_of(&response)["code"], -32080);
    assert_eq!(reason(&response), "approval_unavailable");
    assert_eq!(error_of(&response)["message"], ciba::refusal_message("approval_unavailable"));
    assert!(h.requests("/ciba").await.is_empty());
}

// --- holding: waiting for the user inside one invocation ------------------------

#[tokio::test]
async fn approval_during_the_hold_goes_through_in_one_call() {
    let h = Harness::holding(CibaProvider::PingFederate, 3).await;
    h.approved_by("user-123", json!({"user_name": "carol"})).await;
    let started = Instant::now();
    let response = h.handle(event(&carol(None, 7), "user-123", &[])).await;

    // Waited one interval before polling, then permitted and forwarded.
    assert!(started.elapsed().as_millis() >= 900);
    assert_eq!(forwarded(&response)["headers"]["x-paz-state"], "st-1");
    assert!(short_circuit(&response).is_null());
    assert_eq!(h.requests("/token").await.len(), 1);
    assert_eq!(h.requests("/sideband/request").await.len(), 2);
    assert_eq!(h.memory().item(&ciba::spent_key(REFERENCE)).unwrap()["approver"], "user-123");
}

#[tokio::test]
async fn hold_ends_with_input_required_while_pending() {
    let h = Harness::holding(CibaProvider::PingFederate, 3).await;
    h.token_answers(400, json!({"error": "authorization_pending"})).await;
    let started = Instant::now();
    let response = h.handle(event(&carol(None, 7), "user-123", &[])).await;
    let elapsed = started.elapsed().as_millis();
    assert!((1900..3500).contains(&elapsed), "{elapsed} ms");
    assert_eq!(result_of(&response)["resultType"], "input_required");
    assert_eq!(h.requests("/token").await.len(), 2);
}

// --- retries while the approval is pending --------------------------------------

#[tokio::test]
async fn pending_retry_answers_the_same_state_without_asking_the_policy() {
    let h = Harness::new(CibaProvider::PingFederate).await;
    let state = h.start("user-123").await;
    h.token_answers(400, json!({"error": "authorization_pending"})).await;
    let response = h.handle(event(&carol(Some(&state), 8), "user-123", &[])).await;

    assert_eq!(short_circuit(&response)["body"]["id"], 8);
    assert_eq!(result_of(&response)["resultType"], "input_required");
    assert_eq!(state_of(&response), state);
    assert!(result_of(&response)["_meta"][ciba::APPROVAL_META_KEY]["bindingMessage"].is_string());
    assert_eq!(h.requests("/sideband/request").await.len(), 1); // the first call only
    let poll = form(&h.requests("/token").await[0]);
    assert_eq!(poll["grant_type"], "urn:openid:params:grant-type:ciba");
    assert_eq!(poll["auth_req_id"], REFERENCE);
}

#[tokio::test]
async fn declined_expired_and_unknown_approvals_are_refused() {
    for (error, expected) in [
        ("access_denied", "approval_denied"),
        ("expired_token", "approval_expired"),
        ("invalid_grant", "approval_reference_invalid"),
    ] {
        let h = Harness::new(CibaProvider::PingFederate).await;
        let state = h.start("user-123").await;
        h.token_answers(400, json!({"error": error})).await;
        let response = h.handle(event(&carol(Some(&state), 8), "user-123", &[])).await;
        assert_eq!(short_circuit(&response)["statusCode"], 200, "{error}");
        assert_eq!(error_of(&response)["code"], -32080, "{error}");
        assert_eq!(reason(&response), expected, "{error}");
        assert_eq!(h.requests("/sideband/request").await.len(), 1, "{error}");
    }
}

#[tokio::test]
async fn tampered_foreign_and_expired_states_are_refused_without_polling() {
    let h = Harness::new(CibaProvider::PingFederate).await;
    let state = h.start("user-123").await;

    // Altered, forged with another key, or not a string.
    let (payload, _) = state.rsplit_once('.').unwrap();
    let mut forged = ciba::unseal(&state, KEY).unwrap();
    forged.reference = "someone-elses-approval".into();
    for bad in [format!("{payload}.00"), ciba::seal(&forged, "another-key-another-key-another-key"), String::new()] {
        let response = h.handle(event(&carol(Some(&bad), 8), "user-123", &[])).await;
        assert_eq!(reason(&response), "approval_reference_invalid");
    }
    let mut not_a_string = carol(None, 8);
    not_a_string["params"]["requestState"] = json!(42);
    assert_eq!(reason(&h.handle(event(&not_a_string, "user-123", &[])).await), "approval_reference_invalid");

    // Another caller, or other arguments.
    let response = h.handle(event(&carol(Some(&state), 8), "someone-else", &[])).await;
    assert_eq!(reason(&response), "approval_mismatch");
    let erin = body(json!({"user_name": "erin"}), Some(&state), 8);
    assert_eq!(reason(&h.handle(event(&erin, "user-123", &[])).await), "approval_mismatch");

    // Expired.
    let mut old: RequestState = ciba::unseal(&state, KEY).unwrap();
    old.exp = 1;
    let response = h.handle(event(&carol(Some(&ciba::seal(&old, KEY)), 8), "user-123", &[])).await;
    assert_eq!(reason(&response), "approval_expired");

    assert!(h.requests("/token").await.is_empty());
}

// --- the approved retry ------------------------------------------------------------

#[tokio::test]
async fn approved_retry_is_permitted_once_and_marked_spent() {
    let h = Harness::new(CibaProvider::PingFederate).await;
    let state = h.start("user-123").await;
    h.approved_by("user-123", json!({"user_name": "carol"})).await;
    let mut retry = carol(Some(&state), 8);
    retry["params"]["inputResponses"] = json!({});
    let response = h.handle(event(&retry, "user-123", &[])).await;

    // The policy saw the trusted headers and a body without the round-trip fields.
    let inbound = &h.requests("/sideband/request").await[1];
    let names = header_names(inbound);
    assert!(names.contains(&"x-ciba-approval".to_string()));
    assert!(names.contains(&"x-ciba-approver".to_string()));
    let raw = inbound["body"].as_str().unwrap();
    assert!(!raw.contains("requestState") && !raw.contains("inputResponses"));

    // Forwarded without the trusted headers or round-trip fields, _meta intact.
    let request = forwarded(&response);
    let headers = request["headers"].as_object().unwrap();
    assert!(headers.keys().all(|k| !k.to_lowercase().starts_with("x-ciba-")));
    assert_eq!(headers["x-paz-state"], "st-1");
    let params = &request["body"]["params"];
    assert!(params.get("requestState").is_none() && params.get("inputResponses").is_none());
    assert_eq!(params["_meta"][PROTOCOL_META], "2026-07-28");
    assert_eq!(params["arguments"], json!({"user_name": "carol"}));

    let spent = h.memory().item(&ciba::spent_key(REFERENCE)).unwrap();
    assert_eq!(spent["approver"], "user-123");
}

#[tokio::test]
async fn a_used_approval_is_refused() {
    let h = Harness::new(CibaProvider::PingFederate).await;
    let state = h.start("user-123").await;
    h.approved_by("user-123", json!({"user_name": "carol"})).await;
    h.handle(event(&carol(Some(&state), 8), "user-123", &[])).await;
    let response = h.handle(event(&carol(Some(&state), 9), "user-123", &[])).await;
    assert_eq!(reason(&response), "approval_already_used");
    assert_eq!(h.requests("/token").await.len(), 1);
}

#[tokio::test]
async fn gateway_retry_of_the_same_request_goes_through_without_redeeming() {
    let h = Harness::new(CibaProvider::PingFederate).await;
    let state = h.start("user-123").await;
    h.approved_by("user-123", json!({"user_name": "carol"})).await;
    let e = event(&carol(Some(&state), 8), "user-123", &[]);
    h.handle(e.clone()).await;
    let response = h.handle(e).await;
    assert!(forwarded(&response)["headers"]["x-paz-state"].is_string());
    assert_eq!(h.requests("/token").await.len(), 1);
    assert_eq!(h.requests("/sideband/request").await.len(), 3); // first call + two permits
}

#[tokio::test]
async fn losing_a_race_for_the_spent_record_is_refused() {
    // Two retries redeemed the same approval; the other one wrote the spent
    // record first, so our conditional write fails and we refuse.
    let h = Harness::new(CibaProvider::PingFederate).await;
    let spent = ciba::spent_key(REFERENCE);
    let first = h.ciba.spend(REFERENCE, "rival-key", "user-123", &json!(8)).await;
    assert!(first.is_ok());
    let ours = h.ciba.spend(REFERENCE, "our-key", "user-123", &json!(8)).await;
    let refusal = serde_json::to_value(ours.unwrap_err()).unwrap();
    assert_eq!(reason(&refusal), "approval_already_used");
    assert_eq!(h.memory().item(&spent).unwrap()["idempotency_key"], "rival-key");
}

#[tokio::test]
async fn approval_for_other_arguments_is_refused_with_pingfederate() {
    let h = Harness::new(CibaProvider::PingFederate).await;
    let state = h.start("user-123").await;
    h.approved_by("user-123", json!({"user_name": "erin"})).await;
    let response = h.handle(event(&carol(Some(&state), 8), "user-123", &[])).await;
    assert_eq!(reason(&response), "approval_mismatch");
    assert_eq!(h.requests("/sideband/request").await.len(), 1);
    assert!(h.memory().writes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn approval_by_another_user_is_refused() {
    let h = Harness::new(CibaProvider::PingFederate).await;
    let state = h.start("user-123").await;
    h.approved_by("someone-else", json!({"user_name": "carol"})).await;
    let response = h.handle(event(&carol(Some(&state), 8), "user-123", &[])).await;
    assert_eq!(reason(&response), "approval_mismatch");
}

#[tokio::test]
async fn pingone_approved_retry_is_checked_against_the_record() {
    let h = Harness::new(CibaProvider::PingOne).await;
    let state = h.start("user-123").await;
    h.token_answers(200, json!({"access_token": "at", "id_token": jwt(json!({"sub": "user-123"}))}))
        .await;

    // A state the record doesn't match (sealed by us, but for another request)
    // is caught before redeeming.
    let mut other = ciba::unseal(&state, KEY).unwrap();
    let erin = body(json!({"user_name": "erin"}), None, 8);
    other.params_sha256 = ciba::fingerprint(&erin).1;
    let erin = body(json!({"user_name": "erin"}), Some(&ciba::seal(&other, KEY)), 8);
    assert_eq!(reason(&h.handle(event(&erin, "user-123", &[])).await), "approval_mismatch");
    assert!(h.requests("/token").await.is_empty());

    // The right caller and request go through.
    let response = h.handle(event(&carol(Some(&state), 9), "user-123", &[])).await;
    assert!(forwarded(&response)["headers"]["x-paz-state"].is_string());
}

#[tokio::test]
async fn policy_asking_again_after_approval_is_refused() {
    let h = Harness::with_policy(CibaProvider::PingFederate, CHALLENGE, false).await;
    let state = h.start("user-123").await;
    h.approved_by("user-123", json!({"user_name": "carol"})).await;
    let response = h.handle(event(&carol(Some(&state), 8), "user-123", &[])).await;
    assert_eq!(reason(&response), "approval_not_accepted");
    assert_eq!(h.requests("/ciba").await.len(), 1);
    assert!(h.memory().item(&ciba::spent_key(REFERENCE)).is_none());
}

#[tokio::test]
async fn table_errors_fail_closed() {
    let h = Harness::new(CibaProvider::PingFederate).await;
    let state = h.start("user-123").await;
    h.memory().fail.store(true, Ordering::SeqCst);
    let response = h.handle(event(&carol(Some(&state), 8), "user-123", &[])).await;
    assert_eq!(reason(&response), "approval_store_unavailable");
    assert!(h.requests("/token").await.is_empty());
}

#[tokio::test]
async fn provider_errors_fail_closed() {
    let h = Harness::new(CibaProvider::PingFederate).await;
    let state = h.start("user-123").await;
    h.token_answers(500, json!({})).await;
    let response = h.handle(event(&carol(Some(&state), 8), "user-123", &[])).await;
    assert_eq!(reason(&response), "ciba_unavailable");
}

#[tokio::test]
async fn without_ciba_the_challenge_reaches_the_client_as_upstream() {
    let h = Harness::new(CibaProvider::PingFederate).await;
    let response =
        bedrock::handle_request(event(&carol(None, 7), "user-123", &[]), &h.client, AuthErrorMode::Http).await;
    let response = serde_json::to_value(response).unwrap();
    assert_eq!(response["mcp"]["transformedGatewayResponse"]["statusCode"], 401);
    assert!(h.requests("/ciba").await.is_empty());
}
