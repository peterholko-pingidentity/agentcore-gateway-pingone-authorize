use aws_bedrock_lambda_authorizer::{
    config::{AuthErrorMode, Config},
    handlers::bedrock::{self, BedrockEvent},
    sideband_client::SidebandClient,
};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

fn load_bedrock_event(fixture: &str) -> BedrockEvent {
    serde_json::from_str(fixture).expect("Failed to parse Bedrock event fixture")
}

/// A Config for the mock server with the default auth-error mode (the
/// mode-off regression baseline for every existing flow).
fn test_config(service_url: String) -> Config {
    Config::new(service_url, "test-secret".to_string(), AuthErrorMode::Http)
}

fn test_config_with_secret(service_url: String, secret_header_value: &str) -> Config {
    Config::new(
        service_url,
        secret_header_value.to_string(),
        AuthErrorMode::Http,
    )
}

// ---------------------------------------------------------------------------
// Integration Tests
// ---------------------------------------------------------------------------

/// Full PERMIT flow: Bedrock event -> sideband request -> P1AZ PERMIT -> transformedGatewayRequest
#[tokio::test]
async fn full_permit_flow() {
    let mock_server = MockServer::start().await;

    let permit_response: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/sideband_response_permit.json")).unwrap();

    Mock::given(method("POST"))
        .and(path("/sideband/request"))
        .and(header("Client-Token", "test-secret"))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&permit_response))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = test_config(mock_server.uri());
    let client = SidebandClient::new(&config);

    let event = load_bedrock_event(include_str!("fixtures/bedrock_request_tools_call.json"));
    let inbound = bedrock::build_inbound_request(&event).unwrap();
    let sideband_result = client.send_inbound_request(&inbound).await;

    assert!(sideband_result.is_ok());
    let result = sideband_result.unwrap();
    assert!(
        result.response.is_none(),
        "Expected PERMIT (no response field)"
    );

    let response = bedrock::build_bedrock_response(&event, Ok(result));

    assert_eq!(response.interceptor_output_version, "1.0");
    assert!(
        response.mcp.transformed_gateway_request.is_some(),
        "Expected transformedGatewayRequest for PERMIT"
    );
    assert!(
        response.mcp.transformed_gateway_response.is_none(),
        "Expected no transformedGatewayResponse for PERMIT"
    );

    let req = response.mcp.transformed_gateway_request.unwrap();
    assert!(req.body.is_object(), "Body should be a JSON object");
    assert_eq!(req.body["id"], 3);
}

/// Full PERMIT flow with modified headers/body from P1AZ policies.
#[tokio::test]
async fn full_permit_modified_flow() {
    let mock_server = MockServer::start().await;

    let permit_modified: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/sideband_response_permit_modified.json"
    ))
    .unwrap();

    Mock::given(method("POST"))
        .and(path("/sideband/request"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&permit_modified))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = test_config(mock_server.uri());
    let client = SidebandClient::new(&config);

    let event = load_bedrock_event(include_str!("fixtures/bedrock_request_tools_call.json"));
    let inbound = bedrock::build_inbound_request(&event).unwrap();
    let result = client.send_inbound_request(&inbound).await.unwrap();

    let response = bedrock::build_bedrock_response(&event, Ok(result));
    let req = response.mcp.transformed_gateway_request.unwrap();

    // Verify modified headers are forwarded
    let headers = req.headers.unwrap();
    assert_eq!(
        headers.get("authorization").unwrap(),
        "Bearer new-modified-token-from-p1az"
    );
    assert_eq!(
        headers.get("x-custom-enrichment").unwrap(),
        "policy-value-123"
    );

    // Verify modified body is forwarded
    assert_eq!(
        req.body["params"]["arguments"]["note"],
        "modified by policy"
    );
}

/// Full DENY flow (403): Bedrock event -> sideband request -> P1AZ DENY -> transformedGatewayResponse
#[tokio::test]
async fn full_deny_403_flow() {
    let mock_server = MockServer::start().await;

    let deny_response: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/sideband_response_deny_403.json")).unwrap();

    Mock::given(method("POST"))
        .and(path("/sideband/request"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&deny_response))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = test_config(mock_server.uri());
    let client = SidebandClient::new(&config);

    let event = load_bedrock_event(include_str!("fixtures/bedrock_request_tools_call.json"));
    let inbound = bedrock::build_inbound_request(&event).unwrap();
    let result = client.send_inbound_request(&inbound).await.unwrap();

    assert!(
        result.response.is_some(),
        "Expected DENY (has response field)"
    );

    let response = bedrock::build_bedrock_response(&event, Ok(result));

    // This fixture's deny response carries headers (content-type, content-length,
    // date), so a carrier transformedGatewayRequest is emitted alongside the
    // short-circuiting transformedGatewayResponse -- see
    // deny_401_stashes_response_headers_carrier for the header round-trip itself.
    assert!(
        response.mcp.transformed_gateway_request.is_some(),
        "Expected a carrier transformedGatewayRequest since the deny response has headers"
    );
    assert!(
        response.mcp.transformed_gateway_response.is_some(),
        "Expected transformedGatewayResponse for DENY"
    );

    let resp = response.mcp.transformed_gateway_response.unwrap();
    assert_eq!(resp.status_code, 403);
    assert_eq!(resp.body["error"]["code"], -32080);
    assert_eq!(resp.body["id"], 3);
    assert!(
        resp.headers.is_none(),
        "REQUEST-phase transformedGatewayResponse must not carry headers"
    );
}

/// Full DENY flow (401): unauthorized response
#[tokio::test]
async fn full_deny_401_flow() {
    let mock_server = MockServer::start().await;

    let deny_response: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/sideband_response_deny_401.json")).unwrap();

    Mock::given(method("POST"))
        .and(path("/sideband/request"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&deny_response))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = test_config(mock_server.uri());
    let client = SidebandClient::new(&config);

    let event = load_bedrock_event(include_str!("fixtures/bedrock_request_tools_call.json"));
    let inbound = bedrock::build_inbound_request(&event).unwrap();
    let result = client.send_inbound_request(&inbound).await.unwrap();

    let response = bedrock::build_bedrock_response(&event, Ok(result));
    let resp = response.mcp.transformed_gateway_response.unwrap();
    assert_eq!(resp.status_code, 401);
    assert_eq!(
        resp.body["error"]["message"],
        "Service provider error HTTP 401 Unauthorized"
    );
}

/// DENY with JSON-RPC body from P1AZ: passes through as-is
#[tokio::test]
async fn full_deny_jsonrpc_passthrough() {
    let mock_server = MockServer::start().await;

    let deny_response: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/sideband_response_deny_jsonrpc.json")).unwrap();

    Mock::given(method("POST"))
        .and(path("/sideband/request"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&deny_response))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = test_config(mock_server.uri());
    let client = SidebandClient::new(&config);

    let event = load_bedrock_event(include_str!("fixtures/bedrock_request_tools_call.json"));
    let inbound = bedrock::build_inbound_request(&event).unwrap();
    let result = client.send_inbound_request(&inbound).await.unwrap();

    let response = bedrock::build_bedrock_response(&event, Ok(result));
    let resp = response.mcp.transformed_gateway_response.unwrap();
    assert_eq!(resp.status_code, 403);
    // Should pass through the JSON-RPC error as-is (not wrapped)
    assert_eq!(resp.body["jsonrpc"], "2.0");
    assert_eq!(
        resp.body["error"]["message"],
        "Policy denied: insufficient permissions for tools/call"
    );
}

/// P1AZ returns HTTP 500: produces 502 error response
#[tokio::test]
async fn p1az_error_500_flow() {
    let mock_server = MockServer::start().await;

    let error_body = include_str!("fixtures/sideband_error_500.json");

    Mock::given(method("POST"))
        .and(path("/sideband/request"))
        .respond_with(ResponseTemplate::new(500).set_body_string(error_body))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = test_config(mock_server.uri());
    let client = SidebandClient::new(&config);

    let event = load_bedrock_event(include_str!("fixtures/bedrock_request_tools_call.json"));
    let inbound = bedrock::build_inbound_request(&event).unwrap();
    let sideband_result = client.send_inbound_request(&inbound).await;

    assert!(sideband_result.is_err());

    let response = bedrock::build_bedrock_response(&event, sideband_result);
    let resp = response.mcp.transformed_gateway_response.unwrap();
    assert_eq!(resp.status_code, 502);
    assert_eq!(resp.body["error"]["code"], -32603);
    assert_eq!(resp.body["id"], 3);
}

/// P1AZ returns HTTP 429: produces 429 error response
#[tokio::test]
async fn p1az_rate_limit_429_flow() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/sideband/request"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_string(
                    r#"{"id":"rl-001","code":"RATE_LIMITED","message":"Too many requests"}"#,
                )
                .insert_header("Retry-After", "5"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = test_config(mock_server.uri());
    let client = SidebandClient::new(&config);

    let event = load_bedrock_event(include_str!("fixtures/bedrock_request_tools_call.json"));
    let inbound = bedrock::build_inbound_request(&event).unwrap();
    let sideband_result = client.send_inbound_request(&inbound).await;

    assert!(sideband_result.is_err());

    let response = bedrock::build_bedrock_response(&event, sideband_result);
    let resp = response.mcp.transformed_gateway_response.unwrap();
    assert_eq!(resp.status_code, 429);
    assert_eq!(resp.body["error"]["code"], -32603);
    assert!(resp.body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("Rate limited"));
}

/// Verify the sideband request format sent to P1AZ
#[tokio::test]
async fn verify_sideband_request_format() {
    let mock_server = MockServer::start().await;

    let permit_response: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/sideband_response_permit.json")).unwrap();

    Mock::given(method("POST"))
        .and(path("/sideband/request"))
        .and(header("Client-Token", "my-secret"))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&permit_response))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = test_config_with_secret(mock_server.uri(), "my-secret");
    let client = SidebandClient::new(&config);

    let event = load_bedrock_event(include_str!("fixtures/bedrock_request_tools_call.json"));
    let inbound = bedrock::build_inbound_request(&event).unwrap();

    // Verify the InboundRequest fields
    assert_eq!(inbound.method, "POST");
    assert!(inbound.url.starts_with("https://"));
    assert!(inbound.url.ends_with("/mcp"));
    assert_eq!(inbound.http_version, "1.1");
    assert_eq!(inbound.source_ip, "0.0.0.0");
    assert_eq!(inbound.source_port, 1);
    assert!(!inbound.headers.is_empty());
    assert!(inbound.body.is_some());

    // Send to mock and verify it accepted the request
    let result = client.send_inbound_request(&inbound).await;
    assert!(result.is_ok());
}

/// Verify User-Agent header is sent to P1AZ
#[tokio::test]
async fn verify_user_agent_header() {
    let mock_server = MockServer::start().await;

    let permit_response: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/sideband_response_permit.json")).unwrap();

    Mock::given(method("POST"))
        .and(path("/sideband/request"))
        .and(header(
            "User-Agent",
            format!(
                "aws-bedrock-gateway-authorizer/{}",
                env!("CARGO_PKG_VERSION")
            )
            .as_str(),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(&permit_response))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = test_config(mock_server.uri());
    let client = SidebandClient::new(&config);

    let event = load_bedrock_event(include_str!("fixtures/bedrock_request_tools_call.json"));
    let inbound = bedrock::build_inbound_request(&event).unwrap();
    let result = client.send_inbound_request(&inbound).await;
    assert!(result.is_ok());
}

/// REQUEST-phase DENY (401) stashes the deny headers in a carrier request so the
/// RESPONSE phase can restore them. Verifies the carrier round-trips.
#[tokio::test]
async fn deny_401_stashes_response_headers_carrier() {
    use aws_bedrock_lambda_authorizer::helpers;

    let mock_server = MockServer::start().await;

    let deny_response: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/sideband_response_deny_401.json")).unwrap();

    Mock::given(method("POST"))
        .and(path("/sideband/request"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&deny_response))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = test_config(mock_server.uri());
    let client = SidebandClient::new(&config);

    let event = load_bedrock_event(include_str!("fixtures/bedrock_request_tools_call.json"));
    let inbound = bedrock::build_inbound_request(&event).unwrap();
    let result = client.send_inbound_request(&inbound).await.unwrap();

    let response = bedrock::build_bedrock_response(&event, Ok(result));

    // Still a DENY short-circuit.
    let resp = response.mcp.transformed_gateway_response.unwrap();
    assert_eq!(resp.status_code, 401);

    // Carrier request present with the deny headers encoded.
    let req = response.mcp.transformed_gateway_request.unwrap();
    let headers = req.headers.unwrap();
    let carrier = headers.get(helpers::RESPONSE_HEADERS_CARRIER).unwrap();
    let decoded = helpers::decode_response_headers(carrier).unwrap();
    assert_eq!(
        decoded.get("www-authenticate").unwrap(),
        "Bearer realm=\"PingOne Authorize\""
    );
}

/// RESPONSE-phase event carrying the response-headers carrier restores those
/// headers onto the outgoing response. This path makes no P1AZ call -- assert
/// the mock isn't hit.
#[tokio::test]
async fn response_phase_restores_headers() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let event = load_bedrock_event(include_str!("fixtures/bedrock_response_event.json"));
    assert!(
        event.mcp.gateway_response.is_some(),
        "Fixture must be a RESPONSE-phase event"
    );

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/sideband/response"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    let config = test_config(mock_server.uri());
    let client = SidebandClient::new(&config);

    let response = bedrock::handle_response(&event, &client, AuthErrorMode::Http).await;
    let resp = response.mcp.transformed_gateway_response.unwrap();

    // Status and body preserved from gatewayResponse.
    assert_eq!(resp.status_code, 401);
    assert_eq!(resp.body["error"]["message"], "Unauthorized");

    // Deny header restored; existing response header preserved; carrier not leaked.
    let headers = resp.headers.unwrap();
    assert_eq!(
        headers.get("www-authenticate").unwrap(),
        "Bearer realm=\"PingOne Authorize\""
    );
    assert_eq!(headers.get("mcp-session-id").unwrap(), "session-abc-123");
    assert!(!headers.contains_key("x-paz-response-headers"));
}

/// Full RESPONSE-phase authorization: a PERMIT-phase response carrying
/// `x-paz-state` is sent to `/sideband/response` and the plain (untransformed)
/// result is forwarded to the client.
#[tokio::test]
async fn response_phase_authorizes_permit_passthrough() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    let result: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/sideband_outbound_response_plain.json"
    ))
    .unwrap();

    Mock::given(method("POST"))
        .and(path("/sideband/response"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&result))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = test_config(mock_server.uri());
    let client = SidebandClient::new(&config);

    let event = load_bedrock_event(include_str!("fixtures/bedrock_response_permit_event.json"));
    let response = bedrock::handle_response(&event, &client, AuthErrorMode::Http).await;

    let resp = response.mcp.transformed_gateway_response.unwrap();
    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.body["result"]["content"][0]["text"], "this is a note");
    let headers = resp.headers.unwrap();
    assert_eq!(headers.get("mcp-session-id").unwrap(), "session-abc-123");
}

/// Full RESPONSE-phase authorization where P1AZ transforms the response: the
/// transformed status/headers/body are forwarded verbatim.
#[tokio::test]
async fn response_phase_authorizes_and_forwards_transformed_response() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    let result: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/sideband_outbound_response_transformed.json"
    ))
    .unwrap();

    Mock::given(method("POST"))
        .and(path("/sideband/response"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&result))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = test_config(mock_server.uri());
    let client = SidebandClient::new(&config);

    let event = load_bedrock_event(include_str!("fixtures/bedrock_response_permit_event.json"));
    let response = bedrock::handle_response(&event, &client, AuthErrorMode::Http).await;

    let resp = response.mcp.transformed_gateway_response.unwrap();
    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.body["result"]["content"][0]["text"], "[REDACTED]");
    let headers = resp.headers.unwrap();
    assert_eq!(headers.get("x-paz-transformed").unwrap(), "true");
}

/// P1AZ returns HTTP 500 on `/sideband/response`: the RESPONSE phase fails closed
/// with a 502 JSON-RPC error rather than forwarding the (unauthorized) response.
#[tokio::test]
async fn response_phase_fails_closed_on_p1az_error() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/sideband/response"))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = test_config(mock_server.uri());
    let client = SidebandClient::new(&config);

    let event = load_bedrock_event(include_str!("fixtures/bedrock_response_permit_event.json"));
    let response = bedrock::handle_response(&event, &client, AuthErrorMode::Http).await;

    let resp = response.mcp.transformed_gateway_response.unwrap();
    assert_eq!(resp.status_code, 502);
    assert_eq!(resp.body["error"]["code"], -32603);
    assert_eq!(resp.body["id"], 3);
}

/// A denied short-circuit RESPONSE-phase event (carries
/// `x-paz-response-headers` but no `x-paz-state`) must NOT trigger a call to
/// `/sideband/response` -- the denied request's response does not need
/// authorization.
#[tokio::test]
async fn response_phase_deny_short_circuit_skips_authorization() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/sideband/response"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    let config = test_config(mock_server.uri());
    let client = SidebandClient::new(&config);

    let event = load_bedrock_event(include_str!("fixtures/bedrock_response_event.json"));
    let response = bedrock::handle_response(&event, &client, AuthErrorMode::Http).await;

    let resp = response.mcp.transformed_gateway_response.unwrap();
    assert_eq!(resp.status_code, 401);
}

/// tools/list event produces a valid flow
#[tokio::test]
async fn tools_list_event_flow() {
    let mock_server = MockServer::start().await;

    let permit_response: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/sideband_response_permit.json")).unwrap();

    Mock::given(method("POST"))
        .and(path("/sideband/request"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&permit_response))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = test_config(mock_server.uri());
    let client = SidebandClient::new(&config);

    let event = load_bedrock_event(include_str!("fixtures/bedrock_request_tools_list.json"));
    let inbound = bedrock::build_inbound_request(&event).unwrap();
    assert_eq!(inbound.method, "POST");

    let result = client.send_inbound_request(&inbound).await.unwrap();
    let response = bedrock::build_bedrock_response(&event, Ok(result));
    assert!(response.mcp.transformed_gateway_request.is_some());
}

// ---------------------------------------------------------------------------
// AUTH_ERROR_MODE=jsonrpc conversion flows
// ---------------------------------------------------------------------------

/// Full two-phase DENY flow in jsonrpc mode: the REQUEST phase keeps the
/// transport-level 401 short-circuit + carrier (mode-invariant, runtime-proven
/// path), and the RESPONSE phase's re-hydration converts the challenge to an
/// HTTP 200 in-band JSON-RPC error (code -32081) with the original status and
/// verbatim header in the namespaced error.data.
#[tokio::test]
async fn deny_401_jsonrpc_mode_converts_challenge_to_200() {
    let mock_server = MockServer::start().await;

    let deny_response: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/sideband_response_deny_401.json")).unwrap();

    Mock::given(method("POST"))
        .and(path("/sideband/request"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&deny_response))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = Config::new(
        mock_server.uri(),
        "test-secret".to_string(),
        AuthErrorMode::JsonRpc,
    );
    let client = SidebandClient::new(&config);

    let event = load_bedrock_event(include_str!("fixtures/bedrock_request_tools_call.json"));
    let inbound = bedrock::build_inbound_request(&event).unwrap();
    let result = client.send_inbound_request(&inbound).await.unwrap();

    // REQUEST phase: unchanged transport-level deny + carrier.
    let request_phase = bedrock::build_bedrock_response(&event, Ok(result));
    let short_circuit = request_phase.mcp.transformed_gateway_response.unwrap();
    assert_eq!(short_circuit.status_code, 401);
    let carrier_request = request_phase
        .mcp
        .transformed_gateway_request
        .expect("carrier emitted");

    // RESPONSE phase: Bedrock echoes the short-circuit in gatewayResponse and
    // the carrier lands in gatewayRequest.headers.
    let response_event = serde_json::json!({
        "interceptorInputVersion": "1.0",
        "mcp": {
            "gatewayRequest": {
                "path": "/mcp",
                "httpMethod": "POST",
                "headers": {
                    "Host": "example.com",
                    "x-paz-response-headers": carrier_request.headers.unwrap()[aws_bedrock_lambda_authorizer::helpers::RESPONSE_HEADERS_CARRIER]
                },
                "body": {"id": 3, "method": "tools/call", "jsonrpc": "2.0"}
            },
            "gatewayResponse": {
                "statusCode": short_circuit.status_code,
                "body": short_circuit.body
            },
            "rawGatewayRequest": {"body": "{}"}
        }
    });
    let response_event: BedrockEvent = serde_json::from_value(response_event).unwrap();

    let response_config = Config::new(
        mock_server.uri(),
        "test-secret".to_string(),
        AuthErrorMode::JsonRpc,
    );
    let response_client = SidebandClient::new(&response_config);
    let response_phase =
        bedrock::handle_response(&response_event, &response_client, AuthErrorMode::JsonRpc).await;

    let resp = response_phase.mcp.transformed_gateway_response.unwrap();
    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.body["error"]["code"], -32081);
    assert_eq!(resp.body["error"]["message"], "Authentication required");
    let details = &resp.body["error"]["data"]["com.pingidentity/auth-challenge"];
    assert_eq!(details["status"], 401);
    assert_eq!(
        details["www_authenticate"],
        "Bearer realm=\"PingOne Authorize\""
    );
    assert_eq!(resp.body["id"], 3);
}

/// RESPONSE-phase deny re-hydration in jsonrpc mode: the restored 401 +
/// www-authenticate converts to an HTTP 200 in-band challenge; no P1AZ call.
#[tokio::test]
async fn response_phase_rehydrate_converts_challenge_in_jsonrpc_mode() {
    use wiremock::matchers::path as match_path;
    use wiremock::{Mock as WMock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    WMock::given(method("POST"))
        .and(match_path("/sideband/response"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&mock_server)
        .await;

    let config = Config::new(
        mock_server.uri(),
        "test-secret".to_string(),
        AuthErrorMode::JsonRpc,
    );
    let client = SidebandClient::new(&config);

    let event = load_bedrock_event(include_str!("fixtures/bedrock_response_event.json"));
    let response = bedrock::handle_response(&event, &client, AuthErrorMode::JsonRpc).await;

    let resp = response.mcp.transformed_gateway_response.unwrap();
    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.body["error"]["code"], -32081);
    assert_eq!(
        resp.body["error"]["data"]["com.pingidentity/auth-challenge"]["www_authenticate"],
        "Bearer realm=\"PingOne Authorize\""
    );
    assert_eq!(resp.body["id"], 3);

    let headers = resp.headers.unwrap();
    assert!(!headers.contains_key("www-authenticate"));
    assert_eq!(headers.get("mcp-session-id").unwrap(), "session-abc-123");
}

/// RESPONSE-phase genuine backend response in jsonrpc mode: P1AZ forwards a
/// backend 401 + www-authenticate, which converts to an HTTP 200 in-band
/// challenge with mcp-session-id preserved on the transport.
#[tokio::test]
async fn response_phase_authorize_converts_401_challenge_in_jsonrpc_mode() {
    let mock_server = MockServer::start().await;

    let outbound_result: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/sideband_outbound_response_401_challenge.json"
    ))
    .unwrap();

    Mock::given(method("POST"))
        .and(path("/sideband/response"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&outbound_result))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = Config::new(
        mock_server.uri(),
        "test-secret".to_string(),
        AuthErrorMode::JsonRpc,
    );
    let client = SidebandClient::new(&config);

    let event = load_bedrock_event(include_str!("fixtures/bedrock_response_permit_event.json"));
    let response = bedrock::handle_response(&event, &client, AuthErrorMode::JsonRpc).await;

    let resp = response.mcp.transformed_gateway_response.unwrap();
    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.body["error"]["code"], -32081);
    assert_eq!(resp.body["error"]["message"], "Token expired");
    let details = &resp.body["error"]["data"]["com.pingidentity/auth-challenge"];
    assert_eq!(details["status"], 401);
    assert_eq!(details["error"], "invalid_token");
    assert_eq!(resp.body["id"], 3);

    let headers = resp.headers.unwrap();
    assert!(!headers.contains_key("www-authenticate"));
    assert_eq!(headers.get("mcp-session-id").unwrap(), "session-abc-123");
}

/// RESPONSE-phase rejection of a successful backend result in jsonrpc mode:
/// the backend returned 200 (a successful tool result), but P1AZ's response
/// authorization rejects it with a 403 + www-authenticate before delivery.
/// The successful result is discarded and the client gets the in-band
/// challenge at HTTP 200; no transport-level challenge header.
#[tokio::test]
async fn response_phase_authorize_rejects_successful_result_with_403_in_jsonrpc_mode() {
    let mock_server = MockServer::start().await;

    let outbound_result: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/sideband_outbound_response_403_challenge.json"
    ))
    .unwrap();

    Mock::given(method("POST"))
        .and(path("/sideband/response"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&outbound_result))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = Config::new(
        mock_server.uri(),
        "test-secret".to_string(),
        AuthErrorMode::JsonRpc,
    );
    let client = SidebandClient::new(&config);

    // Backend returned a successful 200 tool result.
    let event = load_bedrock_event(include_str!("fixtures/bedrock_response_permit_event.json"));
    let response = bedrock::handle_response(&event, &client, AuthErrorMode::JsonRpc).await;

    let resp = response.mcp.transformed_gateway_response.unwrap();
    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.body["error"]["code"], -32081);
    assert_eq!(resp.body["error"]["message"], "Missing tool scope");
    let details = &resp.body["error"]["data"]["com.pingidentity/auth-challenge"];
    assert_eq!(details["status"], 403);
    assert_eq!(details["error"], "insufficient_scope");
    assert_eq!(details["scope"], "files:write");
    assert_eq!(resp.body["id"], 3);

    let headers = resp.headers.unwrap();
    assert!(!headers.contains_key("www-authenticate"));
    assert_eq!(headers.get("mcp-session-id").unwrap(), "session-abc-123");
}
