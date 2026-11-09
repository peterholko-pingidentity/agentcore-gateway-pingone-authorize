use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// --- Sideband Request (sent to P1AZ) ---

/// The inbound request sent to PingOne Authorize via the sideband protocol.
#[derive(Serialize, Debug, Clone)]
pub struct InboundRequest {
    pub method: String,
    pub url: String,
    pub http_version: String,
    pub source_ip: String,
    pub source_port: u16,
    pub headers: Vec<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

// --- Sideband Response (received from P1AZ on HTTP 200) ---

/// The result returned by PingOne Authorize for an inbound request.
///
/// - If `response` is `None`, the request is PERMITTED (possibly with modified headers/body).
/// - If `response` is `Some`, the request is DENIED and the response should be returned to the client.
#[derive(Deserialize, Debug, Clone)]
pub struct InboundRequestResult {
    pub method: String,
    pub url: String,
    pub http_version: String,
    pub source_ip: String,
    pub source_port: u16,
    pub headers: Vec<HashMap<String, String>>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub response: Option<DeniedRequestResponse>,
    #[serde(default)]
    pub state: Option<String>,
}

/// The denial response from PingOne Authorize, included when a request is denied.
#[derive(Deserialize, Debug, Clone)]
pub struct DeniedRequestResponse {
    pub response_code: String,
    pub response_status: String,
    pub http_version: String,
    pub headers: Vec<HashMap<String, String>>,
    #[serde(default)]
    pub body: Option<String>,
}

// --- Sideband Outbound Response (sent to P1AZ) ---

/// The outbound response sent to PingOne Authorize via the sideband protocol.
///
/// The spec's `request` context object is omitted -- "Not used by AAM".
#[derive(Serialize, Debug, Clone)]
pub struct OutboundResponse {
    pub url: String,
    pub method: String,
    /// HTTP status as a STRING, per spec.
    pub response_code: String,
    pub response_status: String,
    pub http_version: String,
    pub headers: Vec<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

/// The result returned by PingOne Authorize for an outbound response.
///
/// Unlike [`InboundRequestResult`], there is no PERMIT/DENY branch -- the client
/// always receives a response, so this is always forwarded verbatim (possibly
/// transformed).
#[derive(Deserialize, Debug, Clone)]
pub struct OutboundResponseResult {
    pub response_code: String,
    #[serde(default)]
    pub response_status: Option<String>,
    #[serde(default)]
    pub http_version: Option<String>,
    #[serde(default)]
    pub headers: Vec<HashMap<String, String>>,
    #[serde(default)]
    pub body: Option<String>,
}

// --- Sideband Error Response (received from P1AZ on HTTP 4xx/5xx) ---

/// Error response body returned by PingOne Authorize on non-200 HTTP status codes.
#[derive(Deserialize, Debug, Clone)]
pub struct SidebandErrorResponse {
    pub id: String,
    pub code: String,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub details: Option<Vec<serde_json::Value>>,
}

// --- Application Errors ---

/// Errors that can occur during authorization processing.
#[derive(thiserror::Error, Debug)]
pub enum AuthorizerError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Transform error: {0}")]
    Transform(String),

    #[error("Sideband API returned HTTP {status}: {message}")]
    SidebandHttp { status: u16, message: String },

    #[error("Network error communicating with sideband API: {0}")]
    Network(#[from] reqwest::Error),

    #[error("JSON serialization/deserialization error: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inbound_request_serializes_correctly() {
        let req = InboundRequest {
            method: "POST".to_string(),
            url: "https://example.com/mcp".to_string(),
            http_version: "1.1".to_string(),
            source_ip: "0.0.0.0".to_string(),
            source_port: 1,
            headers: vec![{
                let mut m = HashMap::new();
                m.insert("content-type".to_string(), "application/json".to_string());
                m
            }],
            body: Some(r#"{"jsonrpc":"2.0"}"#.to_string()),
        };

        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["method"], "POST");
        assert_eq!(json["url"], "https://example.com/mcp");
        assert_eq!(json["http_version"], "1.1");
        assert_eq!(json["source_ip"], "0.0.0.0");
        assert_eq!(json["source_port"], 1);
        assert_eq!(json["headers"][0]["content-type"], "application/json");
        assert_eq!(json["body"], r#"{"jsonrpc":"2.0"}"#);
    }

    #[test]
    fn inbound_request_omits_none_body() {
        let req = InboundRequest {
            method: "GET".to_string(),
            url: "https://example.com/mcp".to_string(),
            http_version: "1.1".to_string(),
            source_ip: "0.0.0.0".to_string(),
            source_port: 1,
            headers: vec![],
            body: None,
        };

        let json_str = serde_json::to_string(&req).unwrap();
        assert!(!json_str.contains("\"body\""));
    }

    #[test]
    fn inbound_request_result_deserializes_permit() {
        let json = r#"{
            "method": "POST",
            "url": "https://example.com/mcp",
            "http_version": "1.1",
            "source_ip": "0.0.0.0",
            "source_port": 0,
            "headers": [{"content-type": "application/json"}],
            "body": "{\"jsonrpc\":\"2.0\"}"
        }"#;

        let result: InboundRequestResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.method, "POST");
        assert!(result.response.is_none());
        assert!(result.state.is_none());
        assert!(result.body.is_some());
    }

    #[test]
    fn inbound_request_result_deserializes_deny() {
        let json = r#"{
            "method": "POST",
            "url": "https://example.com/mcp",
            "http_version": "1.1",
            "source_ip": "0.0.0.0",
            "source_port": 0,
            "headers": [],
            "response": {
                "response_code": "403",
                "response_status": "Forbidden",
                "http_version": "1.1",
                "headers": [{"content-length": "0"}],
                "body": "{\"error\":\"access denied\"}"
            },
            "state": "eyJhbGciOiJS..."
        }"#;

        let result: InboundRequestResult = serde_json::from_str(json).unwrap();
        assert!(result.response.is_some());
        let deny = result.response.unwrap();
        assert_eq!(deny.response_code, "403");
        assert_eq!(deny.response_status, "Forbidden");
        assert_eq!(deny.body.unwrap(), r#"{"error":"access denied"}"#);
        assert_eq!(result.state.unwrap(), "eyJhbGciOiJS...");
    }

    #[test]
    fn denied_request_response_handles_no_body() {
        let json = r#"{
            "response_code": "401",
            "response_status": "Unauthorized",
            "http_version": "1.1",
            "headers": [{"www-authenticate": "Bearer"}]
        }"#;

        let deny: DeniedRequestResponse = serde_json::from_str(json).unwrap();
        assert_eq!(deny.response_code, "401");
        assert!(deny.body.is_none());
    }

    #[test]
    fn outbound_response_serializes_correctly() {
        let req = OutboundResponse {
            url: "https://example.com/mcp".to_string(),
            method: "POST".to_string(),
            response_code: "200".to_string(),
            response_status: "OK".to_string(),
            http_version: "1.1".to_string(),
            headers: vec![{
                let mut m = HashMap::new();
                m.insert("content-type".to_string(), "application/json".to_string());
                m
            }],
            body: Some(r#"{"jsonrpc":"2.0"}"#.to_string()),
            state: Some("test-state".to_string()),
        };

        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["url"], "https://example.com/mcp");
        assert_eq!(json["method"], "POST");
        assert_eq!(json["response_code"], "200");
        assert_eq!(json["response_status"], "OK");
        assert_eq!(json["http_version"], "1.1");
        assert_eq!(json["headers"][0]["content-type"], "application/json");
        assert_eq!(json["body"], r#"{"jsonrpc":"2.0"}"#);
        assert_eq!(json["state"], "test-state");
    }

    #[test]
    fn outbound_response_omits_none_body_and_state() {
        let req = OutboundResponse {
            url: "https://example.com/mcp".to_string(),
            method: "POST".to_string(),
            response_code: "200".to_string(),
            response_status: "OK".to_string(),
            http_version: "1.1".to_string(),
            headers: vec![],
            body: None,
            state: None,
        };

        let json_str = serde_json::to_string(&req).unwrap();
        assert!(!json_str.contains("\"body\""));
        assert!(!json_str.contains("\"state\""));
    }

    #[test]
    fn outbound_response_result_deserializes_plain() {
        let json = r#"{
            "response_code": "200",
            "response_status": "OK",
            "http_version": "1.1",
            "headers": [{"content-type": "application/json"}],
            "body": "{\"jsonrpc\":\"2.0\"}"
        }"#;

        let result: OutboundResponseResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.response_code, "200");
        assert_eq!(result.response_status.unwrap(), "OK");
        assert_eq!(result.headers.len(), 1);
        assert!(result.body.is_some());
    }

    #[test]
    fn outbound_response_result_deserializes_minimal() {
        let json = r#"{"response_code": "200"}"#;

        let result: OutboundResponseResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.response_code, "200");
        assert!(result.response_status.is_none());
        assert!(result.http_version.is_none());
        assert!(result.headers.is_empty());
        assert!(result.body.is_none());
    }

    #[test]
    fn sideband_error_response_deserializes() {
        let json = r#"{
            "id": "abc-123",
            "code": "REQUEST_FAILED",
            "message": "Internal server error",
            "details": [{"key": "value"}]
        }"#;

        let err: SidebandErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(err.id, "abc-123");
        assert_eq!(err.code, "REQUEST_FAILED");
        assert_eq!(err.message.unwrap(), "Internal server error");
        assert!(err.details.is_some());
    }

    #[test]
    fn sideband_error_response_handles_missing_optional_fields() {
        let json = r#"{
            "id": "abc-123",
            "code": "REQUEST_FAILED"
        }"#;

        let err: SidebandErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(err.id, "abc-123");
        assert!(err.message.is_none());
        assert!(err.details.is_none());
    }
}
