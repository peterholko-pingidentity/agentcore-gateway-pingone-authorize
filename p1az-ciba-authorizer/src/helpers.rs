use base64::{engine::general_purpose::STANDARD, Engine};
use std::collections::HashMap;

/// Header used to carry a DENY response's headers from the REQUEST interceptor
/// phase to the RESPONSE interceptor phase.
///
/// Bedrock AgentCore forbids a REQUEST interceptor's `transformedGatewayResponse`
/// from setting headers, but a RESPONSE interceptor's may. We stash the deny
/// headers (base64-encoded JSON) on the `transformedGatewayRequest` during the
/// REQUEST phase; they resurface in `gatewayRequest.headers` during the RESPONSE
/// phase, where we decode them back onto the outgoing response.
pub const RESPONSE_HEADERS_CARRIER: &str = "x-paz-response-headers";

/// Header used to carry the P1AZ-issued `state` string from the REQUEST
/// interceptor phase (on PERMIT) to the RESPONSE interceptor phase, so the
/// response call to `/sideband/response` can be correlated with the original
/// request. Its presence in `gatewayRequest.headers` during the RESPONSE phase
/// is also the discriminator for "this is a genuine backend response that
/// needs authorizing" vs. a denied short-circuit.
pub const REQUEST_STATE_CARRIER: &str = "x-paz-state";

/// Generic P1AZ authorization error, used as the JSON-RPC error code in
/// deny-wrap bodies (`build_deny_body`). Replaces the previous misuse of the
/// spec code -32600 ("Invalid Request").
pub const P1AZ_GENERIC_ERROR_CODE: i32 = -32080;

/// Auth challenge marker: JSON-RPC error code carried by `AUTH_ERROR_MODE=jsonrpc`
/// responses. Clients use it to identify a step-up challenge programmatically.
pub const P1AZ_AUTH_ERROR_CODE: i32 = -32081;

/// Convert a flat header map `{"name": "value", ...}` to sideband array format
/// `[{"name": "value"}, {"name2": "value2"}, ...]`.
///
/// Each entry in the output array is a single-key HashMap.
pub fn headers_to_sideband_array(
    headers: &HashMap<String, String>,
) -> Vec<HashMap<String, String>> {
    headers
        .iter()
        .map(|(k, v)| {
            let mut m = HashMap::with_capacity(1);
            m.insert(k.clone(), v.clone());
            m
        })
        .collect()
}

/// Convert sideband array `[{"name": "value"}, ...]` to a flat map `{"name": "value", ...}`.
///
/// For duplicate header names, the LAST value wins (consistent with HTTP semantics
/// where later headers override earlier ones for single-valued headers).
pub fn sideband_array_to_flat_headers(
    headers: &[HashMap<String, String>],
) -> HashMap<String, String> {
    let mut flat = HashMap::new();
    for entry in headers {
        for (k, v) in entry {
            flat.insert(k.clone(), v.clone());
        }
    }
    flat
}

/// Build a full URL from scheme, host, and path.
///
/// Example: `build_url("https", "example.com", "/mcp")` -> `"https://example.com/mcp"`
pub fn build_url(scheme: &str, host: &str, path: &str) -> String {
    format!("{scheme}://{host}{path}")
}

/// Find a header value by name (case-insensitive) in a flat header map.
pub fn find_header<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    let name_lower = name.to_lowercase();
    headers
        .iter()
        .find(|(k, _)| k.to_lowercase() == name_lower)
        .map(|(_, v)| v.as_str())
}

/// Remove a header by name (case-insensitive) from a flat header map,
/// returning its value when present.
pub fn remove_header(headers: &mut HashMap<String, String>, name: &str) -> Option<String> {
    let name_lower = name.to_lowercase();
    let key = headers
        .keys()
        .find(|k| k.to_lowercase() == name_lower)?
        .clone();
    headers.remove(&key)
}

/// The reverse-DNS namespace key (MCP `_meta`-style) under which the
/// auth-challenge details are nested in `error.data`. Clients use it to
/// distinguish this gateway's `-32081` error from any other vendor's
/// server-defined error in the unregistered -32000..-32099 range.
pub const AUTH_CHALLENGE_DATA_KEY: &str = "com.pingidentity/auth-challenge";

/// An RFC 7235 challenge parsed into its auth scheme and attribute pairs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedChallenge {
    /// The scheme token, e.g. `"Bearer"`.
    pub scheme: String,
    /// The challenge's attribute pairs in order of appearance. Keys are
    /// lowercased; quoted values are unquoted with `\"`/`\\` unescaped.
    pub params: Vec<(String, String)>,
}

impl ParsedChallenge {
    /// Look up a param value by (already lowercased) key; last occurrence wins.
    pub fn param(&self, key: &str) -> Option<&str> {
        self.params
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Parse an RFC 7235 `www-authenticate` challenge: the scheme token followed
/// by comma-separated `key=value` attribute pairs. Only the FIRST challenge of
/// a (rare) multi-challenge header is parsed -- a pair whose name carries a
/// space starts a second scheme, and parsing stops there; the verbatim header
/// remains available for exact needs.
pub fn parse_www_authenticate(header: &str) -> ParsedChallenge {
    let header = header.trim();
    let (scheme, rest) = match header.split_once(' ') {
        Some((scheme, rest)) => (scheme, Some(rest)),
        None => (header, None),
    };

    let mut params = Vec::new();
    if let Some(rest) = rest {
        for segment in split_challenge_params(rest) {
            let segment = segment.trim();
            let Some((name, value)) = segment.split_once('=') else {
                continue;
            };
            let name = name.trim().to_lowercase();
            if name.is_empty() || name.contains(' ') {
                break;
            }
            params.push((name, unquote_param_value(value.trim())));
        }
    }

    ParsedChallenge {
        scheme: scheme.to_string(),
        params,
    }
}

/// Unquote an RFC 7235 quoted-string param value, unescaping `\"` and `\\`.
/// A bare token is returned as-is.
fn unquote_param_value(value: &str) -> String {
    if let Some(unquoted) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
        unquoted.replace("\\\"", "\"").replace("\\\\", "\\")
    } else {
        value.to_string()
    }
}

/// Extract the `error_description` parameter from a `www-authenticate` header
/// value. Returns `None` when the param is absent or empty.
pub fn extract_error_description(www_authenticate: &str) -> Option<String> {
    parse_www_authenticate(www_authenticate)
        .param("error_description")
        .map(str::to_string)
        .filter(|value| !value.is_empty())
}

/// Split a challenge header into its comma-separated params, ignoring commas
/// inside double-quoted values (a description like "Token, expired" must not
/// split). Escaped quotes inside quoted values are not special-cased here;
/// a mis-split in that exotic case degrades to a None extraction, never to
/// wrong data (the verbatim header stays in `error.data`).
fn split_challenge_params(header: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut in_quotes = false;
    let mut start = 0;
    for (i, c) in header.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                parts.push(&header[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&header[start..]);
    parts
}

/// Check if a `serde_json::Value` represents a valid JSON-RPC error response
/// (has both `"jsonrpc"` and `"error"` fields).
pub fn is_jsonrpc_error(value: &serde_json::Value) -> bool {
    value.get("jsonrpc").is_some() && value.get("error").is_some()
}

/// Build a JSON-RPC 2.0 error response object.
///
/// `id` should be from the original request; use `Value::Null` if unavailable.
pub fn build_jsonrpc_error(id: serde_json::Value, code: i32, message: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message
        }
    })
}

/// Build the JSON-RPC error body that `AUTH_ERROR_MODE=jsonrpc` returns to the
/// client for an upstream auth challenge ([`P1AZ_AUTH_ERROR_CODE`]).
///
/// `error.message` is the challenge's `error_description` parameter, falling
/// back to "Authentication required" when the header carries none.
///
/// `error.data` nests every detail under the reverse-DNS
/// [`AUTH_CHALLENGE_DATA_KEY`] (MCP `_meta`-style), so a client can tell this
/// vendor's -32081 from any other vendor's server-defined error. The
/// `www_authenticate` slot carries the verbatim header; the `scheme` and
/// `status` slots plus one slot per attribute pair make the challenge
/// recomposable without re-parsing the verbatim string.
pub fn build_auth_challenge_error(
    id: serde_json::Value,
    status: u16,
    www_authenticate: &str,
) -> serde_json::Value {
    let challenge = parse_www_authenticate(www_authenticate);
    let message = extract_error_description(www_authenticate)
        .unwrap_or_else(|| "Authentication required".to_string());

    let mut details = serde_json::Map::new();
    // Attribute pairs first; the three contract slots below are inserted
    // afterward so a challenge param with a colliding name can never corrupt
    // them (the param still exists in the verbatim header).
    for (name, value) in &challenge.params {
        details.insert(name.clone(), serde_json::Value::String(value.clone()));
    }
    details.insert(
        "www_authenticate".to_string(),
        serde_json::Value::String(www_authenticate.to_string()),
    );
    details.insert("status".to_string(), serde_json::json!(status));
    details.insert(
        "scheme".to_string(),
        serde_json::Value::String(challenge.scheme),
    );

    let mut error = build_jsonrpc_error(id, P1AZ_AUTH_ERROR_CODE, &message);
    error["error"]["data"] = serde_json::json!({ AUTH_CHALLENGE_DATA_KEY: details });
    error
}

/// Encode a flat header map as a base64 string of its JSON representation.
///
/// Used to stash DENY response headers in the [`RESPONSE_HEADERS_CARRIER`]
/// header during the REQUEST interceptor phase.
pub fn encode_response_headers(headers: &HashMap<String, String>) -> String {
    // Serialization of a HashMap<String, String> cannot fail; fall back to an
    // empty object rather than panicking.
    let json = serde_json::to_string(headers).unwrap_or_else(|_| "{}".to_string());
    STANDARD.encode(json)
}

/// Decode a [`RESPONSE_HEADERS_CARRIER`] value back into a flat header map.
///
/// Returns `None` if the value is not valid base64 or does not decode to a JSON
/// object of string values -- callers treat this as "no headers to restore".
pub fn decode_response_headers(encoded: &str) -> Option<HashMap<String, String>> {
    let bytes = STANDARD.decode(encoded).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Return the standard HTTP reason phrase for a status code, or `""` if unknown.
///
/// Used to populate the spec-required `response_status` field of an
/// [`crate::models::OutboundResponse`] when the backend's response doesn't carry
/// one explicitly.
pub fn reason_phrase(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn headers_to_sideband_array_converts_flat_map() {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("authorization".to_string(), "Bearer token".to_string());

        let array = headers_to_sideband_array(&headers);
        assert_eq!(array.len(), 2);

        // Each entry should be a single-key map
        for entry in &array {
            assert_eq!(entry.len(), 1);
        }

        // Verify all headers are present
        let flat = sideband_array_to_flat_headers(&array);
        assert_eq!(flat.get("content-type").unwrap(), "application/json");
        assert_eq!(flat.get("authorization").unwrap(), "Bearer token");
    }

    #[test]
    fn headers_to_sideband_array_handles_empty() {
        let headers = HashMap::new();
        let array = headers_to_sideband_array(&headers);
        assert!(array.is_empty());
    }

    #[test]
    fn sideband_array_to_flat_headers_converts_array() {
        let array = vec![
            {
                let mut m = HashMap::new();
                m.insert("content-type".to_string(), "application/json".to_string());
                m
            },
            {
                let mut m = HashMap::new();
                m.insert("authorization".to_string(), "Bearer token".to_string());
                m
            },
        ];

        let flat = sideband_array_to_flat_headers(&array);
        assert_eq!(flat.len(), 2);
        assert_eq!(flat.get("content-type").unwrap(), "application/json");
        assert_eq!(flat.get("authorization").unwrap(), "Bearer token");
    }

    #[test]
    fn sideband_array_to_flat_headers_last_value_wins() {
        let array = vec![
            {
                let mut m = HashMap::new();
                m.insert("authorization".to_string(), "Bearer first".to_string());
                m
            },
            {
                let mut m = HashMap::new();
                m.insert("authorization".to_string(), "Bearer second".to_string());
                m
            },
        ];

        let flat = sideband_array_to_flat_headers(&array);
        assert_eq!(flat.get("authorization").unwrap(), "Bearer second");
    }

    #[test]
    fn sideband_array_to_flat_headers_handles_empty() {
        let flat = sideband_array_to_flat_headers(&[]);
        assert!(flat.is_empty());
    }

    #[test]
    fn build_url_combines_parts() {
        assert_eq!(
            build_url("https", "example.com", "/mcp"),
            "https://example.com/mcp"
        );
    }

    #[test]
    fn build_url_with_port_in_host() {
        assert_eq!(
            build_url("https", "example.com:443", "/mcp"),
            "https://example.com:443/mcp"
        );
    }

    #[test]
    fn build_url_empty_path() {
        assert_eq!(build_url("https", "example.com", ""), "https://example.com");
    }

    #[test]
    fn find_header_case_insensitive() {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("Host".to_string(), "example.com".to_string());

        assert_eq!(
            find_header(&headers, "content-type"),
            Some("application/json")
        );
        assert_eq!(
            find_header(&headers, "CONTENT-TYPE"),
            Some("application/json")
        );
        assert_eq!(
            find_header(&headers, "Content-Type"),
            Some("application/json")
        );
        assert_eq!(find_header(&headers, "host"), Some("example.com"));
        assert_eq!(find_header(&headers, "Host"), Some("example.com"));
    }

    #[test]
    fn find_header_returns_none_for_missing() {
        let headers = HashMap::new();
        assert_eq!(find_header(&headers, "missing"), None);
    }

    #[test]
    fn is_jsonrpc_error_true_for_valid() {
        let value = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32600,
                "message": "Invalid Request"
            }
        });
        assert!(is_jsonrpc_error(&value));
    }

    #[test]
    fn is_jsonrpc_error_false_for_missing_error() {
        let value = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {}
        });
        assert!(!is_jsonrpc_error(&value));
    }

    #[test]
    fn is_jsonrpc_error_false_for_missing_jsonrpc() {
        let value = json!({
            "error": {
                "code": -32600,
                "message": "Invalid Request"
            }
        });
        assert!(!is_jsonrpc_error(&value));
    }

    #[test]
    fn is_jsonrpc_error_false_for_plain_string() {
        let value = json!("not an error");
        assert!(!is_jsonrpc_error(&value));
    }

    #[test]
    fn build_jsonrpc_error_creates_correct_structure() {
        let error = build_jsonrpc_error(json!(3), -32600, "Forbidden");

        assert_eq!(error["jsonrpc"], "2.0");
        assert_eq!(error["id"], 3);
        assert_eq!(error["error"]["code"], -32600);
        assert_eq!(error["error"]["message"], "Forbidden");
    }

    #[test]
    fn build_jsonrpc_error_with_null_id() {
        let error = build_jsonrpc_error(serde_json::Value::Null, -32603, "Internal error");

        assert_eq!(error["jsonrpc"], "2.0");
        assert!(error["id"].is_null());
        assert_eq!(error["error"]["code"], -32603);
        assert_eq!(error["error"]["message"], "Internal error");
    }

    #[test]
    fn error_code_constants_have_expected_values() {
        assert_eq!(P1AZ_GENERIC_ERROR_CODE, -32080);
        assert_eq!(P1AZ_AUTH_ERROR_CODE, -32081);
    }

    #[test]
    fn remove_header_removes_case_insensitively() {
        let mut headers = HashMap::new();
        headers.insert(
            "WWW-Authenticate".to_string(),
            "Bearer realm=\"x\"".to_string(),
        );

        let removed = remove_header(&mut headers, "www-authenticate");
        assert_eq!(removed.as_deref(), Some("Bearer realm=\"x\""));
        assert!(headers.is_empty());
    }

    #[test]
    fn remove_header_returns_none_when_missing() {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());

        assert_eq!(remove_header(&mut headers, "www-authenticate"), None);
        assert_eq!(headers.len(), 1, "unrelated header untouched");
    }

    #[test]
    fn extract_error_description_quoted_value() {
        let header =
            "Bearer realm=\"PingOne Authorize\", error=\"invalid_token\", error_description=\"Token expired\"";
        assert_eq!(
            extract_error_description(header).as_deref(),
            Some("Token expired")
        );
    }

    #[test]
    fn extract_error_description_bare_token_value() {
        let header = "Bearer error_description=Token expired, scope=\"x\"";
        assert_eq!(
            extract_error_description(header).as_deref(),
            Some("Token expired")
        );
    }

    #[test]
    fn extract_error_description_case_insensitive_key() {
        let header = "Bearer ERROR_DESCRIPTION=\"Token expired\"";
        assert_eq!(
            extract_error_description(header).as_deref(),
            Some("Token expired")
        );
    }

    #[test]
    fn extract_error_description_unescapes_quoted_pairs() {
        let header = "Bearer error_description=\"say \\\"hi\\\" now\"";
        assert_eq!(
            extract_error_description(header).as_deref(),
            Some("say \"hi\" now")
        );
    }

    #[test]
    fn extract_error_description_missing_returns_none() {
        let header = "Bearer realm=\"PingOne Authorize\", error=\"invalid_token\"";
        assert_eq!(extract_error_description(header), None);
    }

    #[test]
    fn extract_error_description_empty_value_returns_none() {
        assert_eq!(
            extract_error_description("Bearer error_description=\"\""),
            None
        );
        assert_eq!(extract_error_description("Bearer error_description="), None);
    }

    #[test]
    fn extract_error_description_no_params_returns_none() {
        assert_eq!(extract_error_description("Bearer"), None);
        assert_eq!(extract_error_description(""), None);
    }

    #[test]
    fn parse_www_authenticate_bearer_with_params() {
        let header = "Bearer realm=\"PingOne Authorize\", error=\"invalid_token\", error_description=\"Token expired\"";
        let parsed = parse_www_authenticate(header);

        assert_eq!(parsed.scheme, "Bearer");
        assert_eq!(parsed.param("realm"), Some("PingOne Authorize"));
        assert_eq!(parsed.param("error"), Some("invalid_token"));
        assert_eq!(parsed.param("error_description"), Some("Token expired"));
    }

    #[test]
    fn parse_www_authenticate_lowercases_keys_and_keeps_order() {
        let parsed =
            parse_www_authenticate("Bearer Scope=\"files:write\", ERROR=\"x\", realm=\"r\"");

        assert_eq!(parsed.param("scope"), Some("files:write"));
        assert_eq!(parsed.param("error"), Some("x"));
        assert_eq!(
            parsed
                .params
                .iter()
                .map(|(k, _)| k.as_str())
                .collect::<Vec<_>>(),
            vec!["scope", "error", "realm"],
            "attribute order preserved for recomposition"
        );
    }

    #[test]
    fn parse_www_authenticate_bare_token_value() {
        let parsed = parse_www_authenticate("Bearer error_description=Token expired, realm=\"r\"");
        assert_eq!(parsed.param("error_description"), Some("Token expired"));
        assert_eq!(parsed.param("realm"), Some("r"));
    }

    #[test]
    fn parse_www_authenticate_unescapes_quoted_pairs() {
        let parsed = parse_www_authenticate("Bearer error_description=\"say \\\"hi\\\" now\"");
        assert_eq!(parsed.param("error_description"), Some("say \"hi\" now"));
    }

    #[test]
    fn parse_www_authenticate_scheme_only() {
        let parsed = parse_www_authenticate("Bearer");
        assert_eq!(parsed.scheme, "Bearer");
        assert!(parsed.params.is_empty());
    }

    #[test]
    fn parse_www_authenticate_stops_at_second_scheme() {
        // Multi-challenge header: only the first challenge is parsed; the
        // verbatim string stays in the details for exact needs.
        let parsed = parse_www_authenticate("Bearer realm=\"r\", Basic realm=\"b\"");
        assert_eq!(parsed.scheme, "Bearer");
        assert_eq!(parsed.param("realm"), Some("r"));
        assert_eq!(parsed.params.len(), 1);
    }

    #[test]
    fn parse_www_authenticate_ignores_commas_inside_quotes() {
        let parsed =
            parse_www_authenticate("Bearer error_description=\"Token, expired\", realm=\"r\"");
        assert_eq!(parsed.param("error_description"), Some("Token, expired"));
        assert_eq!(parsed.param("realm"), Some("r"));
    }

    #[test]
    fn parse_www_authenticate_param_last_occurrence_wins() {
        let parsed = parse_www_authenticate("Bearer error=\"first\", error=\"second\"");
        assert_eq!(parsed.param("error"), Some("second"));
    }

    #[test]
    fn build_auth_challenge_error_contains_code_message_and_namespaced_data() {
        let header = "Bearer realm=\"PingOne Authorize\", error=\"invalid_token\", error_description=\"Token expired\"";
        let error = build_auth_challenge_error(json!(3), 401, header);
        let details = &error["error"]["data"][AUTH_CHALLENGE_DATA_KEY];

        assert_eq!(error["jsonrpc"], "2.0");
        assert_eq!(error["id"], 3);
        assert_eq!(error["error"]["code"], P1AZ_AUTH_ERROR_CODE);
        assert_eq!(error["error"]["message"], "Token expired");
        assert_eq!(details["status"], 401);
        assert_eq!(details["scheme"], "Bearer");
        assert_eq!(details["www_authenticate"], header);
        assert_eq!(details["error"], "invalid_token");
        assert_eq!(details["error_description"], "Token expired");
        assert_eq!(details["realm"], "PingOne Authorize");
    }

    #[test]
    fn build_auth_challenge_error_fallback_message_without_error_description() {
        let header = "Bearer realm=\"PingOne Authorize\"";
        let error = build_auth_challenge_error(serde_json::Value::Null, 403, header);
        let details = &error["error"]["data"][AUTH_CHALLENGE_DATA_KEY];

        assert_eq!(error["error"]["code"], P1AZ_AUTH_ERROR_CODE);
        assert_eq!(error["error"]["message"], "Authentication required");
        assert_eq!(details["status"], 403);
        assert_eq!(details["scheme"], "Bearer");
        assert_eq!(details["www_authenticate"], header);
        assert!(error["id"].is_null());
    }

    #[test]
    fn build_auth_challenge_error_data_is_recomposable() {
        // Every ingredient of the header exists as a structured slot, so a
        // client can recompose a different www-authenticate without parsing.
        let header = "Bearer error=\"insufficient_scope\", scope=\"files:write\", resource_metadata=\"https://as.example.com\", error_description=\"Insufficient scope\"";
        let error = build_auth_challenge_error(json!(1), 403, header);
        let details = &error["error"]["data"][AUTH_CHALLENGE_DATA_KEY];

        assert_eq!(details["scheme"], "Bearer");
        assert_eq!(details["error"], "insufficient_scope");
        assert_eq!(details["scope"], "files:write");
        assert_eq!(details["resource_metadata"], "https://as.example.com");
        assert_eq!(details["error_description"], "Insufficient scope");
    }

    #[test]
    fn build_auth_challenge_error_contract_slots_survive_param_collision() {
        // A challenge param literally named "status"/"scheme"/"www_authenticate"
        // must not corrupt the contract slots.
        let header = "Bearer status=\"999\", scheme=\"Fake\", www_authenticate=\"fake\"";
        let error = build_auth_challenge_error(serde_json::Value::Null, 401, header);
        let details = &error["error"]["data"][AUTH_CHALLENGE_DATA_KEY];

        assert_eq!(details["status"], 401);
        assert_eq!(details["scheme"], "Bearer");
        assert_eq!(details["www_authenticate"], header);
    }

    #[test]
    fn build_auth_challenge_error_data_key_is_vendor_namespaced() {
        // The namespacing is the vendor signal: only com.pingidentity/* may
        // appear as a data key besides nothing else at the data top level.
        let error = build_auth_challenge_error(
            serde_json::Value::Null,
            401,
            "Bearer error=\"invalid_token\"",
        );
        let data = error["error"]["data"].as_object().unwrap();
        assert_eq!(data.len(), 1, "data nests everything under one vendor key");
        assert!(data.contains_key(AUTH_CHALLENGE_DATA_KEY));
    }

    #[test]
    fn encode_decode_response_headers_round_trip() {
        let mut headers = HashMap::new();
        headers.insert(
            "www-authenticate".to_string(),
            "Bearer realm=\"PingOne Authorize\"".to_string(),
        );
        headers.insert("content-length".to_string(), "0".to_string());

        let encoded = encode_response_headers(&headers);
        // Base64 output has no JSON delimiters.
        assert!(!encoded.contains('{'));

        let decoded = decode_response_headers(&encoded).unwrap();
        assert_eq!(decoded, headers);
    }

    #[test]
    fn encode_response_headers_empty_map() {
        let headers = HashMap::new();
        let encoded = encode_response_headers(&headers);
        let decoded = decode_response_headers(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn decode_response_headers_invalid_base64() {
        assert!(decode_response_headers("not base64!!!").is_none());
    }

    #[test]
    fn decode_response_headers_valid_base64_but_not_json_object() {
        // base64 of the string "hello" -- decodes fine but isn't a JSON map.
        let encoded = STANDARD.encode("hello");
        assert!(decode_response_headers(&encoded).is_none());
    }

    #[test]
    fn reason_phrase_known_codes() {
        assert_eq!(reason_phrase(200), "OK");
        assert_eq!(reason_phrase(201), "Created");
        assert_eq!(reason_phrase(401), "Unauthorized");
        assert_eq!(reason_phrase(403), "Forbidden");
        assert_eq!(reason_phrase(404), "Not Found");
        assert_eq!(reason_phrase(429), "Too Many Requests");
        assert_eq!(reason_phrase(500), "Internal Server Error");
        assert_eq!(reason_phrase(502), "Bad Gateway");
    }

    #[test]
    fn reason_phrase_unknown_code_falls_back_to_empty() {
        assert_eq!(reason_phrase(499), "");
    }
}
