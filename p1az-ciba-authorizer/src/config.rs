use std::env;
use std::env::VarError;

/// How upstream auth challenges (HTTP 4xx + `www-authenticate`) are returned to
/// MCP clients. Controlled by the optional `AUTH_ERROR_MODE` env var.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthErrorMode {
    /// Current behavior: forward the 4xx status and `www-authenticate` header as-is.
    Http,
    /// Convert auth challenges into HTTP 200 JSON-RPC error responses (code
    /// -32081) with the challenge in `error.message` and `error.data`.
    JsonRpc,
}

impl AuthErrorMode {
    /// Parse the value of the `AUTH_ERROR_MODE` environment variable.
    ///
    /// An empty value is treated as unset (the AWS console allows creating
    /// empty env vars). Matching is case-sensitive: only `jsonrpc` is
    /// recognized. Any other value panics -- fail fast at Lambda init, like
    /// the required variables.
    pub fn parse(value: &str) -> Self {
        match value {
            "" => AuthErrorMode::Http,
            "jsonrpc" => AuthErrorMode::JsonRpc,
            other => panic!("Invalid AUTH_ERROR_MODE value {other:?} -- supported values: jsonrpc"),
        }
    }

    /// Read the mode from the environment; defaults to [`AuthErrorMode::Http`]
    /// when `AUTH_ERROR_MODE` is not present. A non-UTF-8 value also fails fast.
    pub fn from_env() -> Self {
        match env::var("AUTH_ERROR_MODE") {
            Ok(value) => AuthErrorMode::parse(&value),
            Err(VarError::NotPresent) => AuthErrorMode::Http,
            Err(e) => panic!("AUTH_ERROR_MODE environment variable is invalid: {e}"),
        }
    }
}

/// (fork) Whether responses are authorized (`/sideband/response`). Controlled by
/// the optional `RESPONSE_AUTHORIZATION` env var: unset, empty or `on` keeps
/// upstream's behavior; `off` stops the REQUEST phase from emitting the
/// `x-paz-state` carrier, so the RESPONSE phase passes responses through.
///
/// Why turn it off: the carrier must be in the targets' `allowedRequestHeaders`
/// to reach the RESPONSE phase, which makes the Gateway forward it to every
/// target, and AgentCore caps a forwarded header value at 4 KB. P1AZ's state
/// token outgrows that once the request carries a PingOne access token (about
/// 6 KB), and the Gateway's calls to the targets fail. Denials don't need it:
/// their `x-paz-response-headers` carrier is small and never reaches a target.
pub fn response_authorization_from_env() -> bool {
    match env::var("RESPONSE_AUTHORIZATION").as_deref() {
        Err(VarError::NotPresent) | Ok("") | Ok("on") => true,
        Ok("off") => false,
        Ok(other) => panic!("Invalid RESPONSE_AUTHORIZATION value {other:?} -- supported values: on, off"),
        Err(e) => panic!("RESPONSE_AUTHORIZATION environment variable is invalid: {e}"),
    }
}

/// Configuration loaded from environment variables.
///
/// Required variables are validated at Lambda init time (before the first invocation).
/// Missing required variables cause a panic at startup -- fail fast rather than
/// returning errors on every invocation.
pub struct Config {
    /// P1AZ sideband API base URL
    /// (e.g., `https://http-access-policy.pingone.com/v1/environments/<env-id>`)
    pub service_url: String,

    /// Shared secret for P1AZ authentication (sent as the `Client-Token` header)
    pub secret_header_value: String,

    /// Auth-challenge return mode. Defaults to [`AuthErrorMode::Http`]
    /// when `AUTH_ERROR_MODE` is unset or empty.
    pub auth_error_mode: AuthErrorMode,
}

impl Config {
    /// Read configuration from environment variables.
    /// Panics if required variables are missing or `AUTH_ERROR_MODE` is invalid.
    pub fn from_env() -> Self {
        let service_url =
            env::var("SERVICE_URL").expect("SERVICE_URL environment variable is required");
        let secret_header_value = env::var("SECRET_HEADER_VALUE")
            .expect("SECRET_HEADER_VALUE environment variable is required");
        let auth_error_mode = AuthErrorMode::from_env();

        Config {
            service_url,
            secret_header_value,
            auth_error_mode,
        }
    }

    /// Create a Config directly (useful for tests and integration scenarios).
    pub fn new(
        service_url: String,
        secret_header_value: String,
        auth_error_mode: AuthErrorMode,
    ) -> Self {
        Config {
            service_url,
            secret_header_value,
            auth_error_mode,
        }
    }
}

// ---------------------------------------------------------------------------
// CIBA approval flow (this fork's addition)
// ---------------------------------------------------------------------------

/// The CIBA provider the approval flow talks to. Controlled by `CIBA_PROVIDER`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CibaProvider {
    /// PingFederate: the exact request travels in `authorization_details` (RAR) and
    /// comes back with the approval.
    PingFederate,
    /// PingOne: no `authorization_details`; the request is recorded in the CIBA
    /// table when the approval starts.
    PingOne,
}

impl CibaProvider {
    /// Parse `CIBA_PROVIDER`; empty means PingFederate. Any other value panics.
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "pingfederate" => CibaProvider::PingFederate,
            "pingone" => CibaProvider::PingOne,
            other => panic!(
                "Invalid CIBA_PROVIDER value {other:?} -- supported values: pingfederate, pingone"
            ),
        }
    }

    /// Longest binding message the provider accepts (PingFederate 20, PingOne 8).
    pub fn binding_message_max(self) -> usize {
        match self {
            CibaProvider::PingFederate => 20,
            CibaProvider::PingOne => 8,
        }
    }
}

/// How an approval is tied to the exact request it was asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestBinding {
    /// The request travels in `authorization_details`; the provider returns it with
    /// the approval and the authorizer compares it.
    AuthorizationDetails,
    /// The request is recorded under the reference in the CIBA table when the
    /// approval starts, and a replay is checked against it before redeeming.
    Table,
}

/// Configuration of the CIBA approval flow.
///
/// A PingOne Authorize policy asks for a human approval by denying with an
/// `auth-challenge` statement whose `acrValues` include [`Self::challenge_acr`].
/// The authorizer then starts a CIBA request with the provider, waits up to
/// [`Self::hold_seconds`] for it, and otherwise answers with an MCP 2026-07-28
/// `input_required` result whose sealed `requestState` names the approval; the
/// client retries the call with that state. Once the user has approved, the
/// authorizer sends the request to the sideband API again with the trusted
/// [`Self::approval_header`] / [`Self::approver_header`] so the policy can permit
/// it. A DynamoDB table makes each approval single-use.
#[derive(Clone, Debug)]
pub struct CibaConfig {
    pub provider: CibaProvider,
    /// The provider's backchannel authentication endpoint.
    pub authorization_endpoint: String,
    /// The provider's token endpoint.
    pub token_endpoint: String,
    /// CIBA client (poll mode), authenticated with HTTP Basic.
    pub client_id: String,
    pub client_secret: String,
    /// DynamoDB table (partition key `pk`, string; TTL on `ttl`).
    pub table: String,
    /// AWS region of the table (`AWS_REGION`, set by Lambda).
    pub region: String,
    /// DynamoDB endpoint override (`CIBA_DYNAMODB_ENDPOINT`); defaults to the
    /// regional endpoint.
    pub dynamodb_endpoint: String,
    pub scope: String,
    /// Caller-token claim sent as `login_hint`.
    pub login_hint_claim: String,
    /// Caller-token claim that must equal the approver's `sub`.
    pub subject_claim: String,
    /// Requested approval lifetime, in seconds.
    pub requested_expiry: u64,
    pub binding_message_prefix: String,
    /// `authorization_details` type (PingFederate); empty binds through the table.
    pub authorization_details_type: String,
    /// HMAC key that seals the `requestState` given to clients (`CIBA_STATE_KEY`,
    /// at least 32 characters, secret). Changing it invalidates pending approvals.
    pub state_key: String,
    /// Longest time one invocation waits for an approval before answering
    /// `input_required` (`CIBA_HOLD_SECONDS`). Must fit the Lambda timeout.
    pub hold_seconds: u64,
    /// Seconds between polls while holding, when the provider gives no interval.
    pub poll_interval: u64,
    /// Lifetime of table items; never shorter than `requested_expiry`.
    pub table_ttl_seconds: u64,
    /// Network timeout for calls to the provider and DynamoDB, in seconds.
    pub http_timeout_secs: u64,
    /// `acr_values` entry of the policy's challenge that means "get a CIBA approval".
    pub challenge_acr: String,
    /// Trusted header the authorizer sets (and strips from clients) on an approved replay.
    pub approval_header: String,
    /// Trusted header carrying the approver's `sub` on an approved replay.
    pub approver_header: String,
}

impl CibaConfig {
    /// Defaults for everything but the provider, its endpoints and client, and
    /// the table (also used by tests).
    pub fn new(
        provider: CibaProvider,
        authorization_endpoint: String,
        token_endpoint: String,
        client_id: String,
        client_secret: String,
        table: String,
    ) -> Self {
        let region = "us-east-1".to_string();
        CibaConfig {
            provider,
            authorization_endpoint,
            token_endpoint,
            client_id,
            client_secret,
            table,
            dynamodb_endpoint: format!("https://dynamodb.{region}.amazonaws.com"),
            region,
            scope: "openid".to_string(),
            login_hint_claim: "sub".to_string(),
            subject_claim: "sub".to_string(),
            // Under a stock client's 10 retries of hold_seconds each (MCP SDK 2.x,
            // Strands), so the approval expires before the client gives up.
            requested_expiry: 180,
            binding_message_prefix: "APR".to_string(),
            authorization_details_type: "mcp_request".to_string(),
            state_key: String::new(),
            hold_seconds: 20,
            poll_interval: 5,
            table_ttl_seconds: 86400,
            http_timeout_secs: 5,
            challenge_acr: "ciba-approval".to_string(),
            approval_header: "x-ciba-approval".to_string(),
            approver_header: "x-ciba-approver".to_string(),
        }
    }

    /// Read the CIBA configuration from the environment.
    ///
    /// Returns `None` when `CIBA_AUTHORIZATION_ENDPOINT` is unset or empty: the
    /// authorizer then behaves exactly as upstream. Panics on a partial or
    /// invalid configuration -- fail fast at Lambda init, like the required
    /// sideband variables.
    pub fn from_env() -> Option<Self> {
        let get = |name: &str| env::var(name).ok().filter(|v| !v.trim().is_empty());
        let authorization_endpoint = get("CIBA_AUTHORIZATION_ENDPOINT")?;
        let required = |name: &str| {
            get(name).unwrap_or_else(|| {
                panic!("{name} environment variable is required when CIBA_AUTHORIZATION_ENDPOINT is set")
            })
        };
        let number = |name: &str, default: u64| {
            get(name).map_or(default, |v| {
                v.trim()
                    .parse()
                    .unwrap_or_else(|_| panic!("{name} must be a whole number of seconds, got {v:?}"))
            })
        };

        let mut config = CibaConfig::new(
            CibaProvider::parse(&get("CIBA_PROVIDER").unwrap_or_default()),
            authorization_endpoint,
            required("CIBA_TOKEN_ENDPOINT"),
            required("CIBA_CLIENT_ID"),
            required("CIBA_CLIENT_SECRET"),
            required("CIBA_TABLE"),
        );
        config.state_key = required("CIBA_STATE_KEY");
        assert!(
            config.state_key.len() >= 32,
            "CIBA_STATE_KEY must be at least 32 characters (a random secret)"
        );
        config.region = required("AWS_REGION");
        config.dynamodb_endpoint = get("CIBA_DYNAMODB_ENDPOINT")
            .unwrap_or_else(|| format!("https://dynamodb.{}.amazonaws.com", config.region));
        let text = |name: &str, current: &mut String| {
            if let Some(v) = get(name) {
                *current = v;
            }
        };
        text("CIBA_SCOPE", &mut config.scope);
        text("CIBA_LOGIN_HINT_CLAIM", &mut config.login_hint_claim);
        text("CIBA_SUBJECT_CLAIM", &mut config.subject_claim);
        text("CIBA_BINDING_MESSAGE_PREFIX", &mut config.binding_message_prefix);
        text("CIBA_CHALLENGE_ACR", &mut config.challenge_acr);
        text("CIBA_APPROVAL_HEADER", &mut config.approval_header);
        text("CIBA_APPROVER_HEADER", &mut config.approver_header);
        // Present but empty is meaningful here: bind requests through the table.
        if let Ok(v) = env::var("CIBA_AUTHORIZATION_DETAILS_TYPE") {
            config.authorization_details_type = v.trim().to_string();
        }
        config.requested_expiry = number("CIBA_REQUESTED_EXPIRY", config.requested_expiry);
        config.poll_interval = number("CIBA_POLL_INTERVAL", config.poll_interval);
        config.hold_seconds = number("CIBA_HOLD_SECONDS", config.hold_seconds);
        config.table_ttl_seconds = number("CIBA_TABLE_TTL_SECONDS", config.table_ttl_seconds);
        config.http_timeout_secs = number("CIBA_HTTP_TIMEOUT", config.http_timeout_secs);
        config.validate();
        Some(config)
    }

    /// Panics on a configuration the provider would reject.
    pub fn validate(&self) {
        // Binding messages are <prefix>-<4 digits>.
        let longest = self.binding_message_prefix.len() + 5;
        let max = self.provider.binding_message_max();
        assert!(
            longest <= max,
            "CIBA_BINDING_MESSAGE_PREFIX is too long: {:?} allows {max} characters in the binding message",
            self.provider
        );
        assert!(
            !self.approval_header.is_empty() && !self.approver_header.is_empty(),
            "CIBA_APPROVAL_HEADER and CIBA_APPROVER_HEADER must not be empty"
        );
    }

    /// How approvals are tied to requests with this configuration.
    pub fn request_binding(&self) -> RequestBinding {
        match self.provider {
            CibaProvider::PingFederate if !self.authorization_details_type.is_empty() => {
                RequestBinding::AuthorizationDetails
            }
            _ => RequestBinding::Table,
        }
    }

    /// Lifetime of a table item, in seconds: never shorter than an approval could
    /// live, so a spent record can't disappear while the provider would still
    /// redeem its `auth_req_id`.
    pub fn item_lifetime(&self) -> u64 {
        self.table_ttl_seconds.max(self.requested_expiry)
    }
}

/// Returns the User-Agent string: "aws-bedrock-gateway-authorizer/<version>"
pub fn user_agent() -> String {
    format!(
        "aws-bedrock-gateway-authorizer/{}",
        env!("CARGO_PKG_VERSION")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_agent_has_expected_format() {
        let ua = user_agent();
        assert!(ua.starts_with("aws-bedrock-gateway-authorizer/"));
        // Package version, whatever it currently is (e.g. "0.1.1").
        assert!(ua
            .split('/')
            .nth(1)
            .is_some_and(|v| v.chars().next().is_some_and(|c| c.is_ascii_digit())));
    }

    #[test]
    fn config_new_loads_values() {
        let config = Config::new(
            "https://example.com/v1/environments/test".to_string(),
            "test-secret".to_string(),
            AuthErrorMode::Http,
        );
        assert_eq!(
            config.service_url,
            "https://example.com/v1/environments/test"
        );
        assert_eq!(config.secret_header_value, "test-secret");
        assert_eq!(config.auth_error_mode, AuthErrorMode::Http);
    }

    #[test]
    fn auth_error_mode_parse_jsonrpc() {
        assert_eq!(AuthErrorMode::parse("jsonrpc"), AuthErrorMode::JsonRpc);
    }

    #[test]
    fn auth_error_mode_parse_empty_value_is_default_http() {
        assert_eq!(AuthErrorMode::parse(""), AuthErrorMode::Http);
    }

    #[test]
    #[should_panic(expected = "Invalid AUTH_ERROR_MODE")]
    fn auth_error_mode_parse_invalid_value_panics() {
        AuthErrorMode::parse("bogus");
    }

    #[test]
    #[should_panic(expected = "Invalid AUTH_ERROR_MODE")]
    fn auth_error_mode_parse_is_case_sensitive() {
        AuthErrorMode::parse("JSONRPC");
    }

    fn ciba(provider: CibaProvider) -> CibaConfig {
        CibaConfig::new(
            provider,
            "https://idp.test/ciba".to_string(),
            "https://idp.test/token".to_string(),
            "client".to_string(),
            "secret".to_string(),
            "table".to_string(),
        )
    }

    #[test]
    fn ciba_provider_parse() {
        assert_eq!(CibaProvider::parse(""), CibaProvider::PingFederate);
        assert_eq!(CibaProvider::parse("PingOne"), CibaProvider::PingOne);
        assert_eq!(CibaProvider::parse(" pingfederate "), CibaProvider::PingFederate);
    }

    #[test]
    #[should_panic(expected = "Invalid CIBA_PROVIDER")]
    fn ciba_provider_parse_unknown_panics() {
        CibaProvider::parse("okta");
    }

    #[test]
    fn request_binding_follows_provider_and_details_type() {
        assert_eq!(
            ciba(CibaProvider::PingFederate).request_binding(),
            RequestBinding::AuthorizationDetails
        );
        assert_eq!(ciba(CibaProvider::PingOne).request_binding(), RequestBinding::Table);
        let mut no_rar = ciba(CibaProvider::PingFederate);
        no_rar.authorization_details_type.clear();
        assert_eq!(no_rar.request_binding(), RequestBinding::Table);
    }

    #[test]
    fn default_binding_message_fits_pingone() {
        ciba(CibaProvider::PingOne).validate();
    }

    #[test]
    #[should_panic(expected = "CIBA_BINDING_MESSAGE_PREFIX is too long")]
    fn long_prefix_is_rejected_for_pingone() {
        let mut config = ciba(CibaProvider::PingOne);
        config.binding_message_prefix = "APPROVE".to_string();
        config.validate();
    }

    #[test]
    fn item_lifetime_never_below_requested_expiry() {
        let mut config = ciba(CibaProvider::PingOne);
        config.table_ttl_seconds = 60;
        assert_eq!(config.item_lifetime(), 180);
        config.table_ttl_seconds = 86400;
        assert_eq!(config.item_lifetime(), 86400);
    }

    // Note: from_env() tests that depend on env vars are not included here because
    // Rust tests run in parallel within the same process and env vars are global
    // state. The from_env() path is exercised in the Lambda entrypoint and is
    // straightforward (just two env::var calls with .expect()).
}
