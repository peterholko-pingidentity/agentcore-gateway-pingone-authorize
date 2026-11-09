use crate::config::{self, Config};
use crate::models::{
    AuthorizerError, InboundRequest, InboundRequestResult, OutboundResponse, OutboundResponseResult,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tracing::{debug, trace, warn};

/// HTTP client for PingOne Authorize sideband API calls.
///
/// This struct should be created ONCE in `main()` and reused across all Lambda
/// invocations to benefit from connection pooling and keep-alive.
pub struct SidebandClient {
    http_client: reqwest::Client,
    service_url: String,
    secret_header_value: String,
}

impl SidebandClient {
    /// Create a new sideband client from the given configuration.
    ///
    /// The `reqwest::Client` is created here with connection pooling and
    /// keep-alive enabled by default.
    pub fn new(config: &Config) -> Self {
        let http_client = reqwest::Client::new();
        SidebandClient {
            http_client,
            service_url: config.service_url.clone(),
            secret_header_value: config.secret_header_value.clone(),
        }
    }

    /// Send an `InboundRequest` to PingOne Authorize and return the parsed result.
    ///
    /// # Logging
    /// - `TRACE`: Full request body before sending, full response body after receiving
    /// - `DEBUG`: URL, method, response status, timing
    /// - `WARN`: On 4xx/5xx responses from P1AZ
    ///
    /// # Returns
    /// - `Ok(InboundRequestResult)` on P1AZ HTTP 200
    /// - `Err(AuthorizerError::SidebandHttp)` on P1AZ HTTP 4xx/5xx
    /// - `Err(AuthorizerError::Network)` on connection/transport errors
    /// - `Err(AuthorizerError::Json)` on response parse errors
    pub async fn send_inbound_request(
        &self,
        request: &InboundRequest,
    ) -> Result<InboundRequestResult, AuthorizerError> {
        self.post_sideband("/sideband/request", request).await
    }

    /// Send an `OutboundResponse` to PingOne Authorize and return the parsed result.
    ///
    /// Same logging/error semantics as [`Self::send_inbound_request`].
    pub async fn send_outbound_response(
        &self,
        response: &OutboundResponse,
    ) -> Result<OutboundResponseResult, AuthorizerError> {
        self.post_sideband("/sideband/response", response).await
    }

    /// POST a sideband request body to `{service_url}{path}` and parse the response.
    ///
    /// Shared by [`Self::send_inbound_request`] and [`Self::send_outbound_response`]
    /// -- both are a `Client-Token`-authenticated JSON POST with identical
    /// timing/logging and non-200 -> `SidebandHttp` error mapping.
    async fn post_sideband<B: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<R, AuthorizerError> {
        let url = format!("{}{}", self.service_url, path);
        let user_agent = config::user_agent();

        debug!(url = %url, method = "POST", "Sending sideband request");

        let request_body = serde_json::to_string(body)?;
        trace!(body = request_body, "Sideband request body");

        let start = std::time::Instant::now();

        let response = self
            .http_client
            .post(&url)
            .header("Client-Token", &self.secret_header_value)
            .header("Content-Type", "application/json")
            .header("User-Agent", &user_agent)
            .body(request_body)
            .send()
            .await?;

        let elapsed = start.elapsed();
        let status = response.status().as_u16();

        debug!(
            status = status,
            elapsed_ms = elapsed.as_millis() as u64,
            "Sideband response received"
        );

        if status != 200 {
            let body = response.text().await.unwrap_or_default();
            warn!(
                status = status,
                body = %body,
                "P1AZ returned non-200 status"
            );

            return Err(AuthorizerError::SidebandHttp {
                status,
                message: body,
            });
        }

        let body = response.text().await?;
        trace!(body = body, "Sideband response body");

        let result: R = serde_json::from_str(&body)?;
        Ok(result)
    }
}
