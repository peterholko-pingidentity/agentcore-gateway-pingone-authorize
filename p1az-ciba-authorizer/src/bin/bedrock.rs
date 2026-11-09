use aws_bedrock_lambda_authorizer::{
    ciba::Ciba,
    config::{self, CibaConfig, Config},
    handlers::bedrock::{self, BedrockResponse},
    sideband_client::SidebandClient,
};
use lambda_runtime::{service_fn, tracing, Error, LambdaEvent};

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing::init_default_subscriber();

    // Config validation happens here -- panics on missing required vars and on
    // an invalid AUTH_ERROR_MODE. This is intentional: fail at init, not
    // per-invocation.
    let config = Config::from_env();

    // Create HTTP client once -- reused across all invocations (connection pooling).
    let client = SidebandClient::new(&config);

    // Copy the mode out -- it's Copy, so the closure can own it without
    // borrowing `config`.
    let auth_error_mode = config.auth_error_mode;

    // The CIBA approval flow (this fork), when CIBA_AUTHORIZATION_ENDPOINT is
    // set. Panics on a partial or invalid CIBA configuration, like Config::from_env.
    let ciba = CibaConfig::from_env().map(Ciba::with_dynamodb);
    if let Some(ciba) = &ciba {
        tracing::info!(
            provider = ?ciba.config.provider,
            request_binding = ?ciba.config.request_binding(),
            "CIBA approval flow enabled"
        );
    }
    // (fork) RESPONSE_AUTHORIZATION=off: no x-paz-state carrier, responses pass through.
    let response_authorization = config::response_authorization_from_env();
    if !response_authorization {
        tracing::info!("Response authorization off: responses pass through unauthorized");
    }

    // Accept the raw JSON value so we can trace the full event before
    // attempting deserialization. All logging is in handle_request (library
    // crate) so that RUST_LOG=aws_bedrock_lambda_authorizer=trace works.
    lambda_runtime::run(service_fn(|event: LambdaEvent<serde_json::Value>| {
        let client_ref = &client;
        let ciba_ref = ciba.as_ref();
        async move {
            let (raw_event, _context) = event.into_parts();
            let mut response =
                bedrock::handle_request_with_ciba(raw_event, client_ref, auth_error_mode, ciba_ref).await;
            if !response_authorization {
                bedrock::drop_state_carrier(&mut response);
            }
            Ok::<BedrockResponse, Error>(response)
        }
    }))
    .await
}
