//! The DynamoDB approval store against a mock DynamoDB JSON endpoint: request
//! shape, SigV4 headers, item parsing, and conditional-write failures.

use aws_bedrock_lambda_authorizer::{
    approval_store::ApprovalStore,
    config::{CibaConfig, CibaProvider},
};
use serde_json::{json, Value};
use wiremock::matchers::{header, method};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn dynamodb_store(server: &MockServer) -> ApprovalStore {
    // Lambda provides these; this test binary is the only reader.
    std::env::set_var("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE");
    std::env::set_var("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
    std::env::set_var("AWS_SESSION_TOKEN", "session-token");
    let mut config = CibaConfig::new(
        CibaProvider::PingOne,
        "https://idp.test/ciba".into(),
        "https://idp.test/token".into(),
        "client".into(),
        "secret".into(),
        "acgw-ciba".into(),
    );
    config.region = "us-east-2".into();
    config.dynamodb_endpoint = server.uri();
    ApprovalStore::dynamodb(&config)
}

async fn last_request(server: &MockServer) -> (Value, wiremock::Request) {
    let request = server.received_requests().await.unwrap().pop().unwrap();
    (serde_json::from_slice(&request.body).unwrap(), request)
}

#[tokio::test]
async fn requests_are_signed_dynamodb_json_calls() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(header("x-amz-target", "DynamoDB_20120810.GetItem"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"Item": {
            "pk": {"S": "spent#x"}, "idempotency_key": {"S": "idem"}, "ttl": {"N": "123"}}})))
        .mount(&server)
        .await;
    let store = dynamodb_store(&server).await;

    let item = store.get("spent#x").await.unwrap().unwrap();
    assert_eq!(item["idempotency_key"], "idem");
    assert_eq!(item["ttl"], "123");

    let (body, request) = last_request(&server).await;
    assert_eq!(body, json!({"TableName": "acgw-ciba", "Key": {"pk": {"S": "spent#x"}}, "ConsistentRead": true}));
    let header = |name: &str| request.headers.get(name).map(|v| v.to_str().unwrap().to_string());
    assert_eq!(header("content-type").as_deref(), Some("application/x-amz-json-1.0"));
    assert_eq!(header("x-amz-security-token").as_deref(), Some("session-token"));
    assert!(header("x-amz-date").is_some());
    let authorization = header("authorization").unwrap();
    assert!(authorization.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"));
    assert!(authorization.contains("/us-east-2/dynamodb/aws4_request"));
    assert!(authorization.contains("x-amz-target"));
}

#[tokio::test]
async fn missing_items_and_writes() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(header("x-amz-target", "DynamoDB_20120810.GetItem"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(header("x-amz-target", "DynamoDB_20120810.PutItem"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    let store = dynamodb_store(&server).await;

    assert!(store.get("request#x").await.unwrap().is_none());
    assert!(store.put_if_absent("spent#x", &[("approver", "u1")]).await.unwrap());
    let (body, _) = last_request(&server).await;
    assert_eq!(body["ConditionExpression"], "attribute_not_exists(pk)");
    assert_eq!(body["Item"]["pk"], json!({"S": "spent#x"}));
    assert_eq!(body["Item"]["approver"], json!({"S": "u1"}));
    let created: u64 = body["Item"]["created_at"]["N"].as_str().unwrap().parse().unwrap();
    let ttl: u64 = body["Item"]["ttl"]["N"].as_str().unwrap().parse().unwrap();
    assert_eq!(ttl - created, 86400);

    store.put("request#x", &[("method", "tools/call")]).await.unwrap();
    let (body, _) = last_request(&server).await;
    assert!(body.get("ConditionExpression").is_none());
}

#[tokio::test]
async fn a_failed_condition_is_a_lost_race_and_other_errors_fail() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "__type": "com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException",
            "message": "The conditional request failed"})))
        .mount(&server)
        .await;
    let store = dynamodb_store(&server).await;
    assert!(!store.put_if_absent("spent#x", &[]).await.unwrap());
    // Without a condition, the same answer is an error.
    assert!(store.put("spent#x", &[]).await.is_err());

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "__type": "com.amazonaws.dynamodb.v20120810#ProvisionedThroughputExceededException"})))
        .mount(&server)
        .await;
    let store = dynamodb_store(&server).await;
    assert!(store.put_if_absent("spent#x", &[]).await.is_err());
    assert!(store.get("spent#x").await.is_err());
}
