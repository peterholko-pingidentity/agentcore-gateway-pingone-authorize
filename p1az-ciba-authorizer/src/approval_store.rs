//! CIBA approval state in DynamoDB (this fork's addition).
//!
//! The table has a string partition key `pk` and TTL on `ttl`. It holds two
//! kinds of items, keyed by SHA-256 of the provider's `auth_req_id`:
//!
//! - `spent#<hash>`: written once, conditionally, when an approved replay is
//!   permitted, so each approval is used exactly once.
//! - `request#<hash>`: written when an approval starts, with table request
//!   binding (PingOne), recording which request and caller it was issued for.
//!
//! DynamoDB is called through its JSON API over `reqwest`, signed with SigV4
//! using the credentials Lambda puts in the environment, rather than through the
//! full AWS SDK -- the authorizer stays as small as upstream.

use crate::config::CibaConfig;
use aws_credential_types::Credentials;
use aws_sigv4::http_request::{sign, SignableBody, SignableRequest, SigningSettings};
use aws_sigv4::sign::v4;
use aws_smithy_runtime_api::client::identity::Identity;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::debug;

/// A failed table call; callers fail closed.
#[derive(thiserror::Error, Debug)]
#[error("CIBA table error: {0}")]
pub struct StoreError(pub String);

/// An item's attributes as strings (numbers included).
pub type Item = HashMap<String, String>;

/// Where approval state lives.
pub enum ApprovalStore {
    DynamoDb(DynamoDbStore),
    /// In-memory store for tests and local runs.
    Memory(MemoryStore),
}

impl ApprovalStore {
    /// DynamoDB store for the configured table, region and endpoint.
    pub fn dynamodb(config: &CibaConfig) -> Self {
        ApprovalStore::DynamoDb(DynamoDbStore {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(config.http_timeout_secs))
                .build()
                .expect("HTTP client for DynamoDB"),
            endpoint: config.dynamodb_endpoint.clone(),
            region: config.region.clone(),
            table: config.table.clone(),
            lifetime: config.item_lifetime(),
        })
    }

    pub fn memory(lifetime: u64) -> Self {
        ApprovalStore::Memory(MemoryStore {
            items: Mutex::new(HashMap::new()),
            writes: Mutex::new(Vec::new()),
            fail: AtomicBool::new(false),
            lifetime,
        })
    }

    /// Read an item with a consistent read; `None` when it doesn't exist.
    pub async fn get(&self, key: &str) -> Result<Option<Item>, StoreError> {
        match self {
            ApprovalStore::DynamoDb(store) => store.get(key).await,
            ApprovalStore::Memory(store) => store.get(key),
        }
    }

    /// Write an item, replacing any existing one.
    pub async fn put(&self, key: &str, attributes: &[(&str, &str)]) -> Result<(), StoreError> {
        match self {
            ApprovalStore::DynamoDb(store) => store.put(key, attributes, false).await.map(|_| ()),
            ApprovalStore::Memory(store) => store.put(key, attributes, false).map(|_| ()),
        }
    }

    /// Write an item unless one exists; `Ok(false)` when another request got there first.
    pub async fn put_if_absent(&self, key: &str, attributes: &[(&str, &str)]) -> Result<bool, StoreError> {
        match self {
            ApprovalStore::DynamoDb(store) => store.put(key, attributes, true).await,
            ApprovalStore::Memory(store) => store.put(key, attributes, true),
        }
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// The attributes every item gets besides its own: `created_at` and `ttl`.
fn timestamps(lifetime: u64) -> (u64, u64) {
    let created = now();
    (created, created + lifetime)
}

pub struct DynamoDbStore {
    http: reqwest::Client,
    endpoint: String,
    region: String,
    table: String,
    lifetime: u64,
}

impl DynamoDbStore {
    async fn get(&self, key: &str) -> Result<Option<Item>, StoreError> {
        let body = json!({"TableName": self.table, "Key": {"pk": {"S": key}}, "ConsistentRead": true});
        let response = self.call("GetItem", &body).await?;
        let Some(Value::Object(item)) = response.get("Item") else {
            return Ok(None);
        };
        Ok(Some(
            item.iter()
                .filter_map(|(name, value)| {
                    let value = value.get("S").or_else(|| value.get("N"))?.as_str()?;
                    Some((name.clone(), value.to_string()))
                })
                .collect(),
        ))
    }

    async fn put(&self, key: &str, attributes: &[(&str, &str)], if_absent: bool) -> Result<bool, StoreError> {
        let (created, ttl) = timestamps(self.lifetime);
        let mut item = Map::new();
        item.insert("pk".into(), json!({"S": key}));
        item.insert("created_at".into(), json!({"N": created.to_string()}));
        item.insert("ttl".into(), json!({"N": ttl.to_string()}));
        for (name, value) in attributes {
            item.insert((*name).into(), json!({"S": value}));
        }
        let mut body = json!({"TableName": self.table, "Item": item});
        if if_absent {
            body["ConditionExpression"] = json!("attribute_not_exists(pk)");
        }
        match self.call("PutItem", &body).await {
            Ok(_) => Ok(true),
            Err(StoreError(message)) if if_absent && message.contains("ConditionalCheckFailedException") => {
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// POST one DynamoDB JSON API operation, signed with SigV4.
    async fn call(&self, operation: &str, body: &Value) -> Result<Value, StoreError> {
        let payload = serde_json::to_vec(body).map_err(|e| StoreError(e.to_string()))?;
        let target = format!("DynamoDB_20120810.{operation}");
        let host = self
            .endpoint
            .split("://")
            .nth(1)
            .unwrap_or(&self.endpoint)
            .trim_end_matches('/')
            .to_string();
        let mut headers = vec![
            ("host".to_string(), host),
            ("content-type".to_string(), "application/x-amz-json-1.0".to_string()),
            ("x-amz-target".to_string(), target),
        ];
        headers.extend(self.signature(&headers, &payload)?);

        let mut request = self.http.post(&self.endpoint).body(payload);
        for (name, value) in &headers {
            if name != "host" {
                request = request.header(name.as_str(), value.as_str());
            }
        }
        let response = request.send().await.map_err(|e| StoreError(e.to_string()))?;
        let status = response.status().as_u16();
        let text = response.text().await.map_err(|e| StoreError(e.to_string()))?;
        debug!(operation = operation, status = status, "DynamoDB response");
        if status != 200 {
            return Err(StoreError(format!("DynamoDB {operation} returned HTTP {status}: {text}")));
        }
        serde_json::from_str(&text).map_err(|e| StoreError(e.to_string()))
    }

    /// SigV4 headers (`authorization`, `x-amz-date`, `x-amz-security-token`) for
    /// the request, with the credentials Lambda provides in the environment.
    fn signature(&self, headers: &[(String, String)], payload: &[u8]) -> Result<Vec<(String, String)>, StoreError> {
        let var = |name: &str| std::env::var(name).map_err(|_| StoreError(format!("{name} is not set")));
        let identity: Identity = Credentials::from_keys(
            var("AWS_ACCESS_KEY_ID")?,
            var("AWS_SECRET_ACCESS_KEY")?,
            std::env::var("AWS_SESSION_TOKEN").ok(),
        )
        .into();
        let params = v4::SigningParams::builder()
            .identity(&identity)
            .region(&self.region)
            .name("dynamodb")
            .time(SystemTime::now())
            .settings(SigningSettings::default())
            .build()
            .map_err(|e| StoreError(e.to_string()))?
            .into();
        let signable = SignableRequest::new(
            "POST",
            &self.endpoint,
            headers.iter().map(|(k, v)| (k.as_str(), v.as_str())),
            SignableBody::Bytes(payload),
        )
        .map_err(|e| StoreError(e.to_string()))?;
        let (instructions, _signature) = sign(signable, &params)
            .map_err(|e| StoreError(e.to_string()))?
            .into_parts();
        Ok(instructions
            .headers()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect())
    }
}

pub struct MemoryStore {
    items: Mutex<HashMap<String, Item>>,
    /// Keys written, in order (tests check what was recorded).
    pub writes: Mutex<Vec<String>>,
    /// When set, every call fails (tests check fail-closed paths).
    pub fail: AtomicBool,
    lifetime: u64,
}

impl MemoryStore {
    fn check(&self) -> Result<(), StoreError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(StoreError("memory store set to fail".to_string()));
        }
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<Item>, StoreError> {
        self.check()?;
        Ok(self.items.lock().unwrap().get(key).cloned())
    }

    fn put(&self, key: &str, attributes: &[(&str, &str)], if_absent: bool) -> Result<bool, StoreError> {
        self.check()?;
        let mut items = self.items.lock().unwrap();
        self.writes.lock().unwrap().push(key.to_string());
        if if_absent && items.contains_key(key) {
            return Ok(false);
        }
        let (created, ttl) = timestamps(self.lifetime);
        let mut item: Item = attributes.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        item.insert("created_at".into(), created.to_string());
        item.insert("ttl".into(), ttl.to_string());
        items.insert(key.to_string(), item);
        Ok(true)
    }

    /// Insert an item directly (tests simulate another request's write).
    pub fn insert(&self, key: &str, attributes: &[(&str, &str)]) {
        let item = attributes.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        self.items.lock().unwrap().insert(key.to_string(), item);
    }

    pub fn item(&self, key: &str) -> Option<Item> {
        self.items.lock().unwrap().get(key).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_put_if_absent_reports_a_lost_race() {
        let store = ApprovalStore::memory(300);
        assert!(store.put_if_absent("k", &[("a", "1")]).await.unwrap());
        assert!(!store.put_if_absent("k", &[("a", "2")]).await.unwrap());
        let item = store.get("k").await.unwrap().unwrap();
        assert_eq!(item["a"], "1");
        let ttl: u64 = item["ttl"].parse().unwrap();
        let created: u64 = item["created_at"].parse().unwrap();
        assert_eq!(ttl - created, 300);
    }

    #[tokio::test]
    async fn memory_store_can_fail() {
        let store = ApprovalStore::memory(300);
        if let ApprovalStore::Memory(m) = &store {
            m.fail.store(true, Ordering::SeqCst);
        }
        assert!(store.get("k").await.is_err());
        assert!(store.put("k", &[]).await.is_err());
    }
}
