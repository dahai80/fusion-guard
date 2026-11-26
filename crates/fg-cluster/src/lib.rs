// fg-cluster — fusion-guard cross-node consumer (issue #4 / multi-nodes#52 contract).
//
// Multi-node (fusion-multi-node PR #54) defines TRANSPORT + IDENTITY + KEY SCHEME:
//   - HKDF-SHA256 derives 3 domain-separated MAC keys from cluster_token (audit-chain/rule-epoch/confirm-relay)
//   - HTTP API: GET /api/v1/audit/chain, GET/POST /api/v1/rules/epoch, POST /api/confirm, GET /api/v1/confirms
// guard implements the consumer side: federated chain verification / RuleSet epoch reconcile / confirm relay aggregation.
//
// Layer boundary: guard only consumes, does not define the cluster protocol (PRD §4.1/§8.2 per-host design, multi-node brokering).
// 100% local/LAN, no cloud. No new independent secret — cluster_token is already the cluster root of trust (env injected).

use serde::{Deserialize, Serialize};

pub mod client;
pub mod key;
pub mod verify;

pub use client::{ClusterClient, ClusterConfig};
pub use key::{
    canonical_json, derive_audit_chain_key, derive_confirm_relay_key, derive_rule_epoch_key,
    mac_payload, verify_mac,
};
pub use verify::{verify_chain_segment, ChainVerifyResult};

// issue #52 primitive 1 — audit chain segment record (multi-node audit_log.py wire shape, JSON deserialization).
// Chain fields: seq monotonic / prev_hash links sha256 of the full previous record including mac / mac = HMAC over (record minus mac).
// No chain fields (degraded baseline): seq/prev_hash/mac missing, guard treats it as a baseline record excluded from chain verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditChainRecord {
    pub ts: String,
    pub actor: String,
    pub action: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub result: String,
    #[serde(default)]
    pub detail: String,
    #[serde(default)]
    pub seq: Option<u64>,
    #[serde(default)]
    pub prev_hash: Option<String>,
    #[serde(default)]
    pub mac: Option<String>,
}

// GET /api/v1/audit/chain?since_seq=N response (V1AuditChainResponse).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditChainResponse {
    pub node_id: String,
    pub records: Vec<AuditChainRecord>,
    pub fetched_at: String,
    #[serde(default)]
    pub truncated: bool,
}

// GET /api/v1/rules/epoch + POST /api/v1/rules/epoch/advance response (V1RuleEpochResponse).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleEpochResponse {
    pub epoch: u64,
    #[serde(default)]
    pub advanced_at: String,
}

// POST /api/v1/rules/epoch/advance request (RuleEpochAdvanceRequest).
#[derive(Debug, Clone, Serialize)]
pub struct RuleEpochAdvanceRequest {
    #[serde(default)]
    pub reason: String,
}

// POST /api/confirm request (ConfirmRelayRequest) — guard builds the MAC then sends.
#[derive(Debug, Clone, Serialize)]
pub struct ConfirmRelayRequest {
    pub confirm_id: String,
    pub node_id: String,
    pub action: String,
    pub epoch: u64,
    pub ts: String,
    pub mac: String,
}

// confirm relay request payload (minus mac) — MAC signing input, must be deterministic (same algorithm as multi-node canonical_json).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmPayload {
    pub confirm_id: String,
    pub node_id: String,
    pub action: String,
    pub epoch: u64,
    pub ts: String,
}

// GET /api/v1/confirms?epoch=N response (V1ConfirmListResponse).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmListResponse {
    pub confirms: Vec<serde_json::Value>,
    #[serde(default)]
    pub count: usize,
}

// POST /api/confirm response (receive_confirm return): {status, confirm_id, node_id} or {status:"rejected", reason}.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmRelayResponse {
    pub status: String,
    #[serde(default)]
    pub confirm_id: String,
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub epoch: u64,
}
