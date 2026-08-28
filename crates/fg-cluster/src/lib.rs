// fg-cluster — fusion-guard 跨节点消费方 (issue #4 / multi-nodes#52 契约)。
//
// 多节点 (fusion-multi-node PR #54) 定义 TRANSPORT + IDENTITY + KEY SCHEME:
//   - HKDF-SHA256 从 cluster_token 域分离派生 3 个 MAC 密钥 (audit-chain/rule-epoch/confirm-relay)
//   - HTTP API: GET /api/v1/audit/chain, GET/POST /api/v1/rules/epoch, POST /api/confirm, GET /api/v1/confirms
// guard 实现消费方: federated 链验证 / RuleSet epoch reconcile / confirm 中继聚合。
//
// 层边界: guard 仅消费, 不定义集群协议 (PRD §4.1/§8.2 per-host 设计, 多节点 brokering)。
// 100% 本地/LAN, 无云。密钥不新增独立秘密 — cluster_token 已是集群根信源 (env 注入)。

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

// issue #52 原语 1 — 审计链段记录 (multi-node audit_log.py 写出形, JSON 反序列化)。
// 链字段: seq 单调 / prev_hash 链接含 mac 的完整前序记录 sha256 / mac = HMAC over (record 减 mac)。
// 无链字段 (降级基线): seq/prev_hash/mac 缺失, guard 视为基线记录不参与链校验。
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

// GET /api/v1/audit/chain?since_seq=N 响应 (V1AuditChainResponse)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditChainResponse {
    pub node_id: String,
    pub records: Vec<AuditChainRecord>,
    pub fetched_at: String,
    #[serde(default)]
    pub truncated: bool,
}

// GET /api/v1/rules/epoch + POST /api/v1/rules/epoch/advance 响应 (V1RuleEpochResponse)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleEpochResponse {
    pub epoch: u64,
    #[serde(default)]
    pub advanced_at: String,
}

// POST /api/v1/rules/epoch/advance 请求 (RuleEpochAdvanceRequest)。
#[derive(Debug, Clone, Serialize)]
pub struct RuleEpochAdvanceRequest {
    #[serde(default)]
    pub reason: String,
}

// POST /api/confirm 请求 (ConfirmRelayRequest) — guard 构 MAC 后发。
#[derive(Debug, Clone, Serialize)]
pub struct ConfirmRelayRequest {
    pub confirm_id: String,
    pub node_id: String,
    pub action: String,
    pub epoch: u64,
    pub ts: String,
    pub mac: String,
}

// confirm 中继请求载荷 (减 mac) — MAC 签名输入, 须确定性 (与 multi-node canonical_json 同算法)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmPayload {
    pub confirm_id: String,
    pub node_id: String,
    pub action: String,
    pub epoch: u64,
    pub ts: String,
}

// GET /api/v1/confirms?epoch=N 响应 (V1ConfirmListResponse)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmListResponse {
    pub confirms: Vec<serde_json::Value>,
    #[serde(default)]
    pub count: usize,
}

// POST /api/confirm 响应 (receive_confirm 返): {status, confirm_id, node_id} 或 {status:"rejected", reason}。
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
