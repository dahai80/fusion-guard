// client.rs — multi-node HTTP 客户端 (issue #52 跨节点 TRANSPORT 消费方)。
//
// 连 fusion-multi-node master HTTP API (本地/LAN, 无云):
//   GET  /api/v1/audit/chain?since_seq=N     — 拉审计链段
//   GET  /api/v1/rules/epoch                 — 查集群规则纪元
//   POST /api/v1/rules/epoch/advance         — 推进纪元 (leader-only, ADMIN)
//   POST /api/confirm                         — confirm 中继 (MAC 鉴集群成员)
//   GET  /api/v1/confirms?epoch=N            — 查 confirm 聚合
// 鉴权: Bearer cluster_token (集群令牌, env 注入)。5s 超时。
//
// 阻塞客户端 (reqwest::blocking) — fg-ipc handle_method 跑在 spawn_blocking 独立线程,
// 非 tokio worker, 故阻塞 IO 安全 (不会卡异步运行时)。失败 fail-closed: 网络错/非 2xx → Err。

use crate::key::{canonical_json, derive_confirm_relay_key, mac_payload};
use crate::{
    AuditChainResponse, ConfirmListResponse, ConfirmPayload, ConfirmRelayRequest,
    ConfirmRelayResponse, RuleEpochAdvanceRequest, RuleEpochResponse,
};
use reqwest::blocking::Client;
use std::time::Duration;

const TIMEOUT_SECS: u64 = 5;

// 集群消费方配置 — master 地址 + cluster_token (env FUSION_GUARD_CLUSTER_TOKEN 或注入)。
#[derive(Debug, Clone)]
pub struct ClusterConfig {
    pub master_host: String,
    pub master_port: u16,
    pub cluster_token: String,
}

impl ClusterConfig {
    // 从 env 构造 (FUSION_GUARD_CLUSTER_TOKEN + FUSION_GUARD_CLUSTER_MASTER_HOST/PORT)。
    // token 缺失 → None (单节点模式, 不消费跨节点原语)。
    pub fn from_env() -> Option<Self> {
        let token = std::env::var("FUSION_GUARD_CLUSTER_TOKEN").ok()?;
        if token.is_empty() {
            return None;
        }
        let host = std::env::var("FUSION_GUARD_CLUSTER_MASTER_HOST")
            .unwrap_or_else(|_| "127.0.0.1".to_string());
        let port: u16 = std::env::var("FUSION_GUARD_CLUSTER_MASTER_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(11450);
        Some(Self {
            master_host: host,
            master_port: port,
            cluster_token: token,
        })
    }
}

// multi-node HTTP 客户端 — 持久 reqwest::blocking::Client (连接池复用)。
#[derive(Debug, Clone)]
pub struct ClusterClient {
    cfg: ClusterConfig,
    http: Client,
}

#[derive(Debug, thiserror::Error)]
pub enum ClusterError {
    #[error("cluster transport: {0}")]
    Transport(String),
    #[error("cluster HTTP {status}: {body}")]
    HttpStatus { status: u16, body: String },
    #[error("cluster response decode: {0}")]
    Decode(String),
}

impl ClusterClient {
    pub fn new(cfg: ClusterConfig) -> Result<Self, ClusterError> {
        let http = Client::builder()
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .build()
            .map_err(|e| ClusterError::Transport(format!("reqwest build: {e}")))?;
        Ok(Self { cfg, http })
    }

    // 借配置 (IPC 需读 cluster_token 派生 audit-chain 密钥做本地链验证)。
    pub fn cfg_ref(&self) -> &ClusterConfig {
        &self.cfg
    }

    fn url(&self, path: &str) -> String {
        format!(
            "http://{}:{}{}",
            self.cfg.master_host, self.cfg.master_port, path
        )
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.cfg.cluster_token)
    }

    fn decode_resp<T: serde::de::DeserializeOwned>(
        resp: reqwest::blocking::Response,
    ) -> Result<T, ClusterError> {
        let status = resp.status().as_u16();
        let body = resp
            .text()
            .map_err(|e| ClusterError::Decode(format!("read body: {e}")))?;
        if !(200..300).contains(&status) {
            return Err(ClusterError::HttpStatus { status, body });
        }
        serde_json::from_str(&body).map_err(|e| ClusterError::Decode(format!("decode: {e}")))
    }

    // 原语 1 — 拉审计链段 (since_seq 过滤, seq>=N 或无 seq 基线记录)。
    pub fn fetch_audit_chain(&self, since_seq: u64) -> Result<AuditChainResponse, ClusterError> {
        let url = format!(
            "{}?since_seq={}",
            self.url("/api/v1/audit/chain"),
            since_seq
        );
        let resp = self
            .http
            .get(&url)
            .header("Authorization", self.auth_header())
            .send()
            .map_err(|e| ClusterError::Transport(format!("GET audit/chain: {e}")))?;
        let result: AuditChainResponse = Self::decode_resp(resp)?;
        tracing::info!(node_id = %result.node_id, records = result.records.len(), "cluster audit/chain fetched");
        Ok(result)
    }

    // 原语 2 — 查集群规则纪元 (master 内存态, 重启归零)。
    pub fn get_rule_epoch(&self) -> Result<RuleEpochResponse, ClusterError> {
        let resp = self
            .http
            .get(self.url("/api/v1/rules/epoch"))
            .header("Authorization", self.auth_header())
            .send()
            .map_err(|e| ClusterError::Transport(format!("GET rules/epoch: {e}")))?;
        Self::decode_resp(resp)
    }

    // 原语 2 — 推进集群规则纪元 (leader-only, 非 leader 返 409)。
    pub fn advance_rule_epoch(&self, reason: &str) -> Result<RuleEpochResponse, ClusterError> {
        let req = RuleEpochAdvanceRequest {
            reason: reason.to_string(),
        };
        let resp = self
            .http
            .post(self.url("/api/v1/rules/epoch/advance"))
            .header("Authorization", self.auth_header())
            .json(&req)
            .send()
            .map_err(|e| ClusterError::Transport(format!("POST epoch/advance: {e}")))?;
        Self::decode_resp(resp)
    }

    // 原语 3 — confirm 中继到 master 聚合 (构 MAC, 鉴集群成员身份)。
    pub fn relay_confirm(
        &self,
        confirm_id: &str,
        node_id: &str,
        action: &str,
        epoch: u64,
        ts: &str,
    ) -> Result<ConfirmRelayResponse, ClusterError> {
        let key = derive_confirm_relay_key(&self.cfg.cluster_token);
        // MAC 签名输入 = ConfirmPayload 减 mac (canonical)。
        let payload = ConfirmPayload {
            confirm_id: confirm_id.to_string(),
            node_id: node_id.to_string(),
            action: action.to_string(),
            epoch,
            ts: ts.to_string(),
        };
        let canon =
            canonical_json(&serde_json::to_value(&payload).unwrap_or(serde_json::Value::Null));
        let mac = mac_payload(&key, &canon);
        let req = ConfirmRelayRequest {
            confirm_id: confirm_id.to_string(),
            node_id: node_id.to_string(),
            action: action.to_string(),
            epoch,
            ts: ts.to_string(),
            mac,
        };
        let resp = self
            .http
            .post(self.url("/api/confirm"))
            .header("Authorization", self.auth_header())
            .json(&req)
            .send()
            .map_err(|e| ClusterError::Transport(format!("POST confirm: {e}")))?;
        let result: ConfirmRelayResponse = Self::decode_resp(resp)?;
        tracing::info!(confirm_id, node_id, status = %result.status, "cluster confirm relayed");
        Ok(result)
    }

    // 原语 3 — 查 confirm 聚合 (可按 epoch 过滤)。
    pub fn list_confirms(&self, epoch: Option<u64>) -> Result<ConfirmListResponse, ClusterError> {
        let url = match epoch {
            Some(e) => format!("{}?epoch={}", self.url("/api/v1/confirms"), e),
            None => self.url("/api/v1/confirms"),
        };
        let resp = self
            .http
            .get(&url)
            .header("Authorization", self.auth_header())
            .send()
            .map_err(|e| ClusterError::Transport(format!("GET confirms: {e}")))?;
        Self::decode_resp(resp)
    }
}
