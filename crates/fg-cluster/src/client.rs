// client.rs — multi-node HTTP client (issue #52 cross-node TRANSPORT consumer).
//
// Connects to the fusion-multi-node master HTTP API (local/LAN, no cloud):
//   GET  /api/v1/audit/chain?since_seq=N     — fetch audit chain segment
//   GET  /api/v1/rules/epoch                 — query cluster rule epoch
//   POST /api/v1/rules/epoch/advance         — advance epoch (leader-only, ADMIN)
//   POST /api/confirm                        — confirm relay (MAC authenticates cluster membership)
//   GET  /api/v1/confirms?epoch=N            — query confirm aggregation
// Auth: Bearer cluster_token (cluster token, env injected). 5s timeout.
//
// Blocking client (reqwest::blocking) — fg-ipc handle_method runs on a dedicated spawn_blocking thread,
// not a tokio worker, so blocking IO is safe (does not stall the async runtime). Fail-closed on failure: network error/non-2xx → Err.

use crate::key::{canonical_json, derive_confirm_relay_key, mac_payload};
use crate::{
    AuditChainResponse, ConfirmListResponse, ConfirmPayload, ConfirmRelayRequest,
    ConfirmRelayResponse, RuleEpochAdvanceRequest, RuleEpochResponse,
};
use reqwest::blocking::Client;
use std::time::Duration;

const TIMEOUT_SECS: u64 = 5;

// Cluster consumer config — master address + cluster_token (env FUSION_GUARD_CLUSTER_TOKEN or injected).
#[derive(Debug, Clone)]
pub struct ClusterConfig {
    pub master_host: String,
    pub master_port: u16,
    pub cluster_token: String,
}

impl ClusterConfig {
    // Build from env (FUSION_GUARD_CLUSTER_TOKEN + FUSION_GUARD_CLUSTER_MASTER_HOST/PORT).
    // Missing token → None (single-node mode, no cross-node primitive consumption).
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

// multi-node HTTP client — persistent reqwest::blocking::Client (connection pool reuse).
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

    // Borrow the config (IPC needs cluster_token to derive the audit-chain key for local chain verification).
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

    // Primitive 1 — fetch audit chain segment (since_seq filter, seq>=N or baseline records without seq).
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

    // Primitive 2 — query cluster rule epoch (master in-memory state, resets on restart).
    pub fn get_rule_epoch(&self) -> Result<RuleEpochResponse, ClusterError> {
        let resp = self
            .http
            .get(self.url("/api/v1/rules/epoch"))
            .header("Authorization", self.auth_header())
            .send()
            .map_err(|e| ClusterError::Transport(format!("GET rules/epoch: {e}")))?;
        Self::decode_resp(resp)
    }

    // Primitive 2 — advance cluster rule epoch (leader-only, non-leader returns 409).
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

    // Primitive 3 — relay confirm to master aggregation (builds MAC, authenticates cluster membership).
    pub fn relay_confirm(
        &self,
        confirm_id: &str,
        node_id: &str,
        action: &str,
        epoch: u64,
        ts: &str,
    ) -> Result<ConfirmRelayResponse, ClusterError> {
        let key = derive_confirm_relay_key(&self.cfg.cluster_token);
        // MAC signing input = ConfirmPayload minus mac (canonical).
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

    // Primitive 3 — query confirm aggregation (optionally filtered by epoch).
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
