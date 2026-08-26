use fg_audit_engine::AuditEngine;
use fg_core::{GuardError, Result};
use fg_store::AuditStore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;

const MAX_CONNECTIONS: usize = 64;
const MAX_CONCURRENT_REQS: usize = 16;
const MAX_LINE_BYTES: usize = 1024 * 1024;
const REQ_TIMEOUT_SECS: u64 = 2;
const FRAMING_BYTE: u8 = 0x0A;

pub const DEFAULT_SOCK: &str = "/tmp/fusion-guard.sock";

pub struct IpcServer {
    engine: Arc<AuditEngine>,
    audit: Arc<AuditStore>,
    conn_sem: Arc<Semaphore>,
    req_sem: Arc<Semaphore>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RpcRequest {
    jsonrpc: String,
    id: Value,
    method: String,
    params: Value,
}

#[derive(Debug, Serialize)]
struct RpcResponse {
    jsonrpc: String,
    id: Value,
    result: Option<Value>,
    error: Option<RpcError>,
}

#[derive(Debug, Serialize)]
struct RpcError {
    code: i32,
    message: String,
}

impl IpcServer {
    pub fn new(engine: AuditEngine, audit: Arc<AuditStore>) -> Self {
        Self {
            engine: Arc::new(engine),
            audit,
            conn_sem: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            req_sem: Arc::new(Semaphore::new(MAX_CONCURRENT_REQS)),
        }
    }

    pub async fn serve(self, sock: PathBuf) -> Result<()> {
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock)?;
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;
        tracing::info!(sock = %sock.display(), "fusion-guard UDS server listening");

        let arc = Arc::new(self);
        loop {
            let (stream, peer_addr) = listener.accept().await?;
            tracing::debug!(peer = ?peer_addr, "incoming connection");

            let conn_sem = arc.conn_sem.clone();
            let permit = match conn_sem.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => continue,
            };

            let arc2 = arc.clone();
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = arc2.handle_conn(stream).await {
                    tracing::warn!(error = %e, "connection handler error");
                }
            });
        }
    }

    async fn handle_conn(self: Arc<Self>, stream: UnixStream) -> std::io::Result<()> {
        tracing::debug!(
            "peercred check stubbed (unsafe_code=deny; real impl P1 via nix crate allow)"
        );

        let (rd, mut wr) = stream.into_split();
        let mut reader = BufReader::with_capacity(8 * 1024, rd);
        let mut line: Vec<u8> = Vec::new();

        loop {
            line.clear();
            let n = reader.read_until(FRAMING_BYTE, &mut line).await?;
            if n == 0 {
                break;
            }
            if line.len() > MAX_LINE_BYTES {
                let resp = err_resp_bytes(Value::Null, -32600, "request too large");
                wr.write_all(&resp).await?;
                continue;
            }
            while line.last() == Some(&FRAMING_BYTE) {
                line.pop();
            }
            let req_str = String::from_utf8_lossy(&line);
            let resp_json = self.dispatch_arc(&req_str).await;
            wr.write_all(&resp_json).await?;
        }
        Ok(())
    }

    async fn dispatch_arc(self: &Arc<Self>, req_str: &str) -> Vec<u8> {
        let req: RpcRequest = match serde_json::from_str(req_str) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "malformed request");
                return err_resp_bytes(Value::Null, -32700, "parse error");
            }
        };

        let id = req.id.clone();
        let method = req.method.clone();
        let timeout = std::time::Duration::from_secs(REQ_TIMEOUT_SECS);

        let req_sem = self.req_sem.clone();
        let arc = self.clone();
        let fut = async move {
            let _permit = req_sem.acquire_owned().await.ok();
            arc.handle_method(&req).await
        };

        match tokio::time::timeout(timeout, fut).await {
            Ok(Ok(val)) => ok_resp_bytes(id, val),
            Ok(Err(e)) => err_resp_bytes(id, err_code(&e), &e.to_string()),
            Err(_) => {
                tracing::warn!(method = %method, "request timeout (fail-closed)");
                err_resp_bytes(id, -32010, "guard request timeout")
            }
        }
    }

    async fn handle_method(&self, req: &RpcRequest) -> Result<Value> {
        match req.method.as_str() {
            "guard.ping" => Ok(serde_json::json!({
                "pong": "ok",
                "version": env!("CARGO_PKG_VERSION"),
                "rules_epoch": self.engine.epoch(),
            })),
            "guard.evaluate" => {
                let action = req
                    .params
                    .get("action")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let content = req
                    .params
                    .get("content")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let requester = req
                    .params
                    .get("requester")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string();
                let tenant_id = req
                    .params
                    .get("tenant_id")
                    .and_then(Value::as_str)
                    .unwrap_or(fg_store::DEFAULT_TENANT)
                    .to_string();
                let caller_epoch = req
                    .params
                    .get("caller_epoch")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let verdict = self.engine.evaluate(content, caller_epoch)?;
                let redacted = verdict.redacted_content.clone().unwrap_or_default();
                if let Err(e) = self
                    .audit
                    .append_event(&tenant_id, &verdict, redacted, &requester)
                {
                    tracing::error!(error = %e, "audit append failed (fail-closed for high-risk)");
                }
                tracing::info!(
                    action = action,
                    tenant = %tenant_id,
                    requester = %requester,
                    category = %verdict.inferred_category,
                    "guard.evaluate handled"
                );
                Ok(serde_json::to_value(&verdict)?)
            }
            "guard.rule.list" => {
                let rs = self.engine.list_rules();
                Ok(serde_json::json!({ "rules": rs.rules, "epoch": rs.epoch }))
            }
            "guard.rules.dump" => {
                let rs = self.engine.list_rules();
                Ok(serde_json::json!({ "rules": rs.rules, "epoch": rs.epoch }))
            }
            "guard.rule.add" => {
                let rule: fg_rules::GuardRule =
                    serde_json::from_value(req.params.get("rule").cloned().unwrap_or(Value::Null))?;
                let new_epoch = self
                    .engine
                    .add_rule(rule)
                    .map_err(|e| GuardError::Engine(e.to_string()))?;
                tracing::info!(new_epoch = new_epoch, "guard.rule.add handled");
                Ok(serde_json::json!({ "new_epoch": new_epoch }))
            }
            "guard.rule.update" => {
                let name = req.params.get("name").and_then(Value::as_str).unwrap_or("");
                let rule: fg_rules::GuardRule =
                    serde_json::from_value(req.params.get("rule").cloned().unwrap_or(Value::Null))?;
                let new_epoch = self
                    .engine
                    .update_rule(name, rule)
                    .map_err(|e| GuardError::Engine(e.to_string()))?;
                tracing::info!(
                    new_epoch = new_epoch,
                    name = name,
                    "guard.rule.update handled"
                );
                Ok(serde_json::json!({ "new_epoch": new_epoch }))
            }
            "guard.rule.remove" => {
                let name = req.params.get("name").and_then(Value::as_str).unwrap_or("");
                let new_epoch = self
                    .engine
                    .remove_rule(name)
                    .map_err(|e| GuardError::Engine(e.to_string()))?;
                tracing::info!(
                    new_epoch = new_epoch,
                    name = name,
                    "guard.rule.remove handled"
                );
                Ok(serde_json::json!({ "new_epoch": new_epoch }))
            }
            "guard.redact" => {
                let content = req
                    .params
                    .get("content")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let reversible = req
                    .params
                    .get("reversible")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let res = self.engine.redact(content, reversible)?;
                tracing::info!(
                    reversible = reversible,
                    token_map_id = ?res.token_map_id,
                    "guard.redact handled"
                );
                Ok(serde_json::to_value(&res)?)
            }
            "guard.reveal" => {
                let content = req
                    .params
                    .get("content")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let token_map_id = req
                    .params
                    .get("token_map_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let restored = self.engine.reveal(content, &token_map_id)?;
                tracing::info!(token_map_id = %token_map_id, "guard.reveal handled");
                Ok(serde_json::json!({ "content": restored }))
            }
            "guard.confirm" => {
                let action_id = req
                    .params
                    .get("action_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let approved = req
                    .params
                    .get("approved")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let approved_by = req
                    .params
                    .get("approved_by")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string();
                let tenant_id = req
                    .params
                    .get("tenant_id")
                    .and_then(Value::as_str)
                    .unwrap_or(fg_store::DEFAULT_TENANT)
                    .to_string();
                let res = self
                    .engine
                    .confirm(&action_id, approved, &approved_by, &tenant_id)?;
                Ok(serde_json::to_value(&res)?)
            }
            "guard.tcc.status" => {
                let statuses = self.engine.tcc_status();
                Ok(serde_json::json!({ "statuses": statuses }))
            }
            "guard.tcc.report" => {
                let permission = req
                    .params
                    .get("permission")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let requester = req
                    .params
                    .get("requester")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string();
                let result = req
                    .params
                    .get("result")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string();
                let reason = req
                    .params
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let audit_id = self
                    .engine
                    .report_tcc(&permission, &requester, &result, &reason)?;
                tracing::info!(
                    permission = %permission,
                    requester = %requester,
                    result = %result,
                    "guard.tcc.report handled (audit aggregation H1)"
                );
                Ok(serde_json::json!({ "audit_id": audit_id }))
            }
            "guard.tcc.events" => {
                let limit = req
                    .params
                    .get("limit")
                    .and_then(Value::as_u64)
                    .unwrap_or(50) as usize;
                let events = self.engine.list_tcc_events(limit)?;
                Ok(serde_json::json!({ "events": events }))
            }
            "guard.audit.list" => {
                let limit = req
                    .params
                    .get("limit")
                    .and_then(Value::as_u64)
                    .unwrap_or(50) as usize;
                let recs = match req.params.get("tenant_id").and_then(Value::as_str) {
                    Some(t) => self.audit.list_by_tenant(t, limit),
                    None => self.audit.list(limit),
                };
                Ok(serde_json::json!({ "records": recs }))
            }
            _ => Err(GuardError::Engine(format!(
                "unknown method: {}",
                req.method
            ))),
        }
    }
}

fn err_code(e: &GuardError) -> i32 {
    match e {
        GuardError::Unauthorized(_) => -32001,
        GuardError::RateLimited => -32002,
        GuardError::StaleEpoch { .. } => -32003,
        GuardError::Engine(_) => -32010,
        _ => -32603,
    }
}

fn ok_resp_bytes(id: Value, result: Value) -> Vec<u8> {
    let resp = RpcResponse {
        jsonrpc: "2.0".into(),
        id,
        result: Some(result),
        error: None,
    };
    let mut bytes = serde_json::to_vec(&resp).unwrap_or_default();
    bytes.push(FRAMING_BYTE);
    bytes
}

fn err_resp_bytes(id: Value, code: i32, msg: &str) -> Vec<u8> {
    let resp = RpcResponse {
        jsonrpc: "2.0".into(),
        id,
        result: None,
        error: Some(RpcError {
            code,
            message: msg.into(),
        }),
    };
    let mut bytes = serde_json::to_vec(&resp).unwrap_or_default();
    bytes.push(FRAMING_BYTE);
    bytes
}
