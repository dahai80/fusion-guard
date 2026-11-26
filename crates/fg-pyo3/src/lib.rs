// fg-pyo3 — PyO3 binding, maturin target crate
//
// Produces the fusion_guard._native extension, wrapped by pure-Python guard_client.py (upstream fusion-core issue #17).
// PyGuardClient wraps a synchronous UDS JSON-RPC client (talks to the running guard daemon, FUSION_GUARD_SOCK),
// not an in-process engine — preserves rule SSOT (a per-Python-process engine would fork epochs, violating the Checkpoint 2 contract).
// Mirrors the fusion-executor/crates/fe-pyo3 binding mechanism (maturin/#[pyclass]), not in-process embedding.

use std::io::{BufRead, Read};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict};
use serde_json::Value;

use fg_core::GuardVerdict;

const DEFAULT_SOCK: &str = "/tmp/fusion-guard.sock";
const ENV_SOCK: &str = "FUSION_GUARD_SOCK";
// Issue #36: shared secret env fallback (same variable name as the start.sh/daemon side).
const ENV_SHARED_SECRET: &str = "FUSION_GUARD_SHARED_SECRET";
const FRAMING_BYTE: u8 = 0x0A;
const MAX_LINE_BYTES: usize = 1024 * 1024;
const REQ_TIMEOUT_SECS: u64 = 2;
static REQ_ID_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

// ── Python-visible types (mirroring the Rust types) ──────────────────────────────────

/// Python-visible verdict — mirrors Rust GuardVerdict
#[pyclass(name = "NativeGuardVerdict", skip_from_py_object)]
#[derive(Clone)]
struct PyGuardVerdict {
    #[pyo3(get)]
    action: String,
    #[pyo3(get)]
    risk_level: String,
    #[pyo3(get)]
    reason: String,
    #[pyo3(get)]
    stage: String,
    #[pyo3(get)]
    requires_approval: bool,
    #[pyo3(get)]
    redacted_content: Option<String>,
    #[pyo3(get)]
    seatbelt_required: bool,
    #[pyo3(get)]
    action_id: Option<String>,
    #[pyo3(get)]
    verdict_epoch: u64,
    #[pyo3(get)]
    verdict_ttl_secs: u32,
    #[pyo3(get)]
    inferred_category: String,
    // P2-6 (H9): caller-supplied category_hint (None = not provided). Caller claim is visible to the audit.
    #[pyo3(get)]
    category_hint: Option<String>,
}

impl From<GuardVerdict> for PyGuardVerdict {
    fn from(v: GuardVerdict) -> Self {
        Self {
            // C11/P0-G7: use serde wire serialization (lowercase, contract-aligned) instead of the Debug representation.
            // Server to_value now serializes "block"/"l4"; the client must take values from the same source, no longer reverse-depending on Debug.
            action: serde_str(&v.action),
            risk_level: serde_str(&v.risk_level),
            reason: v.reason,
            stage: serde_str(&v.stage),
            requires_approval: v.requires_approval,
            redacted_content: v.redacted_content,
            seatbelt_required: v.seatbelt_required,
            action_id: v.action_id.map(|u| u.to_string()),
            verdict_epoch: v.verdict_epoch,
            verdict_ttl_secs: v.verdict_ttl_secs,
            inferred_category: v.inferred_category,
            category_hint: v.category_hint,
        }
    }
}

// C11: take the enum's serde JSON string (rename_all=lowercase → "block"/"l4"/"ast" etc.),
// strip quotes, fall back to "unknown" on failure. Same source as server to_value, cutting the Debug dependency.
fn serde_str<T: serde::Serialize>(v: &T) -> String {
    match serde_json::to_value(v) {
        Ok(Value::String(s)) => s,
        _ => "unknown".to_string(),
    }
}

#[pymethods]
impl PyGuardVerdict {
    fn __repr__(&self) -> String {
        format!(
            "GuardVerdict(action={}, risk={}, category={}, seatbelt={})",
            self.action, self.risk_level, self.inferred_category, self.seatbelt_required
        )
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("action", &self.action)?;
        d.set_item("risk_level", &self.risk_level)?;
        d.set_item("reason", &self.reason)?;
        d.set_item("stage", &self.stage)?;
        d.set_item("requires_approval", self.requires_approval)?;
        d.set_item("redacted_content", &self.redacted_content)?;
        d.set_item("seatbelt_required", self.seatbelt_required)?;
        d.set_item("action_id", &self.action_id)?;
        d.set_item("verdict_epoch", self.verdict_epoch)?;
        d.set_item("verdict_ttl_secs", self.verdict_ttl_secs)?;
        d.set_item("inferred_category", &self.inferred_category)?;
        d.set_item("category_hint", &self.category_hint)?;
        Ok(d)
    }
}

/// Python-visible rule — mirrors Rust GuardRule
#[pyclass(name = "NativeGuardRule", skip_from_py_object)]
#[derive(Clone)]
struct PyGuardRule {
    #[pyo3(get)]
    name: String,
    #[pyo3(get)]
    pattern: String,
    #[pyo3(get)]
    stage: String,
    #[pyo3(get)]
    action: String,
    #[pyo3(get)]
    risk_level: String,
    #[pyo3(get)]
    reason: String,
    #[pyo3(get)]
    scope: String,
}

#[pymethods]
impl PyGuardRule {
    fn __repr__(&self) -> String {
        format!(
            "GuardRule(name={}, action={}, risk={})",
            self.name, self.action, self.risk_level
        )
    }
}

/// Python-visible redact result — mirrors Rust RedactResult
#[pyclass(name = "NativeRedactResult", skip_from_py_object)]
#[derive(Clone)]
struct PyRedactResult {
    #[pyo3(get)]
    redacted_content: String,
    #[pyo3(get)]
    token_map_id: Option<String>,
}

#[pymethods]
impl PyRedactResult {
    fn __repr__(&self) -> String {
        format!(
            "RedactResult(token_map_id={})",
            self.token_map_id.as_deref().unwrap_or("None")
        )
    }
}

/// Python-visible chain hash verification result — mirrors Rust ChainVerification / SubChainVerification
#[pyclass(name = "NativeChainVerification", skip_from_py_object)]
#[derive(Clone)]
struct PyChainVerification {
    #[pyo3(get)]
    total_rows: u64,
    #[pyo3(get)]
    unhashed_rows: u64,
    #[pyo3(get)]
    verified_links: u64,
    #[pyo3(get)]
    broken_links: u64,
    #[pyo3(get)]
    tampered: bool,
    #[pyo3(get)]
    first_broken_at: Option<u64>,
}

#[pymethods]
impl PyChainVerification {
    fn __repr__(&self) -> String {
        format!(
            "ChainVerification(rows={}, verified={}, broken={}, tampered={})",
            self.total_rows, self.verified_links, self.broken_links, self.tampered
        )
    }
}

// P0-5: all-chains aggregated verification result (audit + tcc + rules + dead_letter).
#[pyclass(name = "NativeAllChainsVerification", skip_from_py_object)]
#[derive(Clone)]
struct PyAllChainsVerification {
    #[pyo3(get)]
    audit: PyChainVerification,
    #[pyo3(get)]
    tcc: PyChainVerification,
    #[pyo3(get)]
    rules: PyChainVerification,
    #[pyo3(get)]
    dead_letter: PyChainVerification,
    #[pyo3(get)]
    tampered: bool,
}

#[pymethods]
impl PyAllChainsVerification {
    fn __repr__(&self) -> String {
        format!(
            "AllChainsVerification(tampered={}, audit.tampered={}, tcc.tampered={}, rules.tampered={}, dead_letter.tampered={})",
            self.tampered,
            self.audit.tampered,
            self.tcc.tampered,
            self.rules.tampered,
            self.dead_letter.tampered
        )
    }
}

// ── UDS JSON-RPC client (synchronous, with connection reuse) ───────────────────────────

// P2-4 (audit §3.6): the old `UdsClient::call` did connect+write+read+drop every time — every call paid
// the UDS connect handshake cost (socket create+bind+connect+accept kernel round trip); for high-frequency L1 evaluate
// P99 was dominated by the handshake, making P99<1ms unreachable with 9 concurrent callers. The server conn_loop already loops over multiple requests per connection
// (read→dispatch→write loop, disconnects only on EOF, CONN_DEADLINE_SECS=30s backstop) — no server change needed.
// Client-side reuse only: UdsClient holds a persistent Mutex<Option<UnixStream>> connection; call takes it out for reuse, and on IO error
// (server 30s deadline disconnect / peer restart / sporadic) → drop the old stream, reconnect, and retry once (transparent self-healing), never surfaced to the caller.
// Python is a single-threaded blocking model with one request in flight at a time; no multiplexing needed — a single reused connection eliminates the handshake overhead.
/// Internal synchronous UDS client — persistent connection reuse (P2-4)
/// Exposed as pub(crate) so integration tests can verify the wire contract (no Python environment)
pub struct UdsClient {
    sock: PathBuf,
    conn: std::sync::Mutex<Option<UnixStream>>,
    // Issue #36: §12.1 shared secret — when Some, inject params["secret"] into every non-ping request
    // (server PeerAuthorizer enforces it strictly on non-ping; ping is open to any peer).
    shared_secret: Option<String>,
}

#[derive(Debug)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

impl UdsClient {
    pub fn new(sock: PathBuf) -> Self {
        Self {
            sock,
            conn: std::sync::Mutex::new(None),
            shared_secret: None,
        }
    }

    // Issue #36: explicitly carry the shared secret (None = do not inject; behavior unchanged when the dev daemon has no secret).
    pub fn new_with_secret(sock: PathBuf, shared_secret: Option<String>) -> Self {
        Self {
            sock,
            conn: std::sync::Mutex::new(None),
            shared_secret,
        }
    }

    pub fn call(&self, method: &str, mut params: Value) -> std::result::Result<Value, RpcError> {
        // Issue #36: inject params["secret"] into non-ping requests (§12.1 second factor).
        // ping is open to any peer server-side; do not inject (aligned with server semantics).
        if method != "guard.ping" {
            if let Some(secret) = &self.shared_secret {
                if let Some(obj) = params.as_object_mut() {
                    obj.insert("secret".into(), Value::String(secret.clone()));
                }
            }
        }
        let id = REQ_ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let mut req_bytes = serde_json::to_vec(&req).map_err(|e| RpcError {
            code: -32700,
            message: format!("serialize req: {e}"),
        })?;
        req_bytes.push(FRAMING_BYTE);
        if req_bytes.len() > MAX_LINE_BYTES {
            return Err(RpcError {
                code: -32600,
                message: "request too large".into(),
            });
        }

        // P2-4: use the persistent stream first; on IO error (server deadline disconnect/restart) → drop the old stream, reconnect, retry once.
        // Retry only once (avoid reconnect loops amplifying the fault); surface the second error.
        match self.call_once(&req_bytes) {
            Ok(v) => Ok(v),
            Err(first) => {
                tracing::debug!(error = %first.message, "persistent conn call failed — reconnect retry once (P2-4)");
                self.call_once(&req_bytes)
            }
        }
    }

    // P2-4: single call — take the persistent stream (connect a new one if absent), write the request and read the response; on IO error → clear the stream (reconnect next time).
    // On success the stream is kept for reuse. The stream is read/written by borrow (BufReader<&UnixStream>), never consumed/cloned; the same fd is reused across calls.
    fn call_once(&self, req_bytes: &[u8]) -> std::result::Result<Value, RpcError> {
        let mut guard = self.conn.lock().expect("conn mutex poisoned");
        // No persistent stream, or it was cleared after a previous IO error → connect a new one (lazy, created on first call).
        if guard.is_none() {
            let stream = UnixStream::connect(&self.sock).map_err(|e| RpcError {
                code: -32010,
                message: format!("connect {}: {e}", self.sock.display()),
            })?;
            let _ = stream.set_read_timeout(Some(Duration::from_secs(REQ_TIMEOUT_SECS)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(REQ_TIMEOUT_SECS)));
            *guard = Some(stream);
        }
        let stream = guard.as_mut().expect("conn just ensured Some");
        // Read/write by borrow: do not consume the stream; the persistent fd is kept for reuse by the next call.
        if let Err(e) = std::io::Write::write_all(stream, req_bytes) {
            // Write error = the stream is broken (peer disconnect/EPIPE); clear it to force a reconnect next time.
            tracing::debug!(error = %e, "write failed — clearing persistent conn (P2-4)");
            *guard = None;
            return Err(RpcError {
                code: -32010,
                message: format!("write: {e}"),
            });
        }
        let mut buf = Vec::new();
        // C17: response read cap (MAX_LINE_BYTES+1); truncate with take, then check for overrun.
        // A malicious/runaway server returning a huge response no longer buffers unboundedly and OOMs the Python process.
        let reader = std::io::BufReader::new(stream);
        if let Err(e) = reader
            .take((MAX_LINE_BYTES + 1) as u64)
            .read_until(FRAMING_BYTE, &mut buf)
        {
            // Read error = the stream is broken (server deadline disconnect/EOF/timeout); clear it to force a reconnect.
            tracing::debug!(error = %e, "read failed — clearing persistent conn (P2-4)");
            *guard = None;
            return Err(RpcError {
                code: -32010,
                message: format!("read: {e}"),
            });
        }
        if buf.len() > MAX_LINE_BYTES {
            *guard = None;
            return Err(RpcError {
                code: -32600,
                message: "response too large".into(),
            });
        }
        while buf.last() == Some(&FRAMING_BYTE) {
            buf.pop();
        }
        if buf.is_empty() {
            // Server closed normally (EOF) = the stream lifecycle ended; clear it to force a reconnect next time.
            *guard = None;
            return Err(RpcError {
                code: -32010,
                message: "empty response".into(),
            });
        }
        let resp: Value = serde_json::from_slice(&buf).map_err(|e| RpcError {
            code: -32700,
            message: format!("parse resp: {e}"),
        })?;

        // Success responses carry "error": null (Option<RpcError> serializes None → null),
        // so null must be excluded — only a non-null error object counts as an error
        if let Some(Value::Object(err)) = resp.get("error") {
            let code = err.get("code").and_then(Value::as_i64).unwrap_or(-32603) as i32;
            let message = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown error")
                .to_string();
            return Err(RpcError { code, message });
        }
        resp.get("result").cloned().ok_or_else(|| RpcError {
            code: -32603,
            message: "missing result".into(),
        })
    }
}

fn map_rpc_err(e: RpcError) -> PyErr {
    match e.code {
        -32003 => PyRuntimeError::new_err(format!("stale epoch: {}", e.message)),
        -32002 => PyRuntimeError::new_err(format!("rate limited: {}", e.message)),
        -32001 => PyRuntimeError::new_err(format!("unauthorized: {}", e.message)),
        _ => PyRuntimeError::new_err(format!("guard error [{}]: {}", e.code, e.message)),
    }
}

// ── Main entry: PyGuardClient ─────────────────────────────────────────────

/// Python-visible guard client — UDS JSON-RPC calls into the running daemon
/// P2-4: holds a persistent UdsClient (with Mutex<Option<UnixStream>> connection reuse inside), not a new socket per call.
#[pyclass(name = "NativeGuardClient", skip_from_py_object)]
struct PyGuardClient {
    client: UdsClient,
}

fn parse_verdict(val: Value) -> PyResult<PyGuardVerdict> {
    let v: GuardVerdict = serde_json::from_value(val)
        .map_err(|e| PyValueError::new_err(format!("verdict decode: {e}")))?;
    Ok(PyGuardVerdict::from(v))
}

fn parse_rule(val: &Value) -> PyResult<PyGuardRule> {
    let action = val
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("allow")
        .to_string();
    let risk = val
        .get("risk_level")
        .and_then(Value::as_str)
        .unwrap_or("l1")
        .to_string();
    let stage = val
        .get("stage")
        .and_then(Value::as_str)
        .unwrap_or("regex")
        .to_string();
    let scope = val
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or("command")
        .to_string();
    Ok(PyGuardRule {
        name: val
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        pattern: val
            .get("pattern")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        stage,
        action,
        risk_level: risk,
        reason: val
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        scope,
    })
}

#[pymethods]
impl PyGuardClient {
    #[new]
    #[pyo3(signature = (sock_path=None, shared_secret=None))]
    fn new(sock_path: Option<String>, shared_secret: Option<String>) -> Self {
        let sock = sock_path
            .map(PathBuf::from)
            .or_else(|| std::env::var(ENV_SOCK).ok().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCK));
        // Issue #36: explicit argument > FUSION_GUARD_SHARED_SECRET env > None.
        // When the daemon enforces the secret (Keychain or --insecure-secret-env), non-ping calls must carry it,
        // otherwise -32001 unauthorized: secret denied (GuardSafetyBackend fully degrades fail-closed).
        let secret = shared_secret
            .or_else(|| std::env::var(ENV_SHARED_SECRET).ok())
            .filter(|s| !s.is_empty());
        match &secret {
            Some(_) => {
                tracing::info!(sock = %sock.display(), "PyGuardClient construct with shared secret (issue #36)")
            }
            None => {
                tracing::info!(sock = %sock.display(), "PyGuardClient construct WITHOUT shared secret — non-ping calls will be rejected if daemon enforces secret")
            }
        }
        Self {
            client: UdsClient::new_with_secret(sock, secret),
        }
    }

    /// ping() -> dict {pong, version, rules_epoch}
    fn ping(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let v = self
            .client()
            .call("guard.ping", Value::Object(Default::default()))
            .map_err(map_rpc_err)?;
        json_to_py(py, v)
    }

    /// evaluate(content, caller_epoch=0, tenant_id=None, requester=None, content_type="shell", category_hint=None) -> NativeGuardVerdict
    /// content_type: "shell" (default, run tokenizer) | "code" (run tree-sitter semantic)
    ///               | "json"/"yaml"/"text" (regex only, skip tokenizer+semantic)
    /// category_hint: caller category hint (H9, PRD §6.3) — guard infers authoritatively from content;
    ///                the hint only acts as a risk floor, raising the level but never lowering it. None = not passed (backward compatible).
    #[pyo3(signature = (content, caller_epoch=0, tenant_id=None, requester=None, content_type="shell", category_hint=None))]
    fn evaluate(
        &self,
        content: String,
        caller_epoch: u64,
        tenant_id: Option<String>,
        requester: Option<String>,
        content_type: &str,
        category_hint: Option<String>,
    ) -> PyResult<PyGuardVerdict> {
        let mut params = serde_json::json!({
            "action": "evaluate",
            "content": content,
            "caller_epoch": caller_epoch,
            "content_type": content_type,
        });
        if let Some(t) = tenant_id {
            params["tenant_id"] = Value::String(t);
        }
        if let Some(r) = requester {
            params["requester"] = Value::String(r);
        }
        if let Some(h) = category_hint {
            params["category_hint"] = Value::String(h);
        }
        let res = self
            .client()
            .call("guard.evaluate", params)
            .map_err(map_rpc_err)?;
        parse_verdict(res)
    }

    /// list_rules() -> (list[NativeGuardRule], int epoch)
    fn list_rules(&self) -> PyResult<(Vec<PyGuardRule>, u64)> {
        let res = self
            .client()
            .call("guard.rule.list", Value::Object(Default::default()))
            .map_err(map_rpc_err)?;
        // L9: error when epoch is missing (falling back to 0 would leave the caller holding a stale epoch forever, making every later evaluate stale).
        let epoch = res
            .get("epoch")
            .and_then(Value::as_u64)
            .ok_or_else(|| PyValueError::new_err("rule.list response missing 'epoch'"))?;
        // Missing rules is treated as empty (legal: no rules), but a wrong type is an error.
        let arr = match res.get("rules").cloned() {
            Some(Value::Array(a)) => a,
            Some(_) => return Err(PyValueError::new_err("rule.list 'rules' not array")),
            None => vec![],
        };
        let mut rules = Vec::with_capacity(arr.len());
        for r in &arr {
            rules.push(parse_rule(r)?);
        }
        Ok((rules, epoch))
    }

    /// redact(content, reversible) -> NativeRedactResult
    fn redact(&self, content: String, reversible: bool) -> PyResult<PyRedactResult> {
        let params = serde_json::json!({ "content": content, "reversible": reversible });
        let res = self
            .client()
            .call("guard.redact", params)
            .map_err(map_rpc_err)?;
        // L9: error when redacted_content is missing (never silently pass an empty string off as a successful redaction).
        let redacted_content = res
            .get("redacted_content")
            .and_then(Value::as_str)
            .map(String::from)
            .ok_or_else(|| PyValueError::new_err("redact response missing 'redacted_content'"))?;
        Ok(PyRedactResult {
            redacted_content,
            token_map_id: res
                .get("token_map_id")
                .and_then(Value::as_str)
                .map(String::from),
        })
    }

    /// reveal(content, token_map_id) -> str
    fn reveal(&self, content: String, token_map_id: String) -> PyResult<String> {
        let params = serde_json::json!({ "content": content, "token_map_id": token_map_id });
        let res = self
            .client()
            .call("guard.reveal", params)
            .map_err(map_rpc_err)?;
        // L9: never mask a missing server field with unwrap_or("") — error explicitly (an empty string would read as a successful reveal).
        res.get("content")
            .and_then(Value::as_str)
            .map(String::from)
            .ok_or_else(|| PyValueError::new_err("reveal response missing 'content'"))
    }

    /// confirm(action_id, approved, approved_by=None, tenant_id=None) -> NativeGuardVerdict
    #[pyo3(signature = (action_id, approved, approved_by=None, tenant_id=None))]
    fn confirm(
        &self,
        action_id: String,
        approved: bool,
        approved_by: Option<String>,
        tenant_id: Option<String>,
    ) -> PyResult<PyGuardVerdict> {
        let mut params = serde_json::json!({
            "action_id": action_id,
            "approved": approved,
        });
        if let Some(b) = approved_by {
            params["approved_by"] = Value::String(b);
        }
        if let Some(t) = tenant_id {
            params["tenant_id"] = Value::String(t);
        }
        let res = self
            .client()
            .call("guard.confirm", params)
            .map_err(map_rpc_err)?;
        // L9: never fall back to unwrap_or(res) — error when the server omits the "verdict" field; do not parse the raw response as a verdict.
        let verdict_val = res
            .get("verdict")
            .cloned()
            .ok_or_else(|| PyValueError::new_err("confirm response missing 'verdict'"))?;
        parse_verdict(verdict_val)
    }

    /// tcc_status() -> list[dict]
    fn tcc_status(&self, py: Python<'_>) -> PyResult<Vec<Py<PyAny>>> {
        let res = self
            .client()
            .call("guard.tcc.status", Value::Object(Default::default()))
            .map_err(map_rpc_err)?;
        let arr = res
            .get("statuses")
            .cloned()
            .unwrap_or(Value::Array(vec![]))
            .as_array()
            .cloned()
            .unwrap_or_default();
        arr.into_iter().map(|v| json_to_py(py, v)).collect()
    }

    /// tcc_events(limit=50) -> list[dict]
    #[pyo3(signature = (limit=50))]
    fn tcc_events(&self, py: Python<'_>, limit: u64) -> PyResult<Vec<Py<PyAny>>> {
        let params = serde_json::json!({ "limit": limit });
        let res = self
            .client()
            .call("guard.tcc.events", params)
            .map_err(map_rpc_err)?;
        let arr = res
            .get("events")
            .cloned()
            .unwrap_or(Value::Array(vec![]))
            .as_array()
            .cloned()
            .unwrap_or_default();
        arr.into_iter().map(|v| json_to_py(py, v)).collect()
    }

    /// audit_verify() -> NativeAllChainsVerification
    /// P0-5: all-chain aggregation (audit + tcc + rules + dead_letter). Each subchain parses into a PyChainVerification;
    /// top-level tampered = any subchain broken. L9: missing key fields → PyValueError (never silently fall back to false).
    fn audit_verify(&self) -> PyResult<PyAllChainsVerification> {
        let res = self
            .client()
            .call("guard.audit.verify", Value::Object(Default::default()))
            .map_err(map_rpc_err)?;
        let parse_sub = |obj: &Value, label: &str| -> PyResult<PyChainVerification> {
            let sub = obj.get(label).ok_or_else(|| {
                PyValueError::new_err(format!("audit.verify response missing '{label}' subchain"))
            })?;
            let get_u64 = |k: &str| -> PyResult<u64> {
                sub.get(k)
                    .and_then(Value::as_u64)
                    .ok_or_else(|| PyValueError::new_err(format!("{label} missing '{k}'")))
            };
            let tampered = sub
                .get("tampered")
                .and_then(Value::as_bool)
                .ok_or_else(|| PyValueError::new_err(format!("{label} missing 'tampered'")))?;
            Ok(PyChainVerification {
                total_rows: get_u64("total_rows")?,
                unhashed_rows: get_u64("unhashed_rows")?,
                verified_links: get_u64("verified_links")?,
                broken_links: get_u64("broken_links")?,
                tampered,
                first_broken_at: sub.get("first_broken_at").and_then(Value::as_u64),
            })
        };
        let tampered = res
            .get("tampered")
            .and_then(Value::as_bool)
            .ok_or_else(|| PyValueError::new_err("audit.verify response missing 'tampered'"))?;
        Ok(PyAllChainsVerification {
            audit: parse_sub(&res, "audit")?,
            tcc: parse_sub(&res, "tcc")?,
            rules: parse_sub(&res, "rules")?,
            dead_letter: parse_sub(&res, "dead_letter")?,
            tampered,
        })
    }
}

impl PyGuardClient {
    // P2-4: return a reference to the persistent UdsClient (with connection pooling inside); never create a new one per call — reuse the UDS connection.
    fn client(&self) -> &UdsClient {
        &self.client
    }
}

// M9: convert Value directly to Python (not a to_string + json.loads round trip).
// The old implementation used serde_json::to_string then Python json.loads — f64 through a JSON decimal string can lose precision
// (e.g. 0.1+0.2 as binary f64 serializes to a short decimal and parses back slightly off), plus the per-call cost of import json + parse.
// Direct conversion recursively builds the Python objects; f64 goes through PyO3's native f64 injection — exact precision, zero imports.
fn json_to_py(py: Python, val: Value) -> PyResult<Py<PyAny>> {
    value_to_obj(py, &val)
}

fn value_to_obj(py: Python, val: &Value) -> PyResult<Py<PyAny>> {
    match val {
        Value::Null => Ok(py.None()),
        Value::Bool(b) => Ok(PyBool::new(py, *b).to_owned().into_any().unbind()),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_pyobject(py)?.unbind().into_any())
            } else if let Some(u) = n.as_u64() {
                Ok(u.into_pyobject(py)?.unbind().into_any())
            } else {
                let f = n.as_f64().unwrap_or(f64::NAN);
                Ok(f.into_pyobject(py)?.unbind().into_any())
            }
        }
        Value::String(s) => Ok(s.clone().into_pyobject(py)?.unbind().into_any()),
        Value::Array(arr) => {
            let list = pyo3::types::PyList::empty(py);
            for v in arr {
                list.append(value_to_obj(py, v)?)?;
            }
            Ok(list.unbind().into_any())
        }
        Value::Object(obj) => {
            let dict = PyDict::new(py);
            for (k, v) in obj {
                dict.set_item(k, value_to_obj(py, v)?)?;
            }
            Ok(dict.unbind().into_any())
        }
    }
}

#[pyfunction]
fn version_info() -> (String, String, String) {
    (
        env!("CARGO_PKG_VERSION").to_string(),
        env!("FG_GIT_SHA").to_string(),
        env!("FG_BUILD_TIME").to_string(),
    )
}

#[pymodule]
fn _native(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyGuardVerdict>()?;
    m.add_class::<PyGuardRule>()?;
    m.add_class::<PyRedactResult>()?;
    m.add_class::<PyChainVerification>()?;
    m.add_class::<PyAllChainsVerification>()?;
    m.add_class::<PyGuardClient>()?;
    m.add_function(wrap_pyfunction!(version_info, m)?)?;
    Ok(())
}
