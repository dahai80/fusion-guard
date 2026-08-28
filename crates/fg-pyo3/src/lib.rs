// fg-pyo3 — PyO3 绑定, maturin 目标 crate
//
// 产出 fusion_guard._native 扩展, 纯 Python guard_client.py 包装 (上游 fusion-core issue #17)。
// PyGuardClient 包装同步 UDS JSON-RPC 客户端 (连运行中的 guard 守护进程, FUSION_GUARD_SOCK),
// 非 in-process engine — 保留规则 SSOT (每 Python 进程独立 engine 会分叉 epoch, 违 Checkpoint 2 契约)。
// 对齐 fusion-executor/crates/fe-pyo3 绑定机制 (maturin/#[pyclass]), 非 in-process 嵌入。

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
const FRAMING_BYTE: u8 = 0x0A;
const MAX_LINE_BYTES: usize = 1024 * 1024;
const REQ_TIMEOUT_SECS: u64 = 2;
static REQ_ID_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

// ── Python 可见类型 (镜像 Rust 类型) ──────────────────────────────────

/// Python 可见 verdict — 镜像 Rust GuardVerdict
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
    // P2-6 (H9): 调用方传入的 category_hint (None=未传)。审计可见调用方主张。
    #[pyo3(get)]
    category_hint: Option<String>,
}

impl From<GuardVerdict> for PyGuardVerdict {
    fn from(v: GuardVerdict) -> Self {
        Self {
            // C11/P0-G7: 用 serde 网络序列化 (lowercase, 契约对齐) 而非 Debug 表示。
            // 服务端 to_value 现序列化 "block"/"l4", 客户端须同源取值, 不再反向依赖 Debug。
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

// C11: 取枚举的 serde JSON 字符串 (rename_all=lowercase → "block"/"l4"/"ast" 等),
// 去引号, 失败回退 "unknown"。与服务端 to_value 同源, 斩 Debug 依赖。
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

/// Python 可见 rule — 镜像 Rust GuardRule
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

/// Python 可见脱敏结果 — 镜像 Rust RedactResult
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

/// Python 可见链式 hash 校验结果 — 镜像 Rust ChainVerification / SubChainVerification
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

// P0-5: 全链聚合校验结果 (audit + tcc + rules + dead_letter)。
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

// ── UDS JSON-RPC 客户端 (同步, 带连接复用) ───────────────────────────

// P2-4 (audit §3.6): 旧 `UdsClient::call` 每次 connect+write+read+drop —— 每次调用付
// UDS connect 握手开销 (socket 创建+bind+connect+accept 内核态往返), 高频 L1 evaluate
// P99 被握手主导, 9 端并发下 P99<1ms 不可达。服务端 conn_loop 已循环处理单连接多请求
// (read→dispatch→write 循环, EOF 才断, CONN_DEADLINE_SECS=30s 兜底) —— 无需改服务端。
// 仅客户端复用: UdsClient 持 Mutex<Option<UnixStream>> 持久连接, call 取出复用, IO 错
// (服务端 30s deadline 断 / 对端重启 / 偶发) → drop 旧流重连一次重试 (透明自愈), 不暴露给调用方。
// Python 单线程阻塞模型, 一次一请求在途, 无需多路复用 —— 单连接复用即消除握手开销。
/// 内部同步 UDS 客户端 — 持久连接复用 (P2-4)
/// pub(crate) 暴露供集成测试验证 wire contract (无 Python 环境)
pub struct UdsClient {
    sock: PathBuf,
    conn: std::sync::Mutex<Option<UnixStream>>,
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
        }
    }

    pub fn call(&self, method: &str, params: Value) -> std::result::Result<Value, RpcError> {
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

        // P2-4: 首次用持久流; IO 错 (服务端 deadline 断/重启) → drop 旧流重连一次重试。
        // 重试仅一次 (避免循环重连放大故障), 第二次错即报出。
        match self.call_once(&req_bytes) {
            Ok(v) => Ok(v),
            Err(first) => {
                tracing::debug!(error = %first.message, "persistent conn call failed — reconnect retry once (P2-4)");
                self.call_once(&req_bytes)
            }
        }
    }

    // P2-4: 单次 call —— 取持久流 (无则 connect 新建), 写请求读响应, IO 错 → 清流 (下次重连)。
    // 成功保留流供复用。流按借用读写 (BufReader<&UnixStream>), 不消耗/clone, 同 fd 跨调用复用。
    fn call_once(&self, req_bytes: &[u8]) -> std::result::Result<Value, RpcError> {
        let mut guard = self.conn.lock().expect("conn mutex poisoned");
        // 无持久流或上次 IO 错清空 → connect 新建 (lazy, 首次 call 才建)。
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
        // 借用读写: 不消耗 stream, 持久 fd 保留供下次 call 复用。
        if let Err(e) = std::io::Write::write_all(stream, req_bytes) {
            // 写错 = 流已坏 (对端断/EPIPE), 清空促下次重连。
            tracing::debug!(error = %e, "write failed — clearing persistent conn (P2-4)");
            *guard = None;
            return Err(RpcError {
                code: -32010,
                message: format!("write: {e}"),
            });
        }
        let mut buf = Vec::new();
        // C17: 响应读取限流 (MAX_LINE_BYTES+1), take 截断后查超限。
        // 恶意/失控服务端返回巨响应不再无界缓冲到 Python 进程 OOM。
        let reader = std::io::BufReader::new(stream);
        if let Err(e) = reader
            .take((MAX_LINE_BYTES + 1) as u64)
            .read_until(FRAMING_BYTE, &mut buf)
        {
            // 读错 = 流已坏 (服务端 deadline 断/EOF/超时), 清空促重连。
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
            // 服务端正常关闭 (EOF) = 流生命周期尽, 清空促下次重连。
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

        // 成功响应带 "error": null (Option<RpcError> serialize None → null),
        // 须排除 null — 仅 error 为非 null 对象才算错误
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

// ── 主入口: PyGuardClient ─────────────────────────────────────────────

/// Python 可见 guard 客户端 — UDS JSON-RPC 调运行中守护进程
/// P2-4: 持持久 UdsClient (内含 Mutex<Option<UnixStream>> 连接复用), 非 sock 每次新建。
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
    #[pyo3(signature = (sock_path=None))]
    fn new(sock_path: Option<String>) -> Self {
        let sock = sock_path
            .map(PathBuf::from)
            .or_else(|| std::env::var(ENV_SOCK).ok().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCK));
        tracing::info!(sock = %sock.display(), "PyGuardClient construct (P2-4 persistent conn)");
        Self {
            client: UdsClient::new(sock),
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
    /// category_hint: 调用方 category hint (H9, PRD §6.3) —— guard 从 content 推断权威,
    ///                hint 仅作风险地板抬等级不压低。None=不传 (向后兼容)。
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
        // L9: epoch 缺失报错 (回退 0 会让 caller 永持陈旧 epoch, 后续 evaluate 永判 stale)。
        let epoch = res
            .get("epoch")
            .and_then(Value::as_u64)
            .ok_or_else(|| PyValueError::new_err("rule.list response missing 'epoch'"))?;
        // rules 缺失当空 (合法: 无规则), 但类型错即报错。
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
        // L9: redacted_content 缺失即报错 (勿静默空串伪装成功脱敏)。
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
        // L9: 勿 unwrap_or("") 掩盖服务端缺失 — 显式报错 (空串会被 caller 当成功 reveal)。
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
        // L9: 勿 unwrap_or(res) 回退 — 服务端缺 "verdict" 字段即报错, 不拿裸响应当 verdict 解析。
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
    /// P0-5: 全链聚合 (audit + tcc + rules + dead_letter)。每条子链解析为 PyChainVerification,
    /// 顶层 tampered = 任一子链坏。L9: 关键字段缺失 → PyValueError (勿静默回退 false)。
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
    // P2-4: 返回持久 UdsClient 引用 (内含连接池), 不每次新建 —— 复用 UDS 连接。
    fn client(&self) -> &UdsClient {
        &self.client
    }
}

// M9: Value → Python 直转 (非 to_string + json.loads 往返)。
// 原实现 serde_json::to_string 再 Python json.loads —— f64 经 JSON 十进制串可能丢精度
// (如 0.1+0.2 二进制 f64 序列化为短十进制再解析回略偏值), 且每次调 import json + parse 开销。
// 直转递归构造 Python 对象, f64 走 PyO3 原生 f64 注入, 精度保真, 零 import。
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
