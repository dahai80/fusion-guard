// fg-es — Endpoint Security 高危系统事件监控 (PRD Phase 7, Q#3)
//
// macOS Endpoint Security framework 监控高危系统事件 (exec/file-write/rename/unlink/socket)。
// **资质约束**: ES client 需 `com.apple.developer.endpoint-security.client` entitlement
// (Apple 开发者协议签署 + provisioning)。无 entitlement:
//   - 真实 ES C FFI 无法运行 (ESNewClient 返回缺权限错误)
//   - 降级路径 (PRD Q#3): 退回 TCC runtime prompt (Phase 5 已覆盖 TCC)
//
// 本 crate 为安全类型层 (unsafe_code=deny), FFI 逻辑在 fg-es-bridge (唯一 allow crate)。
// build.rs 检测 entitlement/编译环境 → 无则发 cfg(es_bridge_stub) + C stub fallback
// (返回 degraded=true, 无事件), 镜像 fg-tcc-bridge stub 范式。
//
// 当前落地 (无 entitlement 开发环境): stub 模式 — 提供类型 + degraded 状态 + 空事件流,
// 真实 ES 绑定待 entitlement 就位后接入 (ESNewClient/ESSubscribe/ESNewClientResult)。

use serde::{Deserialize, Serialize};

// ── 监控事件种类 (PRD: 高危系统事件) ──────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EsEventKind {
    Exec,
    FileWrite,
    Rename,
    Unlink,
    SocketOpen,
}

impl EsEventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            EsEventKind::Exec => "exec",
            EsEventKind::FileWrite => "file_write",
            EsEventKind::Rename => "rename",
            EsEventKind::Unlink => "unlink",
            EsEventKind::SocketOpen => "socket_open",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "exec" => Some(EsEventKind::Exec),
            "file_write" => Some(EsEventKind::FileWrite),
            "rename" => Some(EsEventKind::Rename),
            "unlink" => Some(EsEventKind::Unlink),
            "socket_open" => Some(EsEventKind::SocketOpen),
            _ => None,
        }
    }
}

// ── ES 事件记录 (监控捕获后落审计) ────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EsEvent {
    pub kind: EsEventKind,
    pub pid: u32,
    pub process: String,
    pub target: String,
    pub ts: i64,
}

// ── ES 监控器状态 ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EsMonitorState {
    // 真实 ES client 运行中 (有 entitlement, 订阅生效)
    Active,
    // 无 entitlement → 降级, 退回 TCC (PRD Q#3)
    Degraded,
    // 监控未启动
    Inactive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EsStatus {
    pub state: EsMonitorState,
    pub source: String,
    pub entitlement: bool,
    pub subscribed: Vec<EsEventKind>,
}

impl EsStatus {
    pub fn degraded() -> Self {
        Self {
            state: EsMonitorState::Degraded,
            source: "es-bridge:stub".to_string(),
            entitlement: false,
            subscribed: Vec::new(),
        }
    }
}

// ── 监控器 (配置 + 启动 + 取事件) ─────────────────────────────────────
// 当前 stub 模式: monitor_events 返回空 (degraded), 启动即记录降级
// 真实模式 (entitlement 就位): fg-es-bridge ESNewClient + ESSubscribe → 事件流

pub struct EsMonitor {
    kinds: Vec<EsEventKind>,
    active: bool,
}

impl EsMonitor {
    pub fn new(kinds: Vec<EsEventKind>) -> Self {
        Self {
            kinds,
            active: false,
        }
    }

    pub fn start(&mut self) -> EsStatus {
        if fg_es_bridge::is_stub() {
            tracing::warn!(
                "ES monitor degraded: no entitlement (stub mode), fall back to TCC (PRD Q#3)"
            );
            return EsStatus::degraded();
        }
        // 真实 ES 路径 (entitlement 就位后): 调 fg_es_bridge::new_client + subscribe
        // 当前 unreachable — build.rs 无 entitlement 即发 stub cfg
        self.active = true;
        EsStatus {
            state: EsMonitorState::Active,
            source: "es-bridge:live".to_string(),
            entitlement: true,
            subscribed: self.kinds.clone(),
        }
    }

    pub fn stop(&mut self) {
        self.active = false;
        tracing::info!("ES monitor stopped");
    }

    pub fn status(&self) -> EsStatus {
        if fg_es_bridge::is_stub() {
            return EsStatus::degraded();
        }
        if self.active {
            EsStatus {
                state: EsMonitorState::Active,
                source: "es-bridge:live".to_string(),
                entitlement: true,
                subscribed: self.kinds.clone(),
            }
        } else {
            EsStatus {
                state: EsMonitorState::Inactive,
                source: "es-bridge:live".to_string(),
                entitlement: true,
                subscribed: Vec::new(),
            }
        }
    }

    // stub 模式恒空 (degraded, 无事件); 真实模式从 bridge 拉事件
    pub fn monitor_events(&self) -> Vec<EsEvent> {
        if fg_es_bridge::is_stub() {
            return Vec::new();
        }
        Vec::new()
    }
}

// ── 默认订阅高危事件集 ────────────────────────────────────────────────

pub fn default_kinds() -> Vec<EsEventKind> {
    vec![
        EsEventKind::Exec,
        EsEventKind::FileWrite,
        EsEventKind::Rename,
        EsEventKind::Unlink,
        EsEventKind::SocketOpen,
    ]
}
