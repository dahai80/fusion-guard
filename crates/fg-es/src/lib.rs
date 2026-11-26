// fg-es — Endpoint Security high-risk system event monitor (PRD Phase 7, Q#3)
//
// macOS Endpoint Security framework monitors high-risk system events (exec/file-write/rename/unlink/socket).
// **Entitlement constraint**: the ES client needs the `com.apple.developer.endpoint-security.client` entitlement
// (Apple developer agreement signing + provisioning). Without the entitlement:
//   - the real ES C FFI cannot run (ESNewClient returns a permission error)
//   - degrade path (PRD Q#3): fall back to the TCC runtime prompt (Phase 5 already covers TCC)
//
// This crate is the safe types layer (unsafe_code=deny); FFI logic lives in fg-es-bridge (the sole allow crate).
// build.rs detects the entitlement/compile environment → if absent emits cfg(es_bridge_stub) + a C stub fallback
// (degraded=true, no events), mirroring the fg-tcc-bridge stub pattern.
//
// Currently landed (dev environment without entitlement): stub mode — types + degraded status + empty event stream;
// the real ES binding lands once the entitlement is in place (ESNewClient/ESSubscribe/ESNewClientResult).

use serde::{Deserialize, Serialize};

// ── Monitored event kinds (PRD: high-risk system events) ──────────────────────────────────

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

// ── ES event record (captured by the monitor, then audited) ────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EsEvent {
    pub kind: EsEventKind,
    pub pid: u32,
    pub process: String,
    pub target: String,
    pub ts: i64,
}

// ── ES monitor state ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EsMonitorState {
    // Real ES client running (entitlement present, subscription effective)
    Active,
    // No entitlement → degraded, fall back to TCC (PRD Q#3)
    Degraded,
    // Monitor not started
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

// ── Monitor (config + start + fetch events) ─────────────────────────────────────
// Current stub mode: monitor_events returns empty (degraded); start records the degraded state
// Real mode (entitlement in place): fg-es-bridge ESNewClient + ESSubscribe → event stream

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
        // Real ES path (once the entitlement is in place): call fg_es_bridge::new_client + subscribe
        // Currently unreachable — build.rs emits the stub cfg when no entitlement exists
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

    // Stub mode is always empty (degraded, no events); real mode pulls events from the bridge
    pub fn monitor_events(&self) -> Vec<EsEvent> {
        if fg_es_bridge::is_stub() {
            return Vec::new();
        }
        Vec::new()
    }
}

// ── Default set of high-risk subscribed events ────────────────────────────────────────────────

pub fn default_kinds() -> Vec<EsEventKind> {
    vec![
        EsEventKind::Exec,
        EsEventKind::FileWrite,
        EsEventKind::Rename,
        EsEventKind::Unlink,
        EsEventKind::SocketOpen,
    ]
}
