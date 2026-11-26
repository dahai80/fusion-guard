pub use serde::{Deserialize, Serialize};

// C11/P0-G7 (E5): contract requires lowercase serialization ("block"/"l4" not "Block"/"L4").
// Server to_value and client parse aligned end-to-end, otherwise a caller matching on "block" fails → Block silently becomes allow.
// M6: explicit repr(u8) + discriminants, no longer relying on implicit variant order. Ord explicitly impl'd to lock L4>L3>L2>L1,
// max_by_key uses rank() for deterministic comparison (L11 tie-breaking dependency).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum RiskLevel {
    L1 = 0,
    L2 = 1,
    L3 = 2,
    L4 = 3,
}

impl RiskLevel {
    pub fn rank(self) -> u8 {
        self as u8
    }
}

impl PartialOrd for RiskLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RiskLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

// M6: SafetyAction explicit severity order (Block > Redact > Preview > Allow).
// verdict_from_hits (L11) takes head by action severity, no longer relying on push order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SafetyAction {
    Allow,
    Preview,
    Redact,
    Block,
}

impl SafetyAction {
    pub fn severity(self) -> u8 {
        match self {
            SafetyAction::Allow => 0,
            SafetyAction::Preview => 1,
            SafetyAction::Redact => 2,
            SafetyAction::Block => 3,
        }
    }
}

impl PartialOrd for SafetyAction {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SafetyAction {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.severity().cmp(&other.severity())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStage {
    Regex,
    Ast,
    Semantic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleScope {
    Command,
    Content,
    Network,
    Filesystem,
}

// P0-2 (audit §1.7/§1.8): guard.evaluate dispatches scan stages by content_type.
//   Shell  → Stage1 regex + Stage2 tokenizer (AST). shell_words parses argv.
//   Code   → Stage1 regex + Stage3 semantic (tree-sitter multi-grammar). Skips the tokenizer
//            (code is not shell syntax; the tokenizer would false-positive on import os as a non-whitelisted binary).
//   Json/Yaml/Text → Stage1 regex only. Skips tokenizer + semantic (structured/free text is not executable).
// Default Shell (backward compatible: existing callers not passing content_type are treated as shell). Default derive takes first variant Shell.
// Unknown → handled as Shell (fail-open applies only to scan-stage selection; rule hits still Block, no security reduction).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ContentType {
    #[default]
    Shell,
    Code,
    Json,
    Yaml,
    Text,
}

impl ContentType {
    // tokenizer (Stage2 AST) runs only for Shell content.
    pub fn run_tokenizer(self) -> bool {
        matches!(self, ContentType::Shell)
    }
    // semantic (Stage3 tree-sitter) runs only for Code content.
    pub fn run_semantic(self) -> bool {
        matches!(self, ContentType::Code)
    }
    // Parse from IPC string, unknown value → Shell (default, fail-open only for scan stage; rule hits still Block).
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "code" => ContentType::Code,
            "json" => ContentType::Json,
            "yaml" => ContentType::Yaml,
            "text" => ContentType::Text,
            _ => ContentType::Shell,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardVerdict {
    pub action: SafetyAction,
    pub risk_level: RiskLevel,
    pub reason: String,
    pub stage: CheckStage,
    pub requires_approval: bool,
    pub redacted_content: Option<String>,
    pub seatbelt_required: bool,
    pub action_id: Option<uuid::Uuid>,
    pub verdict_epoch: u64,
    pub verdict_ttl_secs: u32,
    pub inferred_category: String,
    // P2-6 (audit §3.2/F6, PRD §6.3 H9): category_hint passed in by the caller.
    // guard infers category from content as the authority (inferred_category); hint is only a risk floor
    // (max(inferred, hit, hint)) — hint raises the level, never lowers it (prevents self-attested downgrade bypass).
    // None = caller did not pass one (default, backward compatible). serde default so old verdict JSON missing this field still parses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category_hint: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum GuardError {
    #[error("rule engine internal failure: {0}")]
    Engine(String),
    #[error("unauthorized caller: {0}")]
    Unauthorized(String),
    #[error("rate limited")]
    RateLimited,
    #[error("stale epoch: caller={caller} guard={guard}")]
    StaleEpoch { caller: u64, guard: u64 },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
    // L8/M2/P1: JSON-RPC standard codes — invalid params (-32602) and method not found (-32601).
    // Display carries no internal details (M1: no SQLite schema/paths/method names forwarded onto the wire).
    #[error("invalid params")]
    InvalidParams,
    #[error("method not found")]
    MethodNotFound,
    // P2-3 (audit §3.4): JSON-RPC protocol version not "2.0" → -32600 (Invalid Request).
    // Prevents callers bypassing/polluting audit with a non-standard protocol (old code parsed the jsonrpc field but did not validate its value).
    #[error("invalid request: jsonrpc must be \"2.0\"")]
    InvalidRequest,
    // H-B (product-audit §5): rule mutation methods (add/update/remove) callable only by admin (root).
    // Non-admin rule mutation → rejected (-32001, same wire code as Unauthorized but distinguished in logs).
    #[error("forbidden: rule mutation requires admin")]
    Forbidden,
}

pub type Result<T> = std::result::Result<T, GuardError>;
