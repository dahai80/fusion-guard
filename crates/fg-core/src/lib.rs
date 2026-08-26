pub use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    L1,
    L2,
    L3,
    L4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SafetyAction {
    Allow,
    Preview,
    Redact,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckStage {
    Regex,
    Ast,
    Semantic,
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
}

pub type Result<T> = std::result::Result<T, GuardError>;
