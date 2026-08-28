pub use serde::{Deserialize, Serialize};

// C11/P0-G7 (E5): 契约要求 lowercase 序列化 ("block"/"l4" 非 "Block"/"L4")。
// 服务端 to_value 与客户端 parse 端到端对齐, 否则 caller 按 "block" 匹配失败 → Block 静默变 allow。
// M6: 显式 repr(u8) + 判别式, 不再依赖隐式变体序。Ord 显式 impl 锁 L4>L3>L2>L1,
// max_by_key 用 rank() 确定性比较 (L11 平局消除依赖)。
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

// M6: SafetyAction 显式严重度序 (Block > Redact > Preview > Allow)。
// verdict_from_hits (L11) 按动作严重度取 head, 不再依赖 push 顺序。
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

// P0-2 (audit §1.7/§1.8): guard.evaluate 按 content_type 分派扫描阶段。
//   Shell  → Stage1 regex + Stage2 tokenizer (AST)。shell_words 解析 argv。
//   Code   → Stage1 regex + Stage3 semantic (tree-sitter 多 grammar)。跳 tokenizer
//            (代码非 shell 语法, tokenizer 会把 import os 当非白名单 binary 假阳)。
//   Json/Yaml/Text → 仅 Stage1 regex。跳 tokenizer + semantic (结构化/自由文本非可执行)。
// 默认 Shell (向后兼容: 现有 caller 不传 content_type 当 shell)。Default 派生取首变体 Shell。
// Unknown → 按 Shell 处理 (fail-open 仅对扫描阶段选择; 命中规则照常 Block, 不降低安全)。
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
    // tokenizer (Stage2 AST) 仅对 Shell 内容跑。
    pub fn run_tokenizer(self) -> bool {
        matches!(self, ContentType::Shell)
    }
    // semantic (Stage3 tree-sitter) 仅对 Code 内容跑。
    pub fn run_semantic(self) -> bool {
        matches!(self, ContentType::Code)
    }
    // 从 IPC 字符串解析, 未知值 → Shell (默认, fail-open 仅对扫描阶段; 规则命中仍 Block)。
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
    // P2-6 (audit §3.2/F6, PRD §6.3 H9): 调用方传入的 category_hint。
    // guard 从 content 推断 category 权威 (inferred_category), hint 仅作风险地板
    // (max(推断, 命中, hint)) —— hint 抬高等级, 永不压低 (防自证降级绕过)。
    // None = 调用方未传 (默认, 向后兼容)。serde default 关让旧 verdict JSON 缺此字段仍可解。
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
    // L8/M2/P1: JSON-RPC 标准码 — 参数错误 (-32602) 与方法未找到 (-32601)。
    // Display 不含内部细节 (M1: 不转发 SQLite schema/路径/方法名到 wire)。
    #[error("invalid params")]
    InvalidParams,
    #[error("method not found")]
    MethodNotFound,
}

pub type Result<T> = std::result::Result<T, GuardError>;
