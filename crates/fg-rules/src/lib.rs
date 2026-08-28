pub mod tokenizer;

#[cfg(feature = "semantic")]
pub mod semantic;

use fg_core::{CheckStage, ContentType, GuardVerdict, RiskLevel, RuleScope, SafetyAction};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

// M3: 锁中毒 recover 非进程 panic。守护进程须存活, 内存态次新可接受 (rules 持久化 SQLite,
// 原子性由 DB 保证)。EMERG 日志供运维感知。RwLock read/write lock result 通用 into_inner()。
macro_rules! recover_lock {
    ($lock:expr, $what:expr) => {
        match $lock {
            Ok(g) => g,
            Err(e) => {
                tracing::error!(
                    what = $what,
                    "rwlock poisoned — recovering (daemon must stay alive, M3)"
                );
                e.into_inner()
            }
        }
    };
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardRule {
    pub name: String,
    pub pattern: String,
    pub stage: CheckStage,
    pub action: SafetyAction,
    pub risk_level: RiskLevel,
    pub reason: String,
    pub scope: RuleScope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleHit {
    pub rule: GuardRule,
    pub matched_text: String,
    pub stage: CheckStage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSet {
    pub epoch: u64,
    pub rules: Vec<GuardRule>,
}

struct Inner {
    rules: Vec<GuardRule>,
    compiled: Vec<Option<regex::Regex>>,
    epoch: u64,
}

#[derive(Clone)]
pub struct RuleEngine {
    inner: Arc<RwLock<Inner>>,
}

#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    #[error("regex compile failed: {0}")]
    Regex(#[from] regex::Error),
    #[error("rule not found: {0}")]
    NotFound(String),
    #[error("duplicate rule name: {0}")]
    Duplicate(String),
}

impl RuleEngine {
    pub fn new(ruleset: RuleSet) -> Result<Self, RuleError> {
        let mut compiled = Vec::with_capacity(ruleset.rules.len());
        for r in &ruleset.rules {
            compiled.push(Some(regex::Regex::new(&r.pattern)?));
        }
        Ok(Self {
            inner: Arc::new(RwLock::new(Inner {
                rules: ruleset.rules,
                compiled,
                epoch: ruleset.epoch,
            })),
        })
    }

    pub fn epoch(&self) -> u64 {
        recover_lock!(self.inner.read(), "rule rwlock read").epoch
    }

    pub fn list(&self) -> RuleSet {
        let g = recover_lock!(self.inner.read(), "rule rwlock read");
        RuleSet {
            epoch: g.epoch,
            rules: g.rules.clone(),
        }
    }

    pub fn add(&self, rule: GuardRule) -> Result<u64, RuleError> {
        let re = regex::Regex::new(&rule.pattern)?;
        let mut g = recover_lock!(self.inner.write(), "rule rwlock write");
        if g.rules.iter().any(|r| r.name == rule.name) {
            return Err(RuleError::Duplicate(rule.name.clone()));
        }
        g.rules.push(rule);
        g.compiled.push(Some(re));
        g.epoch += 1;
        tracing::info!(epoch = g.epoch, "rule added");
        Ok(g.epoch)
    }

    pub fn update(&self, name: &str, rule: GuardRule) -> Result<u64, RuleError> {
        let re = regex::Regex::new(&rule.pattern)?;
        let mut g = recover_lock!(self.inner.write(), "rule rwlock write");
        let idx = g
            .rules
            .iter()
            .position(|r| r.name == name)
            .ok_or_else(|| RuleError::NotFound(name.to_string()))?;
        g.rules[idx] = rule;
        g.compiled[idx] = Some(re);
        g.epoch += 1;
        tracing::info!(epoch = g.epoch, name = name, "rule updated");
        Ok(g.epoch)
    }

    pub fn remove(&self, name: &str) -> Result<u64, RuleError> {
        let mut g = recover_lock!(self.inner.write(), "rule rwlock write");
        let idx = g
            .rules
            .iter()
            .position(|r| r.name == name)
            .ok_or_else(|| RuleError::NotFound(name.to_string()))?;
        g.rules.remove(idx);
        g.compiled.remove(idx);
        g.epoch += 1;
        tracing::info!(epoch = g.epoch, name = name, "rule removed");
        Ok(g.epoch)
    }

    pub fn evaluate(&self, content: &str) -> Vec<RuleHit> {
        let g = recover_lock!(self.inner.read(), "rule rwlock read");
        let mut hits = Vec::new();
        for (rule, re) in g.rules.iter().zip(g.compiled.iter()) {
            if rule.stage != CheckStage::Regex {
                continue;
            }
            if let Some(re) = re {
                if let Some(m) = re.find(content) {
                    hits.push(RuleHit {
                        rule: rule.clone(),
                        matched_text: m.as_str().to_string(),
                        stage: CheckStage::Regex,
                    });
                }
            }
        }
        hits
    }

    // P0-2 (audit §1.7/§1.8): 按 content_type 分派扫描阶段。
    //   Shell  → regex + tokenizer (AST)。shell_words 解析 argv。
    //   Code   → regex + semantic (tree-sitter)。跳 tokenizer (代码非 shell 语法,
    //            tokenizer 会把 `import os` 当非白名单 binary 假阳)。
    //   Json/Yaml/Text → 仅 regex。跳 tokenizer + semantic (结构化/自由文本非可执行,
    //            tokenizer 假阳 + semantic 无对应 grammar)。
    pub fn evaluate_full_typed(&self, content: &str, content_type: ContentType) -> Vec<RuleHit> {
        let mut hits = self.evaluate(content);
        // Stage 2 tokenizer: 仅 Shell 内容。
        if content_type.run_tokenizer() {
            for tok in tokenizer::tokenize_check(content) {
                let risk = if tok.sensitive_target {
                    RiskLevel::L4
                } else {
                    RiskLevel::L3
                };
                let binary_name = tok.binary.clone();
                let sensitive = tok.sensitive_target;
                tracing::info!(
                    binary = %binary_name,
                    sensitive = sensitive,
                    "ast stage token hit"
                );
                hits.push(RuleHit {
                    rule: GuardRule {
                        name: format!("ast:{}", binary_name),
                        pattern: binary_name.clone(),
                        stage: CheckStage::Ast,
                        action: SafetyAction::Block,
                        risk_level: risk,
                        reason: tok.reason,
                        scope: RuleScope::Command,
                    },
                    matched_text: binary_name,
                    stage: CheckStage::Ast,
                });
            }
        }
        // Stage 3 语义分析: 仅 Code 内容 (feature=semantic 默认开)。
        #[cfg(feature = "semantic")]
        if content_type.run_semantic() {
            let sem_hits = semantic::semantic_check(content);
            for sh in &sem_hits {
                tracing::info!(
                    language = %sh.language,
                    callee = %sh.callee,
                    risk = ?sh.risk,
                    "semantic stage hit"
                );
                let name = format!("semantic:{}:{}", sh.language, sh.callee);
                hits.push(RuleHit {
                    rule: GuardRule {
                        name: name.clone(),
                        pattern: sh.callee.clone(),
                        stage: CheckStage::Semantic,
                        action: SafetyAction::Block,
                        risk_level: sh.risk,
                        reason: sh.reason.clone(),
                        scope: RuleScope::Content,
                    },
                    matched_text: sh.callee.clone(),
                    stage: CheckStage::Semantic,
                });
            }
        }
        hits
    }

    // 向后兼容: 不传 content_type 当 Shell (现有 caller/单测默认 shell 路径)。
    // 生产路径 (AuditEngine.evaluate) 调 evaluate_full_typed 传 IPC content_type。
    pub fn evaluate_full(&self, content: &str) -> Vec<RuleHit> {
        self.evaluate_full_typed(content, ContentType::Shell)
    }

    // L10: category 从实际 hit 派生 (非独立重复解析 + 固定 shell_exec fallback)。
    // 原实现独立 split_chain+shell_words 重解析, 与 tokenize_check 分叉 (split Err 即 continue
    // 跳段, tokenize_check 则 Block), 且 fallback "shell_exec" 对多数命令无意义 (cat/ls)。
    // 新实现: 从 hits 取 category —— scope 命中决定 category, 无 hit → "clean"。
    pub fn infer_category_from_hits(hits: &[RuleHit]) -> String {
        if hits.is_empty() {
            return "clean".to_string();
        }
        let top = hits.iter().max_by(|a, b| {
            let key = |h: &RuleHit| (h.rule.action.severity(), h.rule.risk_level.rank());
            key(a).cmp(&key(b))
        });
        let top = match top {
            Some(h) => h,
            None => return "clean".to_string(),
        };
        match top.rule.scope {
            RuleScope::Network => "network".to_string(),
            RuleScope::Filesystem => {
                if top.rule.action == SafetyAction::Block
                    && matches!(top.rule.risk_level, RiskLevel::L4)
                {
                    "file_write".to_string()
                } else {
                    "file_read".to_string()
                }
            }
            RuleScope::Content => format!("semantic:{}", top.rule.name),
            RuleScope::Command => {
                if top.rule.name.starts_with("ast:") {
                    top.rule.pattern.clone()
                } else {
                    "shell_exec".to_string()
                }
            }
        }
    }

    // 保留 content-based 推断供 evaluate "clean" 路径补全 category (无 hit 但有敏感内容)。
    // 仅在无 hit 时作 hint, 不再当权威 (权威由 infer_category_from_hits 从 hit 派生)。
    pub fn infer_category(content: &str) -> String {
        let trimmed = content.trim();
        if trimmed.is_empty() {
            return "unknown".to_string();
        }
        for seg in tokenizer::split_chain_pub(trimmed) {
            let words = match shell_words::split(&seg) {
                Ok(w) => w,
                Err(_) => continue,
            };
            if words.is_empty() {
                continue;
            }
            let mut idx = 0;
            while idx < words.len() && words[idx].contains('=') && !words[idx].starts_with('=') {
                idx += 1;
            }
            if idx >= words.len() {
                continue;
            }
            let bin = tokenizer::basename_pub(&words[idx]);
            match bin {
                "rm" | "sh" | "bash" | "zsh" | "dd" | "diskutil" | "mkfs" | "chmod" | "chown"
                | "kill" | "killall" => return "shell_exec".to_string(),
                "curl" | "wget" | "scp" | "rsync" | "nc" | "ssh" | "ftp" | "sftp" => {
                    return "network".to_string()
                }
                _ => {}
            }
            for (i, w) in words.iter().enumerate() {
                if (w == ">" || w == ">>")
                    && i + 1 < words.len()
                    && tokenizer::is_sensitive_path(&words[i + 1])
                {
                    return "file_write".to_string();
                }
            }
        }
        "read".to_string()
    }

    pub fn check_epoch(&self, caller_epoch: u64) -> Result<(), fg_core::GuardError> {
        let g = recover_lock!(self.inner.read(), "rule rwlock read");
        if caller_epoch != 0 && caller_epoch != g.epoch {
            tracing::warn!(
                caller_epoch = caller_epoch,
                guard_epoch = g.epoch,
                "stale epoch rejected"
            );
            return Err(fg_core::GuardError::StaleEpoch {
                caller: caller_epoch,
                guard: g.epoch,
            });
        }
        Ok(())
    }
}

pub fn default_ruleset() -> RuleSet {
    RuleSet {
        epoch: 1,
        rules: vec![GuardRule {
            name: "rm-rf".to_string(),
            pattern: r"\brm\s+-rf\b".to_string(),
            stage: CheckStage::Regex,
            action: SafetyAction::Block,
            risk_level: RiskLevel::L4,
            reason: "destructive recursive delete".to_string(),
            scope: RuleScope::Command,
        }],
    }
}

// L11: 显式优先级 (非 max_by_key as u8 任意平局)。
// 排序键: (动作严重度 desc, 风险等级 desc, stage rank desc)。确定性 head:
//   Block L4 Regex > Block L4 Semantic > Block L4 Ast > ... > Allow
// regex L4 rm-rf 与 semantic L4 os.system 平局时, stage rank 决定 (Regex 先报可信度高)。
// 消除"末 hit 胜"导致的 verdict stage/reason 依赖 push 顺序的脆性。
fn stage_rank(s: CheckStage) -> u8 {
    match s {
        CheckStage::Regex => 3,
        CheckStage::Ast => 2,
        CheckStage::Semantic => 1,
    }
}

pub fn verdict_from_hits(hits: &[RuleHit], epoch: u64) -> GuardVerdict {
    let top = hits.iter().max_by(|a, b| {
        let key = |h: &RuleHit| {
            (
                h.rule.action.severity(),
                h.rule.risk_level.rank(),
                stage_rank(h.stage),
            )
        };
        key(a).cmp(&key(b))
    });
    match top {
        Some(h) => {
            let seatbelt = matches!(h.rule.risk_level, RiskLevel::L3 | RiskLevel::L4)
                || h.rule.action == SafetyAction::Block;
            GuardVerdict {
                action: h.rule.action,
                risk_level: h.rule.risk_level,
                reason: h.rule.reason.clone(),
                stage: h.stage,
                requires_approval: matches!(h.rule.risk_level, RiskLevel::L3),
                redacted_content: None,
                seatbelt_required: seatbelt,
                action_id: None,
                verdict_epoch: epoch,
                verdict_ttl_secs: 30,
                inferred_category: h.rule.name.clone(),
                category_hint: None,
            }
        }
        None => GuardVerdict {
            action: SafetyAction::Allow,
            risk_level: RiskLevel::L1,
            reason: "no rule hit".to_string(),
            stage: CheckStage::Regex,
            requires_approval: false,
            redacted_content: None,
            seatbelt_required: false,
            action_id: None,
            verdict_epoch: epoch,
            verdict_ttl_secs: 30,
            inferred_category: "clean".to_string(),
            category_hint: None,
        },
    }
}
