use fg_core::{CheckStage, GuardVerdict, RiskLevel, RuleScope, SafetyAction};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

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
        self.inner.read().expect("rule rwlock poisoned").epoch
    }

    pub fn list(&self) -> RuleSet {
        let g = self.inner.read().expect("rule rwlock poisoned");
        RuleSet {
            epoch: g.epoch,
            rules: g.rules.clone(),
        }
    }

    pub fn add(&self, rule: GuardRule) -> Result<u64, RuleError> {
        let re = regex::Regex::new(&rule.pattern)?;
        let mut g = self.inner.write().expect("rule rwlock poisoned");
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
        let mut g = self.inner.write().expect("rule rwlock poisoned");
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
        let mut g = self.inner.write().expect("rule rwlock poisoned");
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
        let g = self.inner.read().expect("rule rwlock poisoned");
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

    pub fn check_epoch(&self, caller_epoch: u64) -> Result<(), fg_core::GuardError> {
        let g = self.inner.read().expect("rule rwlock poisoned");
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

pub fn verdict_from_hits(hits: &[RuleHit], epoch: u64) -> GuardVerdict {
    let top = hits.iter().max_by_key(|h| h.rule.risk_level as u8);
    match top {
        Some(h) => GuardVerdict {
            action: h.rule.action,
            risk_level: h.rule.risk_level,
            reason: h.rule.reason.clone(),
            stage: h.stage,
            requires_approval: matches!(h.rule.risk_level, RiskLevel::L3),
            redacted_content: None,
            seatbelt_required: false,
            action_id: None,
            verdict_epoch: epoch,
            verdict_ttl_secs: 30,
            inferred_category: h.rule.name.clone(),
        },
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
        },
    }
}
