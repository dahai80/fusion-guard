use fg_core::{CheckStage, GuardVerdict, RiskLevel, SafetyAction};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardRule {
    pub name: String,
    pub pattern: String,
    pub stage: CheckStage,
    pub action: SafetyAction,
    pub risk_level: RiskLevel,
    pub reason: String,
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

pub struct RuleEngine {
    rules: Vec<GuardRule>,
    compiled: Vec<regex::Regex>,
    epoch: u64,
}

impl RuleEngine {
    pub fn new(ruleset: RuleSet) -> Result<Self, regex::Error> {
        let mut compiled = Vec::with_capacity(ruleset.rules.len());
        for r in &ruleset.rules {
            compiled.push(regex::Regex::new(&r.pattern)?);
        }
        Ok(Self {
            rules: ruleset.rules,
            compiled,
            epoch: ruleset.epoch,
        })
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn evaluate(&self, content: &str) -> Vec<RuleHit> {
        let mut hits = Vec::new();
        for (rule, re) in self.rules.iter().zip(self.compiled.iter()) {
            if rule.stage != CheckStage::Regex {
                continue;
            }
            if let Some(m) = re.find(content) {
                hits.push(RuleHit {
                    rule: rule.clone(),
                    matched_text: m.as_str().to_string(),
                    stage: CheckStage::Regex,
                });
            }
        }
        hits
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
