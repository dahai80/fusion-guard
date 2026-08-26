use fg_core::{GuardVerdict, RiskLevel, SafetyAction};
use fg_redact::Redactor;
use fg_rules::{RuleEngine, verdict_from_hits};
use uuid::Uuid;

pub struct AuditEngine {
    rules: RuleEngine,
    redactor: Redactor,
}

impl AuditEngine {
    pub fn new(rules: RuleEngine) -> Self {
        Self {
            rules,
            redactor: Redactor::new(),
        }
    }

    pub fn epoch(&self) -> u64 {
        self.rules.epoch()
    }

    pub fn evaluate(&self, content: &str) -> GuardVerdict {
        let hits = self.rules.evaluate(content);
        let mut verdict = verdict_from_hits(&hits, self.rules.epoch());

        if self.redactor.has_sensitive(content) {
            if verdict.action == SafetyAction::Allow {
                verdict.action = SafetyAction::Redact;
                verdict.risk_level = RiskLevel::L2;
            }
            verdict.redacted_content = Some(self.redactor.redact(content));
        }

        if verdict.requires_approval || verdict.action == SafetyAction::Block {
            verdict.action_id = Some(Uuid::new_v4());
        }

        tracing::info!(
            category = %verdict.inferred_category,
            action = ?verdict.action,
            risk = ?verdict.risk_level,
            "guard.evaluate verdict"
        );
        verdict
    }
}
