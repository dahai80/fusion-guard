use fg_core::{GuardVerdict, Result, RiskLevel, SafetyAction};
use fg_redact::Redactor;
use fg_rules::{default_ruleset, verdict_from_hits, GuardRule, RuleEngine, RuleError, RuleSet};
use fg_store::AuditStore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactResult {
    pub redacted_content: String,
    pub token_map_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmResult {
    pub verdict: GuardVerdict,
}

pub struct AuditEngine {
    rules: RuleEngine,
    redactor: Redactor,
    store: Arc<AuditStore>,
}

impl AuditEngine {
    pub fn new(store: Arc<AuditStore>) -> Result<Self> {
        let ruleset = match store
            .load_rules()
            .map_err(|e| fg_core::GuardError::Engine(e.to_string()))?
        {
            Some(rs) if !rs.rules.is_empty() => {
                tracing::info!(
                    epoch = rs.epoch,
                    count = rs.rules.len(),
                    "bootstrapped rules from store"
                );
                rs
            }
            _ => {
                let rs = default_ruleset();
                tracing::info!("no persisted rules, seeding default ruleset");
                for r in &rs.rules {
                    let _ = store.save_rule(r);
                }
                let _ = store.save_epoch(rs.epoch);
                rs
            }
        };
        let engine =
            RuleEngine::new(ruleset).map_err(|e| fg_core::GuardError::Engine(e.to_string()))?;
        Ok(Self {
            rules: engine,
            redactor: Redactor::new(),
            store,
        })
    }

    pub fn epoch(&self) -> u64 {
        self.rules.epoch()
    }

    pub fn evaluate(&self, content: &str, caller_epoch: u64) -> Result<GuardVerdict> {
        self.rules.check_epoch(caller_epoch)?;
        let hits = self.rules.evaluate_full(content);
        let mut verdict = verdict_from_hits(&hits, self.rules.epoch());

        let inferred = RuleEngine::infer_category(content);
        if verdict.inferred_category == "clean" {
            verdict.inferred_category = inferred.clone();
        }
        tracing::debug!(
            inferred_category = %inferred,
            rule_category = %verdict.inferred_category,
            "category inference (H9)"
        );

        if self.redactor.has_sensitive(content) {
            if verdict.action == SafetyAction::Allow {
                verdict.action = SafetyAction::Redact;
                verdict.risk_level = RiskLevel::L2;
            }
            verdict.redacted_content = Some(self.redactor.redact(content));
        }

        if verdict.requires_approval || verdict.action == SafetyAction::Block {
            verdict.action_id = Some(Uuid::new_v4());
            if let Err(e) = self.store.actions().put(&verdict) {
                tracing::warn!(error = %e, "pending action store put failed");
            }
        }

        tracing::info!(
            category = %verdict.inferred_category,
            action = ?verdict.action,
            risk = ?verdict.risk_level,
            epoch = verdict.verdict_epoch,
            "guard.evaluate verdict"
        );
        Ok(verdict)
    }

    pub fn list_rules(&self) -> RuleSet {
        self.rules.list()
    }

    pub fn redact(&self, content: &str, reversible: bool) -> Result<RedactResult> {
        let _ = self.store.tokens().evict_expired();
        if reversible {
            let (redacted, matches) = self.redactor.redact_reversible(content);
            let tokens = self.store.tokens();
            for m in &matches {
                if let Err(e) = tokens.put(&m.token_id, &m.original) {
                    tracing::warn!(error = %e, token_id = %m.token_id, "token store put failed");
                }
            }
            tracing::info!(
                redacted_len = redacted.len(),
                token_count = matches.len(),
                "guard.redact reversible"
            );
            Ok(RedactResult {
                redacted_content: redacted,
                token_map_id: matches.first().map(|m| m.token_id.clone()),
            })
        } else {
            let redacted = self.redactor.redact_irreversible(content);
            tracing::info!(redacted_len = redacted.len(), "guard.redact irreversible");
            Ok(RedactResult {
                redacted_content: redacted,
                token_map_id: None,
            })
        }
    }

    pub fn reveal(&self, content: &str, _token_map_id: &str) -> Result<String> {
        let tokens = self.store.tokens();
        let placeholders = self.redactor.extract_placeholders(content);
        let mut restored = content.to_string();
        let mut recovered = 0usize;
        let mut failed = 0usize;
        for (kind, token_id) in &placeholders {
            let _ = tokens.set_in_flight(token_id, true);
            match tokens.get(token_id) {
                Ok(original) => {
                    let ph = format!("[REDACTED:{}#{}]", kind, token_id);
                    restored = restored.replace(&ph, &original);
                    recovered += 1;
                }
                Err(e) => {
                    tracing::warn!(error = %e, token_id = token_id, "token reveal failed (H6 fallback)");
                    let ph = format!("[REDACTED:{}#{}]", kind, token_id);
                    let fb = format!("[REDACTED:unrecoverable#{}]", &token_id[..8]);
                    restored = restored.replace(&ph, &fb);
                    failed += 1;
                }
            }
            let _ = tokens.set_in_flight(token_id, false);
        }
        tracing::info!(recovered = recovered, failed = failed, "guard.reveal done");
        Ok(restored)
    }

    pub fn confirm(
        &self,
        action_id: &str,
        approved: bool,
        approved_by: &str,
        tenant_id: &str,
    ) -> Result<ConfirmResult> {
        let _ = self.store.actions().evict_expired();
        let verdict = self
            .store
            .actions()
            .confirm(action_id, approved, approved_by)
            .map_err(|e| {
                tracing::warn!(error = %e, action_id = action_id, "confirm failed");
                match e {
                    fg_store::ActionError::AbsoluteBlock(_) => {
                        fg_core::GuardError::Engine(e.to_string())
                    }
                    _ => fg_core::GuardError::Engine(e.to_string()),
                }
            })?;
        let outcome = match verdict.action {
            SafetyAction::Allow => "approved",
            SafetyAction::Block => "rejected",
            _ => "confirmed",
        };
        if let Err(e) = self
            .store
            .append_confirm_event(tenant_id, &verdict, approved_by, outcome)
        {
            tracing::error!(error = %e, "confirm audit append failed");
        }
        tracing::info!(
            action_id = action_id,
            approved = approved,
            outcome = outcome,
            "guard.confirm handled"
        );
        Ok(ConfirmResult { verdict })
    }

    fn persist(&self, new_epoch: u64) -> Result<()> {
        self.store
            .save_epoch(new_epoch)
            .map_err(|e| fg_core::GuardError::Engine(e.to_string()))?;
        Ok(())
    }

    pub fn add_rule(&self, rule: GuardRule) -> std::result::Result<u64, RuleError> {
        let new_epoch = self.rules.add(rule.clone())?;
        if let Err(e) = self.store.save_rule(&rule) {
            tracing::error!(error = %e, "rule persist failed");
        }
        let _ = self.persist(new_epoch);
        Ok(new_epoch)
    }

    pub fn update_rule(&self, name: &str, rule: GuardRule) -> std::result::Result<u64, RuleError> {
        let new_epoch = self.rules.update(name, rule.clone())?;
        if let Err(e) = self.store.save_rule(&rule) {
            tracing::error!(error = %e, "rule persist failed");
        }
        if name != rule.name {
            if let Err(e) = self.store.delete_rule(name) {
                tracing::warn!(error = %e, "old rule name delete failed");
            }
        }
        let _ = self.persist(new_epoch);
        Ok(new_epoch)
    }

    pub fn remove_rule(&self, name: &str) -> std::result::Result<u64, RuleError> {
        let new_epoch = self.rules.remove(name)?;
        if let Err(e) = self.store.delete_rule(name) {
            tracing::warn!(error = %e, "rule delete failed");
        }
        let _ = self.persist(new_epoch);
        Ok(new_epoch)
    }
}
