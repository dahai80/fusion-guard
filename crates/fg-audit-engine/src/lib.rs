use fg_core::{ContentType, GuardVerdict, Result, RiskLevel, SafetyAction};
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

// Issue #1/#3 (PRD §6.7 / D-10): response payload of the frozen guard.audit contract with fusion-event.
// decision: pass | block | challenge (the fusion-event caller's three-state enum, not guard-internal SafetyAction).
//   Allow/Redact/Preview → pass; Block → block; L3 requires_approval → challenge.
// risk_level: integer 0..N (the caller expects an int, not a RiskLevel enum string) — rank() yields 0..3.
// audit_id: audit chain row primary key (Uuid); the caller uses it to look up/reconcile.
// trigger_id: echoes the caller's trigger_id so the caller can correlate request↔reply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditDecision {
    pub decision: String,
    pub reason: String,
    pub risk_level: u8,
    pub audit_id: uuid::Uuid,
    pub trigger_id: String,
}

pub struct AuditEngine {
    rules: RuleEngine,
    redactor: Redactor,
    store: Arc<AuditStore>,
    // P1-5 (audit §P1-5): mutex serializing the rule-mutation orchestration layer.
    // The three steps of add/update/remove (persist rule → in-memory add → persist epoch) are not atomic; two
    // concurrent add_rule threads each read epoch=N and write N+1 → one bump is lost: the epoch stays monotonic but
    // diverges from the rules. The in-memory RuleEngine's internal RwLock only guards its read/write set, not the
    // cross-step orchestration ordering. This Mutex serializes the three-step orchestration, keeping the epoch
    // strictly monotonic and consistent with the rules. evaluate only takes the RuleEngine read lock and never holds
    // this Mutex → the interception path is never blocked by mutations.
    rule_orch_lock: Arc<std::sync::Mutex<()>>,
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
                // M10/P0-G4: refuse startup if default-ruleset seeding fails (fail-closed), not a swallowed let _.
                let rs = default_ruleset();
                tracing::info!("no persisted rules, seeding default ruleset");
                for r in &rs.rules {
                    store.save_rule(r).map_err(|e| {
                        fg_core::GuardError::Engine(format!("seed rule persist failed: {e}"))
                    })?;
                }
                store.save_epoch(rs.epoch).map_err(|e| {
                    fg_core::GuardError::Engine(format!("seed epoch persist failed: {e}"))
                })?;
                rs
            }
        };
        let engine =
            RuleEngine::new(ruleset).map_err(|e| fg_core::GuardError::Engine(e.to_string()))?;
        let redactor = Redactor::new().map_err(|e| fg_core::GuardError::Engine(e.to_string()))?;
        Ok(Self {
            rules: engine,
            redactor,
            store,
            rule_orch_lock: Arc::new(std::sync::Mutex::new(())),
        })
    }

    pub fn epoch(&self) -> u64 {
        self.rules.epoch()
    }

    // L7/P1: stale-epoch check before rule mutation. caller_epoch != 0 and != guard epoch → StaleEpoch (-32003).
    // Prevents a caller from mutating the ruleset with a stale epoch (overwriting someone else's concurrent change).
    // evaluate already checks; the mutation path was missing this check.
    pub fn check_epoch(&self, caller_epoch: u64) -> Result<()> {
        self.rules.check_epoch(caller_epoch)
    }

    // P0-2 (audit §1.7/§1.8): content_type dispatches the scan stage. Shell→tokenizer, Code→semantic,
    // Json/Yaml/Text→regex only. Callers pass content_type via IPC (default Shell).
    pub fn evaluate(
        &self,
        content: &str,
        caller_epoch: u64,
        tenant_id: &str,
        content_type: ContentType,
        category_hint: Option<&str>,
    ) -> Result<GuardVerdict> {
        self.rules.check_epoch(caller_epoch)?;
        let hits = self.rules.evaluate_full_typed(content, content_type);
        let mut verdict = verdict_from_hits(&hits, self.rules.epoch());
        // P2-6 (audit §3.2/F6, PRD §6.3 H9): caller hint lands on the verdict (audit-visible caller claim).
        // The hint acts only as a risk floor (max(inferred, hit, hint)) — it can raise the level, never lower it,
        // preventing the v0.1 self-attested downgrade bypass. L3/L4 are always driven by real rule hits (not caller
        // claims); the hint floor caps at L2 (Redact/attention).
        verdict.category_hint = category_hint.map(|s| s.to_string());
        let floor = category_hint.and_then(hint_risk_floor);
        if let Some(floor_risk) = floor {
            if floor_risk > verdict.risk_level {
                tracing::debug!(
                    hint = ?category_hint,
                    before = ?verdict.risk_level,
                    floor = ?floor_risk,
                    "category_hint raised risk floor (P2-6 H9)"
                );
                verdict.risk_level = floor_risk;
                // Allow → Redact (the L2 floor requires masking/attention); leave Redact/L3/L4 actions untouched
                // (the floor only raises risk).
                if verdict.action == SafetyAction::Allow {
                    verdict.action = SafetyAction::Redact;
                }
            }
        }

        // L10: category is derived from hits (authoritative), not the rule.name written by verdict_from_hits.
        // rule.name is the rule identity (rm-rf/ast:nc); category is the semantic class (network/file_write/shell_exec).
        // Hit → infer_category_from_hits (scope → category). No hit → infer_category(content),
        // a content-based hint (cat/ls → "read", instead of blindly falling back to "shell_exec").
        if !hits.is_empty() {
            verdict.inferred_category = RuleEngine::infer_category_from_hits(&hits);
        } else {
            verdict.inferred_category = RuleEngine::infer_category(content);
        }
        tracing::debug!(
            rule_category = %verdict.inferred_category,
            hit_count = hits.len(),
            "category inference (H9, L10 derive-from-hit)"
        );

        // P2: single-pass redact_counted replaces the has_sensitive+redact double scan (4 regex ×2 → ×1).
        // hit_count>0 → sensitive content; Allow→Redact (L2), verdict.redacted_content set to the masked content.
        let (redacted, hit_count) = self.redactor.redact_counted(content);
        if hit_count > 0 {
            if verdict.action == SafetyAction::Allow {
                verdict.action = SafetyAction::Redact;
                verdict.risk_level = RiskLevel::L2;
            }
            verdict.redacted_content = Some(redacted);
        }

        if verdict.requires_approval || verdict.action == SafetyAction::Block {
            verdict.action_id = Some(Uuid::new_v4());
            // P1-3 (audit §2.5): pending action put is fail-closed.
            // L3 (requires_approval) needs the confirm flow; if put fails the action_id is delivered but no row is
            // persisted, so the caller's confirm finds no row → permanent dead end (L3 confirm flow broken).
            // L4 (Block) has no confirm path (H8), but a put failure breaks durable semantics the same way. Both
            // writes (pending put + H7 audit) happen in the same evaluate; durability must agree (H7 fail-closed
            // already landed on the audit side) → a put failure refuses the evaluation instead of returning a
            // verdict carrying an action_id.
            if let Err(e) = self.store.actions().put(&verdict, tenant_id) {
                tracing::error!(
                    error = %e,
                    action_id = ?verdict.action_id,
                    risk = ?verdict.risk_level,
                    "pending action put failed — refusing evaluate (P1-3 fail-closed, H7 durable consistency)"
                );
                return Err(fg_core::GuardError::Engine(format!(
                    "pending action persist failed: {e}"
                )));
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
        self.redact_tenant(content, reversible, fg_store::DEFAULT_TENANT)
    }

    // C2: reversible redaction tokens are tenant-bound; reveal verifies ownership (cuts the cross-tenant leak chain).
    pub fn redact_tenant(
        &self,
        content: &str,
        reversible: bool,
        tenant_id: &str,
    ) -> Result<RedactResult> {
        let _ = self.store.tokens().evict_expired();
        if reversible {
            let (redacted, matches) = self.redactor.redact_reversible(content);
            let tokens = self.store.tokens();
            for m in &matches {
                if let Err(e) = tokens.put_tenant(&m.token_id, &m.original, tenant_id) {
                    tracing::warn!(error = %e, token_id = %m.token_id, "token store put failed");
                }
            }
            tracing::info!(
                redacted_len = redacted.len(),
                token_count = matches.len(),
                tenant = tenant_id,
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

    // issue #7: expose a serializable dump of the 15 redaction pattern definitions (guard.redact.patterns.dump).
    // Patterns are global (not tenant-scoped); pass through Redactor::pattern_defs directly.
    pub fn pattern_defs(&self) -> Vec<fg_redact::PatternDefDump> {
        self.redactor.pattern_defs()
    }

    pub fn reveal(&self, content: &str, _token_map_id: &str) -> Result<String> {
        self.reveal_tenant(content, fg_store::DEFAULT_TENANT)
    }

    // C2: reveal verifies token ownership against the caller's tenant; cross-tenant access is rejected (H6 fallback).
    pub fn reveal_tenant(&self, content: &str, tenant_id: &str) -> Result<String> {
        // P4: evict expired tokens before reveal too (not just the redact path), preventing TTL-expired tokens
        // from accumulating in the store.
        let _ = self.store.tokens().evict_expired();
        let tokens = self.store.tokens();
        let placeholders = self.redactor.extract_placeholders(content);
        let mut restored = content.to_string();
        let mut recovered = 0usize;
        let mut failed = 0usize;
        for (kind, token_id) in &placeholders {
            let _ = tokens.set_in_flight(token_id, true);
            match tokens.get_tenant(token_id, tenant_id) {
                Ok(original) => {
                    let ph = format!("[REDACTED:{}#{}]", kind, token_id);
                    restored = restored.replace(&ph, &original);
                    recovered += 1;
                }
                Err(e) => {
                    tracing::warn!(error = %e, token_id = token_id, tenant = tenant_id, "token reveal failed (H6 fallback / C2 cross-tenant)");
                    let ph = format!("[REDACTED:{}#{}]", kind, token_id);
                    let fb = format!("[REDACTED:unrecoverable#{}]", &token_id[..8]);
                    restored = restored.replace(&ph, &fb);
                    failed += 1;
                }
            }
            let _ = tokens.set_in_flight(token_id, false);
        }
        tracing::info!(
            recovered = recovered,
            failed = failed,
            tenant = tenant_id,
            "guard.reveal done"
        );
        Ok(restored)
    }

    // G6/L2+A8/C9/C20: confirm goes through confirm_atomic — the consume UPDATE and the confirm audit INSERT
    // run in the same critical section (ActionStore.db lock held throughout, audit_writer lock nested), ordered
    // audit-then-consume.
    // C9: H8 checks the risk_level column, not the JSON blob, plus cross-validation. C20: cross-tenant confirm rejected.
    // Audit failure → refuse to consume (the action stays re-confirmable; no consumed-without-audit permanent gap).
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
            .confirm_atomic(
                action_id,
                approved,
                approved_by,
                tenant_id,
                &self.store.audit_writer_handle(),
                &self.store.chain_key_handle(),
                self.store.current_key_version(),
            )
            .map_err(|e| {
                tracing::warn!(error = %e, action_id = action_id, "confirm failed");
                fg_core::GuardError::Engine(e.to_string())
            })?;
        tracing::info!(
            action_id = action_id,
            approved = approved,
            tenant = tenant_id,
            "guard.confirm handled (atomic audit-then-consume, C9/C20/L2)"
        );
        Ok(ConfirmResult { verdict })
    }

    // Issue #1/#3 (PRD §6.7 / D-10, frozen fusion-event contract): inbound guard.audit RPC.
    // fusion-event calls this before dispatching an Agent Task trigger to audit permission/injection risk.
    // Concatenate the event fields (event_type/target_path/target_agent/payload) into the content to scan,
    // reuse evaluate (regex + tokenizer/semantic + redact), and map the verdict → the three-state decision.
    // audit_id comes from the append_event chain row; trigger_id is echoed verbatim (for caller correlation).
    // H4's 2s timeout is enforced by the IPC layer; this returns synchronously and never blocks the callback
    // (the callback is fusion-event's reverse path, see audit_result).
    // 9 parameters = frozen fusion-event contract fields (D-10), must not be trimmed; clippy too_many_arguments
    // explicitly allowed.
    #[allow(clippy::too_many_arguments)]
    pub fn audit_event(
        &self,
        trigger_id: &str,
        event_type: &str,
        target_path: &str,
        target_agent: &str,
        payload: &serde_json::Value,
        node_id: &str,
        tenant_id: &str,
        requester: &str,
    ) -> Result<AuditDecision> {
        // Assemble the scan content: target_path most likely carries injection vectors (paths/shell metacharacters),
        // placed first; event_type/target_agent/node_id act as label context; the serialized payload goes last
        // (KV pairs may hide credentials/commands).
        // Newline separators keep field values from gluing together and causing false hits. Empty object/missing
        // payload → skip, no "null".
        let payload_str = match payload {
            serde_json::Value::Null => String::new(),
            v @ serde_json::Value::Object(_) => v.to_string(),
            v => v.to_string(),
        };
        let content = if payload_str.is_empty() {
            format!("{target_path}\n{event_type}\n{target_agent}\n{node_id}")
        } else {
            format!("{target_path}\n{event_type}\n{target_agent}\n{node_id}\n{payload_str}")
        };
        // Events are mostly path/label text, not executable shell — use the Text scan stage (regex only, skipping
        // tokenizer/semantic). If target_path contains shell metacharacters, regex hits on rm-rf etc. still Block
        // (the rules do not depend on the tokenizer).
        let verdict = self.evaluate(&content, 0, tenant_id, ContentType::Text, None)?;
        // Three-state decision mapping (fusion-event contract): Block→block, L3 requires_approval→challenge,
        // everything else → pass.
        // Redact (L2 sensitive masking) maps to pass — already audit-logged, do not block the trigger (DLP masking
        // is not a permission denial).
        let decision = match verdict.action {
            SafetyAction::Block => "block",
            _ if verdict.requires_approval => "challenge",
            _ => "pass",
        };
        let redacted = verdict.redacted_content.clone().unwrap_or_default();
        let ev = self
            .store
            .append_event(tenant_id, &verdict, redacted, requester)
            .map_err(|e| fg_core::GuardError::Engine(format!("audit append failed: {e}")))?;
        tracing::info!(
            trigger_id = trigger_id,
            event_type = event_type,
            target_agent = target_agent,
            node_id = node_id,
            decision = decision,
            risk = ?verdict.risk_level,
            audit_id = %ev.audit_id,
            "guard.audit handled (fusion-event contract D-10)"
        );
        Ok(AuditDecision {
            decision: decision.to_string(),
            reason: verdict.reason.clone(),
            risk_level: verdict.risk_level.rank(),
            audit_id: ev.audit_id,
            trigger_id: trigger_id.to_string(),
        })
    }

    fn persist(&self, new_epoch: u64) -> Result<()> {
        self.store
            .save_epoch(new_epoch)
            .map_err(|e| fg_core::GuardError::Engine(e.to_string()))?;
        Ok(())
    }

    // L1/P0-G4: commit disk first, memory second; any persistence failure → roll back memory + return error (fail-closed).
    // Order: save_rule(disk) → engine.add(memory, compiles and validates the regex) → save_epoch(disk).
    // engine.add failure (regex/duplicate) → delete_rule rolls back the already-written disk row.
    // save_epoch failure → roll back memory + disk.
    // P1-5: rule_orch_lock held throughout to serialize the three-step orchestration, preventing concurrent
    // add_rule from losing an epoch bump.
    pub fn add_rule(&self, rule: GuardRule) -> std::result::Result<u64, RuleError> {
        let _orch = self
            .rule_orch_lock
            .lock()
            .map_err(|_| RuleError::NotFound("rule orchestration lock poisoned".into()))?;
        self.store
            .save_rule(&rule)
            .map_err(|e| {
                tracing::error!(error = %e, name = %rule.name, "add_rule: save_rule failed (fail-closed)");
                RuleError::NotFound(format!("persist failed: {e}"))
            })?;
        let new_epoch = match self.rules.add(rule.clone()) {
            Ok(ep) => ep,
            Err(e) => {
                let _ = self.store.delete_rule(&rule.name);
                tracing::warn!(error = %e, name = %rule.name, "add_rule: engine.add failed, rolled back disk");
                return Err(e);
            }
        };
        if let Err(e) = self.persist(new_epoch) {
            tracing::error!(error = %e, "add_rule: save_epoch failed, rolling back");
            let _ = self.store.delete_rule(&rule.name);
            self.rules.remove(&rule.name).ok();
            return Err(RuleError::NotFound(format!("epoch persist failed: {e}")));
        }
        tracing::info!(new_epoch = new_epoch, name = %rule.name, "guard.rule.add handled (fail-closed)");
        Ok(new_epoch)
    }

    pub fn update_rule(&self, name: &str, rule: GuardRule) -> std::result::Result<u64, RuleError> {
        // P1-5: hold rule_orch_lock to serialize the three-step orchestration (mutually exclusive with
        // add/remove), keeping the epoch consistent.
        let _orch = self
            .rule_orch_lock
            .lock()
            .map_err(|_| RuleError::NotFound("rule orchestration lock poisoned".into()))?;
        self.store
            .save_rule(&rule)
            .map_err(|e| {
                tracing::error!(error = %e, name = %rule.name, "update_rule: save_rule failed (fail-closed)");
                RuleError::NotFound(format!("persist failed: {e}"))
            })?;
        if name != rule.name {
            if let Err(e) = self.store.delete_rule(name) {
                tracing::warn!(error = %e, old = name, "update_rule: old name delete failed");
            }
        }
        let new_epoch = match self.rules.update(name, rule.clone()) {
            Ok(ep) => ep,
            Err(e) => {
                if name != rule.name {
                    let _ = self.store.delete_rule(&rule.name);
                }
                tracing::warn!(error = %e, name = name, "update_rule: engine.update failed, rolled back disk");
                return Err(e);
            }
        };
        if let Err(e) = self.persist(new_epoch) {
            tracing::error!(error = %e, "update_rule: save_epoch failed");
            return Err(RuleError::NotFound(format!("epoch persist failed: {e}")));
        }
        tracing::info!(
            new_epoch = new_epoch,
            name = name,
            "guard.rule.update handled (fail-closed)"
        );
        Ok(new_epoch)
    }

    pub fn remove_rule(&self, name: &str) -> std::result::Result<u64, RuleError> {
        // P1-5: hold rule_orch_lock to serialize the three-step orchestration (mutually exclusive with
        // add/update), keeping the epoch consistent.
        let _orch = self
            .rule_orch_lock
            .lock()
            .map_err(|_| RuleError::NotFound("rule orchestration lock poisoned".into()))?;
        self.store
            .delete_rule(name)
            .map_err(|e| {
                tracing::error!(error = %e, name = name, "remove_rule: delete_rule failed (fail-closed)");
                RuleError::NotFound(format!("persist failed: {e}"))
            })?;
        let new_epoch = self.rules.remove(name)?;
        if let Err(e) = self.persist(new_epoch) {
            tracing::error!(error = %e, "remove_rule: save_epoch failed");
            return Err(RuleError::NotFound(format!("epoch persist failed: {e}")));
        }
        tracing::info!(
            new_epoch = new_epoch,
            name = name,
            "guard.rule.remove handled (fail-closed)"
        );
        Ok(new_epoch)
    }

    pub fn tcc_status(&self) -> Vec<fg_tcc::TccStatus> {
        fg_tcc::query_status()
    }

    pub fn report_tcc(
        &self,
        permission: &str,
        requester: &str,
        result: &str,
        reason: &str,
    ) -> Result<uuid::Uuid> {
        let id = self
            .store
            .report_tcc_event(permission, requester, result, reason)
            .map_err(|e| fg_core::GuardError::Engine(e.to_string()))?;
        Ok(id)
    }

    pub fn list_tcc_events(&self, limit: usize) -> Result<Vec<fg_store::TccEventRecord>> {
        self.store
            .list_tcc_events(limit)
            .map_err(|e| fg_core::GuardError::Engine(e.to_string()))
    }

    // P0-7 (audit §2.8): ES monitor integration (not dead code). No entitlement → degraded (Q#3 falls back to TCC);
    // with entitlement → Active + event stream. status/events exposed via IPC so ops sees the real state (not
    // faked availability).
    pub fn es_status(&self) -> fg_es::EsStatus {
        let kinds = fg_es::default_kinds();
        let mut monitor = fg_es::EsMonitor::new(kinds);
        monitor.start()
    }

    pub fn es_events(&self) -> Vec<fg_es::EsEvent> {
        let kinds = fg_es::default_kinds();
        let monitor = fg_es::EsMonitor::new(kinds);
        monitor.monitor_events()
    }
}

// P2-6 (audit §3.2/F6, PRD §6.3 H9): category_hint → pure risk-floor decision.
// The caller hint can only raise the level, never lower it; the floor caps at L2 (L3/L4 are driven by real rule
// hits, not caller claims).
// Known high-risk categories (shell_exec/network/file_write) → L2 floor; read/clean/unknown → None (no floor).
// Rule 5: decide with code, not tokens — a pure fn is unit-testable, not inline engine logic.
pub fn hint_risk_floor(hint: &str) -> Option<RiskLevel> {
    match hint {
        "shell_exec" | "network" | "file_write" => Some(RiskLevel::L2),
        // read/clean/unknown categories: a low-risk caller claim does not raise the floor (the reverse direction
        // is not trusted); unknown does not invent risk.
        _ => None,
    }
}
