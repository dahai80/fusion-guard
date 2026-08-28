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

// Issue #1/#3 (PRD §6.7 / D-10): fusion-event 冻结契约 guard.audit 的应答载荷。
// decision: pass | block | challenge (caller fusion-event 的三态枚举, 非 guard 内部 SafetyAction)。
//   Allow/Redact/Preview → pass; Block → block; L3 requires_approval → challenge。
// risk_level: 0..N 整数 (caller 期望 int, 非 RiskLevel 枚举字符串) —— rank() 即 0..3。
// audit_id: 审计链行主键 (Uuid), caller 据此回查/对账。
// trigger_id: 透传 caller 的 trigger_id (回声), 便于 caller 关联 request↔reply。
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
                // M10/P0-G4: 种子持久化失败拒启动 (fail-closed), 非 let _ = 吞。
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
        })
    }

    pub fn epoch(&self) -> u64 {
        self.rules.epoch()
    }

    // L7/P1: 规则突变前 stale-epoch 校验。caller_epoch 非 0 且 != guard epoch → StaleEpoch (-32003)。
    // 防 caller 用旧 epoch 突变规则集 (覆盖他人并发改动)。evaluate 已查, 突变路径此前漏查。
    pub fn check_epoch(&self, caller_epoch: u64) -> Result<()> {
        self.rules.check_epoch(caller_epoch)
    }

    // P0-2 (audit §1.7/§1.8): content_type 分派扫描阶段。Shell→tokenizer, Code→semantic,
    // Json/Yaml/Text→仅 regex。调用方经 IPC 传 content_type (默认 Shell)。
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
        // P2-6 (audit §3.2/F6, PRD §6.3 H9): 调用方 hint 落 verdict (审计可见调用方主张)。
        // hint 仅作风险地板 (max(推断, 命中, hint)) —— 抬高等级永不压低, 防 v0.1 自证降级绕过。
        // L3/L4 始终由真实规则命中驱动 (非 caller 声明), hint 地板封顶 L2 (Redact/attention)。
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
                // Allow → Redact (L2 地板要求脱敏/留意); 已 Redact/L3/L4 不动 action (地板只抬 risk)。
                if verdict.action == SafetyAction::Allow {
                    verdict.action = SafetyAction::Redact;
                }
            }
        }

        // L10: category 从 hits 派生 (权威), 非 verdict_from_hits 写的 rule.name。
        // rule.name 是规则标识 (rm-rf/ast:nc), category 是语义类 (network/file_write/shell_exec)。
        // 有 hit → infer_category_from_hits (scope → category)。无 hit → infer_category(content)
        // content-based hint (cat/ls → "read", 不再无脑 fallback "shell_exec")。
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

        // P2: 单次遍历 redact_counted 取代 has_sensitive+redact 二扫 (4 regex ×2 → ×1)。
        // 命中数>0 → 敏感内容; Allow→Redact (L2), verdict.redacted_content 置脱敏后内容。
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
            // P1-3 (audit §2.5): pending action put fail-closed。
            // L3 (requires_approval) 需 confirm 流, put 失败 → action_id 交付但无落盘行,
            // caller confirm 查无此行 → 永久死胡同 (L3 确认流断)。L4 (Block) 无 confirm 路径 (H8),
            // 但 put 失败同样耐久语义断层。两套写 (pending put + H7 审计) 同一次 evaluate,
            // 耐久性须一致 (H7 fail-closed 已落地审计侧) → put 失败拒评估, 不下发带 action_id 的 verdict。
            if let Err(e) = self.store.actions().put(&verdict, tenant_id) {
                tracing::error!(
                    error = %e,
                    action_id = ?verdict.action_id,
                    risk = ?verdict.risk_level,
                    "pending action put failed — refusing evaluate (P1-3 fail-closed, H7 耐久一致)"
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

    // C2: 可逆脱敏 token 绑定租户, reveal 校验归属 (斩跨租户外泄链)。
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

    // issue #7: 暴露 15 redaction pattern 定义的可序列化 dump (guard.redact.patterns.dump)。
    // pattern 全局 (非租户 scoped), 直接透传 Redactor::pattern_defs。
    pub fn pattern_defs(&self) -> Vec<fg_redact::PatternDefDump> {
        self.redactor.pattern_defs()
    }

    pub fn reveal(&self, content: &str, _token_map_id: &str) -> Result<String> {
        self.reveal_tenant(content, fg_store::DEFAULT_TENANT)
    }

    // C2: reveal 按调用方租户校验 token 归属, 跨租户拒绝 (H6 fallback)。
    pub fn reveal_tenant(&self, content: &str, tenant_id: &str) -> Result<String> {
        // P4: reveal 前也驱逐过期 token (非仅 redact 路径), 防 TTL 过期 token 累积占库。
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

    // G6/L2+A8/C9/C20: confirm 走 confirm_atomic —— consume UPDATE 与 confirm 审计 INSERT
    // 在同一临界区 (ActionStore.db 锁全程持, audit_writer 锁内嵌), 顺序 audit-then-consume。
    // C9: H8 查 risk_level 列非 JSON blob + 交叉校验。C20: 跨租户 confirm 拒绝。
    // 审计失败 → 拒绝 consume (动作仍可重 confirm, 不留已消费无审计永久缺口)。
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

    // Issue #1/#3 (PRD §6.7 / D-10, fusion-event 冻结契约): guard.audit 入站 RPC。
    // fusion-event 在下发 Agent Task trigger 前, 调此方法做权限/注入风险审计。
    // 把 event 字段 (event_type/target_path/target_agent/payload) 拼成待扫描 content,
    // 复用 evaluate (regex + tokenizer/semantic + redact), 映射 verdict → decision 三态。
    // audit_id 来自 append_event 落链行; trigger_id 原样回声 (caller 关联用)。
    // H4 2s 超时由 IPC 层保证; 此处同步返, 不阻塞回调 (回调是 fusion-event 反向路径, 见 audit_result)。
    // 9 参数 = fusion-event 冻结契约字段 (D-10), 不可裁剪; clippy too_many_arguments 显式放行。
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
        // 拼扫描 content: target_path 最可能含注入向量 (路径/shell 元字符), 置首;
        // event_type/target_agent/node_id 作标签上下文; payload 序列化挂尾 (含 KV 可能藏凭据/命令)。
        // 用换行分隔避免字段值粘连误命中。payload 空 object/缺省 → 跳过, 不挂 "null"。
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
        // event 多为路径/标签文本, 非可执行 shell —— 用 Text 扫描阶段 (仅 regex, 跳 tokenizer/semantic)。
        // target_path 含 shell 元字符时 regex 命中 rm-rf 等模式仍 Block (规则不依赖 tokenizer)。
        let verdict = self.evaluate(&content, 0, tenant_id, ContentType::Text, None)?;
        // decision 三态映射 (fusion-event 契约): Block→block, L3 requires_approval→challenge, 余→pass。
        // Redact (L2 敏感脱敏) 归 pass —— 审计已记录, 不阻断 trigger (DLP 脱敏非权限拒)。
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

    // L1/P0-G4: disk 先 commit, 内存后 commit; 任一持久化失败 → 回滚内存 + 返错 (fail-closed)。
    // 顺序: save_rule(disk) → engine.add(memory, 编译 regex 验证) → save_epoch(disk)。
    // engine.add 失败 (regex/重复) → delete_rule 回滚已写 disk。save_epoch 失败 → 回滚内存 + disk。
    pub fn add_rule(&self, rule: GuardRule) -> std::result::Result<u64, RuleError> {
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

    // P0-7 (audit §2.8): ES 监控接入 (非 dead-code)。无 entitlement → degraded (Q#3 回退 TCC),
    // 有 entitlement → Active + 事件流。status/events 经 IPC 暴露, 运维可见真实状态 (非假装可用)。
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

// P2-6 (audit §3.2/F6, PRD §6.3 H9): category_hint → 风险地板纯决策。
// caller hint 仅抬等级不压低, 地板封顶 L2 (L3/L4 由真实规则命中驱动, 非 caller 声明)。
// 已知高风险 category (shell_exec/network/file_write) → L2 地板; read/clean/未知 → None (无地板)。
// 规则 5: 决策用代码非 token —— 纯 fn 可单测, 非 engine 内联逻辑。
pub fn hint_risk_floor(hint: &str) -> Option<RiskLevel> {
    match hint {
        "shell_exec" | "network" | "file_write" => Some(RiskLevel::L2),
        // read/clean/未知 category: 调用方主张低风险不抬地板 (反方向不取信), 未知不臆造风险。
        _ => None,
    }
}
