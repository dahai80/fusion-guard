use fg_core::{GuardVerdict, RiskLevel};
use rusqlite::{params, Connection};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

const ACTION_TTL_SECS: i64 = 30;

pub struct ActionStore {
    db: Mutex<Connection>,
}

#[derive(Debug, thiserror::Error)]
pub enum ActionError {
    #[error("action not found: {0}")]
    NotFound(String),
    #[error("action expired: {0}")]
    Expired(String),
    #[error("action already consumed: {0}")]
    Consumed(String),
    #[error("L4 absolute block has no confirm path: {0}")]
    AbsoluteBlock(String),
    #[error("cross-tenant confirm denied: action tenant {stored}, caller {caller}")]
    CrossTenant { stored: String, caller: String },
    #[error("risk column tampered: stored {stored}, verdict_json {json}")]
    RiskTampered { stored: i64, json: String },
    #[error("audit persist failed: {0}")]
    AuditFailed(String),
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
}

#[derive(Debug, Clone)]
pub struct PendingAction {
    pub action_id: String,
    pub verdict: GuardVerdict,
    pub created_ts: i64,
    pub consumed: bool,
}

impl ActionStore {
    pub fn open(conn: Connection) -> Result<Self, ActionError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS pending_actions (
                action_id TEXT PRIMARY KEY,
                verdict_json TEXT NOT NULL,
                risk_level INTEGER NOT NULL,
                created_ts INTEGER NOT NULL,
                consumed INTEGER NOT NULL DEFAULT 0,
                ttl_secs INTEGER NOT NULL,
                tenant_id TEXT NOT NULL DEFAULT 'default'
            );
            CREATE INDEX IF NOT EXISTS idx_pending_ts ON pending_actions(created_ts);
            ",
        )?;
        // C20 旧库迁移: 加 tenant_id 列 (幂等)
        let _ = conn.execute(
            "ALTER TABLE pending_actions ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'",
            [],
        );
        Ok(Self {
            db: Mutex::new(conn),
        })
    }

    pub fn put(&self, verdict: &GuardVerdict, tenant_id: &str) -> Result<(), ActionError> {
        let action_id = match verdict.action_id {
            Some(id) => id.to_string(),
            None => return Ok(()),
        };
        let risk = verdict.risk_level as i64;
        let j = serde_json::to_string(verdict)?;
        let now = now_ts();
        let g = recover_lock!(self.db.lock(), "action db");
        g.execute(
            "INSERT OR REPLACE INTO pending_actions
             (action_id, verdict_json, risk_level, created_ts, consumed, ttl_secs, tenant_id)
             VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6)",
            params![action_id, j, risk, now, ACTION_TTL_SECS, tenant_id],
        )?;
        tracing::debug!(
            action_id = action_id,
            tenant = tenant_id,
            "pending action stored (tenant-bound)"
        );
        Ok(())
    }

    // G6/L2+A8/C9/C20: 原子 confirm —— consume UPDATE 与 confirm 审计 INSERT 在
    // 同一临界区 (单 audit_writer 锁全程), 顺序 audit-then-consume (审计成功才标消费)。
    // P0-6 (audit §2.1): 双锁消除。旧码 action_db 锁全程 + 嵌套 audit_writer 锁 → 突发负载活锁,
    // 改单 audit_writer 锁: SELECT pending_actions + INSERT audit_events + UPDATE consumed 同锁内。
    // P1-7 (audit §3.5): 物理分库后 pending_actions 在 action.db, audit_writer 连接 ATTACH action.db
    // 为 `action` schema (open 时建), 故引用改 `action.pending_actions`。跨库事务 (main.audit_events
    // + action.pending_actions) 协调提交保 H4 原子, action.db 独立 WAL 不并入 audit.db WAL。
    // ActionStore 自身连接 (put/evict_expired) 未 ATTACH, 仍走 main.pending_actions。
    // C9: H8 查 risk_level 列 (ground truth) 非 verdict_json blob; 交叉校验列与 JSON 一致。
    // C20: 校验 caller tenant_id == stored tenant_id (斩跨租户 confirm)。
    #[allow(clippy::too_many_arguments)]
    pub fn confirm_atomic(
        &self,
        action_id: &str,
        approved: bool,
        approved_by: &str,
        caller_tenant: &str,
        audit_writer: &Arc<Mutex<Connection>>,
        chain_key: &Zeroizing<[u8; 32]>,
        key_version: i64,
    ) -> Result<GuardVerdict, ActionError> {
        // P0-6: 单 audit_writer 锁全程 (pending_actions + audit_events 同连接可见, P1-7 经 ATTACH)。
        let w = recover_lock!(
            audit_writer.lock(),
            "audit writer (confirm single-lock P0-6)"
        );
        let row = w
            .query_row(
                "SELECT verdict_json, risk_level, created_ts, consumed, ttl_secs, tenant_id
                 FROM action.pending_actions WHERE action_id = ?1",
                params![action_id],
                |r| {
                    let j: String = r.get(0)?;
                    let risk: i64 = r.get(1)?;
                    let created: i64 = r.get(2)?;
                    let consumed: i64 = r.get(3)?;
                    let ttl: i64 = r.get(4)?;
                    let tenant: String = r.get(5)?;
                    Ok((j, risk, created, consumed, ttl, tenant))
                },
            )
            .optional()?;
        let (j, risk, created, consumed, ttl, stored_tenant) =
            row.ok_or_else(|| ActionError::NotFound(action_id.to_string()))?;
        let mut verdict: GuardVerdict = serde_json::from_str(&j)?;

        // C9: H8 查 risk_level 列 (权威 ground truth, put 时写), 非 JSON blob。
        if risk == RiskLevel::L4 as i64 {
            tracing::warn!(
                action_id = action_id,
                "confirm on L4 rejected (H8, risk column)"
            );
            return Err(ActionError::AbsoluteBlock(action_id.to_string()));
        }
        // C9 交叉校验: 列 risk_level 必须与 verdict_json 反序列化值一致, 不一致即篡改 → 拒。
        if risk != verdict.risk_level as i64 {
            tracing::error!(
                action_id = action_id,
                stored_risk = risk,
                json_risk = ?verdict.risk_level,
                "risk column / verdict_json mismatch — tamper suspected, refusing (C9)"
            );
            return Err(ActionError::RiskTampered {
                stored: risk,
                json: j,
            });
        }
        // C20: 跨租户 confirm 拒绝 (action_id 泄露也不可被他租户消费)。
        if stored_tenant != caller_tenant {
            tracing::warn!(
                action_id = action_id,
                stored_tenant = stored_tenant,
                caller_tenant = caller_tenant,
                "cross-tenant confirm denied (C20)"
            );
            return Err(ActionError::CrossTenant {
                stored: stored_tenant,
                caller: caller_tenant.to_string(),
            });
        }
        if consumed != 0 {
            tracing::warn!(action_id = action_id, "confirm replay rejected (one-time)");
            return Err(ActionError::Consumed(action_id.to_string()));
        }
        let now = now_ts();
        if created + ttl < now {
            tracing::warn!(action_id = action_id, "confirm rejected (expired)");
            return Err(ActionError::Expired(action_id.to_string()));
        }

        // L12: 先存原始触发原因 (evaluate 时写入的规则名/触发理由), 再覆盖 reason。
        let original_trigger = verdict.reason.clone();
        if approved {
            verdict.action = fg_core::SafetyAction::Allow;
            verdict.reason = format!("approved by {}", approved_by);
            verdict.requires_approval = false;
        } else {
            verdict.action = fg_core::SafetyAction::Block;
            verdict.reason = format!("rejected by {}", approved_by);
            verdict.requires_approval = false;
        }

        // L2+A8: 先写 confirm 审计 (同步高风险 H7), 成功才标 consumed。
        // 审计失败 → 拒绝消费 (动作仍可重 confirm), 不留"已消费无审计"永久缺口。
        let outcome = if approved { "approved" } else { "rejected" };
        let ev = crate::AuditEvent {
            audit_id: uuid::Uuid::new_v4(),
            ts: chrono::Utc::now(),
            event_type: "confirm".to_string(),
            tenant_id: caller_tenant.to_string(),
            requester: approved_by.to_string(),
            action: original_trigger,
            inferred_category: verdict.inferred_category.clone(),
            verdict_json: serde_json::to_string(&verdict).unwrap_or_default(),
            approved_by: Some(approved_by.to_string()),
            seatbelt_required: verdict.seatbelt_required,
            outcome: outcome.to_string(),
            prev_hash: String::new(),
            event_hash: String::new(),
        };
        if let Err(e) = crate::insert_audit_event(&w, &ev, chain_key, key_version) {
            tracing::error!(error = %e, action_id = action_id, "confirm audit insert failed — refusing consume (L2 fail-closed)");
            return Err(ActionError::AuditFailed(e.to_string()));
        }

        // 审计落库成功 → 标 consumed (一次性)。同一 audit_writer 锁内, 无并发重消费窗口。
        // P1-7: pending_actions 在 action.db (audit_writer ATTACH 为 `action` schema)。
        w.execute(
            "UPDATE action.pending_actions SET consumed = 1 WHERE action_id = ?1",
            params![action_id],
        )?;
        drop(w);

        tracing::info!(
            action_id = action_id,
            approved = approved,
            approved_by = approved_by,
            tenant = caller_tenant,
            "action confirmed (single-lock: audit-then-consume, one-time, P0-6)"
        );
        Ok(verdict)
    }

    pub fn evict_expired(&self) -> Result<usize, ActionError> {
        let now = now_ts();
        let g = recover_lock!(self.db.lock(), "action db");
        let n = g.execute(
            "DELETE FROM pending_actions WHERE created_ts + ttl_secs < ?1",
            params![now],
        )?;
        if n > 0 {
            tracing::info!(evicted = n, "expired pending actions evicted");
        }
        Ok(n)
    }
}

fn now_ts() -> i64 {
    chrono::Utc::now().timestamp()
}

use rusqlite::OptionalExtension;
