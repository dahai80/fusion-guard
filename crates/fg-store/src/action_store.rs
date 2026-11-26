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
        // C20 legacy DB migration: add tenant_id column (idempotent)
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

    // G6/L2+A8/C9/C20: atomic confirm — the consume UPDATE and the confirm audit INSERT run in
    // the same critical section (single audit_writer lock held throughout), ordered audit-then-consume
    // (consumed is marked only after the audit insert succeeds).
    // P0-6 (audit §2.1): double-lock elimination. Old code held the action_db lock throughout plus a
    // nested audit_writer lock → livelock under bursty load; switched to a single audit_writer lock:
    // SELECT pending_actions + INSERT audit_events + UPDATE consumed inside one lock.
    // P1-7 (audit §3.5): after the physical DB split, pending_actions lives in action.db and the
    // audit_writer connection ATTACHes action.db as the `action` schema (created at open), so references
    // became `action.pending_actions`. The cross-db transaction (main.audit_events +
    // action.pending_actions) commits coordinately to keep H4 atomic; action.db keeps its own WAL,
    // not merged into audit.db's WAL.
    // ActionStore's own connection (put/evict_expired) does not ATTACH and still uses main.pending_actions.
    // C9: H8 checks the risk_level column (ground truth), not the verdict_json blob; cross-checks column vs JSON consistency.
    // C20: verifies caller tenant_id == stored tenant_id (kills cross-tenant confirm).
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
        // P0-6: single audit_writer lock held throughout (pending_actions + audit_events visible on the same connection, P1-7 via ATTACH).
        let mut w = recover_lock!(
            audit_writer.lock(),
            "audit writer (confirm single-lock P0-6)"
        );
        // H-D (product-audit §5): cross-db transaction. The old implementation committed SELECT+INSERT+UPDATE
        // independently under autocommit — a crash window (audit INSERT committed, UPDATE consumed not committed)
        // left action_id with consumed=0 after restart → confirm possible again = double-confirm replay,
        // violating H4 one-time. BEGIN IMMEDIATE across ATTACHed databases (audit_writer ATTACHes action.db
        // as the `action` schema) gives cross-db atomicity: all three steps in one transaction, commit succeeds
        // fully or rolls back fully, achieving crash-recovery-grade H4 atomicity. BEGIN IMMEDIATE immediately takes
        // the audit.db write lock + action.db coordinated lock (under ATTACH, multi-db transactions take locks in a
        // consistent per-db order, no deadlock). SELECTs inside the transaction see the held write lock; other
        // connections cannot jump in and change consumed.
        let tx = w.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let row = tx
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

        // C9: H8 checks the risk_level column (authoritative ground truth, written at put), not the JSON blob.
        if risk == RiskLevel::L4 as i64 {
            tracing::warn!(
                action_id = action_id,
                "confirm on L4 rejected (H8, risk column)"
            );
            return Err(ActionError::AbsoluteBlock(action_id.to_string()));
        }
        // C9 cross-check: the risk_level column must match the verdict_json deserialized value; a mismatch means tampering → refuse.
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
        // C20: cross-tenant confirm rejected (even a leaked action_id cannot be consumed by another tenant).
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

        // L12: save the original trigger reason (rule name/trigger reason written at evaluate) before overwriting reason.
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

        // L2+A8: write the confirm audit first (sync high-risk H7); only mark consumed on success.
        // Audit failure → refuse to consume (the action can still be re-confirmed), leaving no permanent
        // "consumed without audit" gap.
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
        if let Err(e) = crate::insert_audit_event_tx(&tx, &ev, chain_key, key_version) {
            tracing::error!(error = %e, action_id = action_id, "confirm audit insert failed — refusing consume (L2 fail-closed)");
            return Err(ActionError::AuditFailed(e.to_string()));
        }

        // Audit persisted → mark consumed (one-time). H-D: same BEGIN IMMEDIATE transaction as the audit
        // INSERT, commit is atomic — a crash between INSERT and UPDATE rolls back the uncommitted transaction,
        // consumed stays 0 but the audit row rolls back too (consumption without audit) → no double-confirm
        // replay window. Full commit = audit + consumed land together.
        // P1-7: pending_actions lives in action.db (audit_writer ATTACHes it as the `action` schema).
        tx.execute(
            "UPDATE action.pending_actions SET consumed = 1 WHERE action_id = ?1",
            params![action_id],
        )?;
        tx.commit()?;
        drop(w);

        tracing::info!(
            action_id = action_id,
            approved = approved,
            approved_by = approved_by,
            tenant = caller_tenant,
            "action confirmed (single-lock + cross-db tx: audit-then-consume atomic, one-time, P0-6 H-D)"
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
