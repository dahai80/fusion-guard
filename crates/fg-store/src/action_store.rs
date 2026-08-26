use fg_core::{GuardVerdict, RiskLevel};
use rusqlite::{params, Connection};
use std::sync::Mutex;

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
                ttl_secs INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_pending_ts ON pending_actions(created_ts);
            ",
        )?;
        Ok(Self {
            db: Mutex::new(conn),
        })
    }

    pub fn put(&self, verdict: &GuardVerdict) -> Result<(), ActionError> {
        let action_id = match verdict.action_id {
            Some(id) => id.to_string(),
            None => return Ok(()),
        };
        let risk = verdict.risk_level as i64;
        let j = serde_json::to_string(verdict)?;
        let now = now_ts();
        let g = self.db.lock().expect("action db mutex poisoned");
        g.execute(
            "INSERT OR REPLACE INTO pending_actions
             (action_id, verdict_json, risk_level, created_ts, consumed, ttl_secs)
             VALUES (?1, ?2, ?3, ?4, 0, ?5)",
            params![action_id, j, risk, now, ACTION_TTL_SECS],
        )?;
        tracing::debug!(action_id = action_id, "pending action stored");
        Ok(())
    }

    pub fn confirm(
        &self,
        action_id: &str,
        approved: bool,
        approved_by: &str,
    ) -> Result<GuardVerdict, ActionError> {
        let g = self.db.lock().expect("action db mutex poisoned");
        let row = g
            .query_row(
                "SELECT verdict_json, risk_level, created_ts, consumed, ttl_secs
                 FROM pending_actions WHERE action_id = ?1",
                params![action_id],
                |r| {
                    let j: String = r.get(0)?;
                    let risk: i64 = r.get(1)?;
                    let created: i64 = r.get(2)?;
                    let consumed: i64 = r.get(3)?;
                    let ttl: i64 = r.get(4)?;
                    Ok((j, risk, created, consumed, ttl))
                },
            )
            .optional()?;
        let (j, risk, created, consumed, ttl) =
            row.ok_or_else(|| ActionError::NotFound(action_id.to_string()))?;
        let mut verdict: GuardVerdict = serde_json::from_str(&j)?;

        if matches!(verdict.risk_level, RiskLevel::L4) {
            tracing::warn!(action_id = action_id, "confirm on L4 rejected (H8)");
            return Err(ActionError::AbsoluteBlock(action_id.to_string()));
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
        let _ = risk;
        g.execute(
            "UPDATE pending_actions SET consumed = 1 WHERE action_id = ?1",
            params![action_id],
        )?;
        drop(g);

        if approved {
            verdict.action = fg_core::SafetyAction::Allow;
            verdict.reason = format!("approved by {}", approved_by);
            verdict.requires_approval = false;
        } else {
            verdict.action = fg_core::SafetyAction::Block;
            verdict.reason = format!("rejected by {}", approved_by);
            verdict.requires_approval = false;
        }
        tracing::info!(
            action_id = action_id,
            approved = approved,
            approved_by = approved_by,
            "action confirmed (one-time consumed)"
        );
        Ok(verdict)
    }

    pub fn evict_expired(&self) -> Result<usize, ActionError> {
        let now = now_ts();
        let g = self.db.lock().expect("action db mutex poisoned");
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
