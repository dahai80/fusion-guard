use fg_core::{GuardVerdict, RiskLevel, SafetyAction};
use fg_rules::{GuardRule, RuleSet};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

pub mod action_store;
pub mod token_store;
pub use action_store::{ActionError, ActionStore, PendingAction};
pub use token_store::{TokenError, TokenStore};

pub const DEFAULT_TENANT: &str = "default";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TccEventRecord {
    pub audit_id: uuid::Uuid,
    pub ts: chrono::DateTime<chrono::Utc>,
    pub permission: String,
    pub requester: String,
    pub result: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub id: uuid::Uuid,
    pub ts: chrono::DateTime<chrono::Utc>,
    pub tenant_id: String,
    pub verdict: GuardVerdict,
    pub raw_content_redacted: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub audit_id: uuid::Uuid,
    pub ts: chrono::DateTime<chrono::Utc>,
    pub event_type: String,
    pub tenant_id: String,
    pub requester: String,
    pub action: String,
    pub inferred_category: String,
    pub verdict_json: String,
    pub approved_by: Option<String>,
    pub seatbelt_required: bool,
    pub outcome: String,
}

pub struct AuditStore {
    db: Mutex<Connection>,
    low_queue: mpsc::Sender<AuditEvent>,
    tokens: Arc<TokenStore>,
    actions: Arc<ActionStore>,
}

pub struct StoreError;

impl AuditStore {
    pub fn open(db_path: &Path) -> std::io::Result<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(db_path).map_err(io_err)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA wal_autocheckpoint=1000;",
        )
        .map_err(io_err)?;
        conn.execute_batch(SCHEMA).map_err(io_err)?;
        tracing::info!(db = %db_path.display(), "audit store opened (SQLite WAL)");

        let (tx, rx) = mpsc::channel::<AuditEvent>();
        let writer_conn = Connection::open(db_path).map_err(io_err)?;
        writer_conn
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .map_err(io_err)?;
        let token_conn = Connection::open(db_path).map_err(io_err)?;
        token_conn
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .map_err(io_err)?;
        let tokens = TokenStore::open(token_conn).map_err(|e| {
            tracing::error!(error = %e, "token store open failed");
            std::io::Error::other(e.to_string())
        })?;
        let action_conn = Connection::open(db_path).map_err(io_err)?;
        action_conn
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .map_err(io_err)?;
        let actions = ActionStore::open(action_conn).map_err(|e| {
            tracing::error!(error = %e, "action store open failed");
            std::io::Error::other(e.to_string())
        })?;
        let writer = Arc::new(Mutex::new(writer_conn));
        std::thread::spawn(move || {
            let mut buf: Vec<AuditEvent> = Vec::with_capacity(100);
            while let Ok(ev) = rx.recv() {
                buf.push(ev);
                while let Ok(ev) = rx.try_recv() {
                    buf.push(ev);
                    if buf.len() >= 100 {
                        break;
                    }
                }
                let w = writer.clone();
                let batch: Vec<AuditEvent> = std::mem::take(&mut buf);
                let res = std::thread::spawn(move || {
                    let g = w.lock().expect("writer mutex poisoned");
                    for ev in &batch {
                        if let Err(e) = insert_audit_event(&g, ev) {
                            tracing::warn!(error = %e, audit_id = %ev.audit_id, "async audit insert failed");
                        }
                    }
                })
                .join();
                if let Err(e) = res {
                    tracing::error!(error = ?e, "audit writer thread panic");
                }
            }
            tracing::info!("audit async writer exited");
        });

        Ok(Self {
            db: Mutex::new(conn),
            low_queue: tx,
            tokens: Arc::new(tokens),
            actions: Arc::new(actions),
        })
    }

    pub fn tokens(&self) -> Arc<TokenStore> {
        self.tokens.clone()
    }

    pub fn actions(&self) -> Arc<ActionStore> {
        self.actions.clone()
    }

    pub fn append_confirm_event(
        &self,
        tenant_id: &str,
        verdict: &GuardVerdict,
        approved_by: &str,
        outcome: &str,
    ) -> Result<AuditEvent, rusqlite::Error> {
        let ev = AuditEvent {
            audit_id: uuid::Uuid::new_v4(),
            ts: chrono::Utc::now(),
            event_type: "confirm".to_string(),
            tenant_id: tenant_id.to_string(),
            requester: approved_by.to_string(),
            action: verdict.reason.clone(),
            inferred_category: verdict.inferred_category.clone(),
            verdict_json: serde_json::to_string(verdict).unwrap_or_default(),
            approved_by: Some(approved_by.to_string()),
            seatbelt_required: verdict.seatbelt_required,
            outcome: outcome.to_string(),
        };
        let g = self.db.lock().expect("audit mutex poisoned");
        insert_audit_event(&g, &ev)?;
        tracing::info!(
            audit_id = %ev.audit_id,
            tenant = %ev.tenant_id,
            outcome = %ev.outcome,
            "confirm audit event persisted (sync H7)"
        );
        Ok(ev)
    }

    pub fn append_event(
        &self,
        tenant_id: &str,
        verdict: &GuardVerdict,
        raw_redacted: String,
        requester: &str,
    ) -> Result<AuditEvent, rusqlite::Error> {
        let high_risk = matches!(verdict.risk_level, RiskLevel::L3 | RiskLevel::L4)
            || verdict.action == SafetyAction::Block;
        let outcome = match verdict.action {
            SafetyAction::Block => "blocked",
            SafetyAction::Allow => "allowed",
            SafetyAction::Preview | SafetyAction::Redact => "allowed",
        };
        let ev = AuditEvent {
            audit_id: uuid::Uuid::new_v4(),
            ts: chrono::Utc::now(),
            event_type: "evaluate".to_string(),
            tenant_id: tenant_id.to_string(),
            requester: requester.to_string(),
            action: raw_redacted,
            inferred_category: verdict.inferred_category.clone(),
            verdict_json: serde_json::to_string(verdict).unwrap_or_default(),
            approved_by: None,
            seatbelt_required: verdict.seatbelt_required,
            outcome: outcome.to_string(),
        };

        if high_risk {
            let g = self.db.lock().expect("audit mutex poisoned");
            insert_audit_event(&g, &ev)?;
            tracing::info!(
                audit_id = %ev.audit_id,
                tenant = %ev.tenant_id,
                "high-risk audit event persisted (sync gate H7)"
            );
        } else {
            if self.low_queue.send(ev.clone()).is_err() {
                tracing::warn!("low-risk audit queue closed, event dropped");
            }
        }
        Ok(ev)
    }

    pub fn list_events(
        &self,
        tenant_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AuditEvent>, rusqlite::Error> {
        let g = self.db.lock().expect("audit mutex poisoned");
        let mut stmt = if tenant_id.is_some() {
            g.prepare(
                "SELECT audit_id, ts, event_type, tenant_id, requester, action,
                        inferred_category, verdict_json, approved_by, seatbelt_required, outcome
                 FROM audit_events WHERE tenant_id = ?1
                 ORDER BY ts DESC LIMIT ?2",
            )?
        } else {
            g.prepare(
                "SELECT audit_id, ts, event_type, tenant_id, requester, action,
                        inferred_category, verdict_json, approved_by, seatbelt_required, outcome
                 FROM audit_events ORDER BY ts DESC LIMIT ?1",
            )?
        };
        let rows = if let Some(t) = tenant_id {
            stmt.query_map(params![t, limit as i64], row_to_event)?
                .collect::<Result<Vec<_>, _>>()?
        } else {
            stmt.query_map(params![limit as i64], row_to_event)?
                .collect::<Result<Vec<_>, _>>()?
        };
        Ok(rows)
    }

    pub fn list_by_tenant(&self, tenant_id: &str, limit: usize) -> Vec<AuditRecord> {
        match self.list_events(Some(tenant_id), limit) {
            Ok(events) => events.into_iter().filter_map(event_to_record).collect(),
            Err(e) => {
                tracing::warn!(error = %e, "list_by_tenant failed");
                Vec::new()
            }
        }
    }

    pub fn list(&self, limit: usize) -> Vec<AuditRecord> {
        match self.list_events(None, limit) {
            Ok(events) => events.into_iter().filter_map(event_to_record).collect(),
            Err(e) => {
                tracing::warn!(error = %e, "list failed");
                Vec::new()
            }
        }
    }

    pub fn load_rules(&self) -> Result<Option<RuleSet>, rusqlite::Error> {
        let g = self.db.lock().expect("audit mutex poisoned");
        let epoch: i64 = g
            .query_row("SELECT value FROM rule_meta WHERE key='epoch'", [], |r| {
                r.get(0)
            })
            .ok()
            .unwrap_or(0);
        let mut stmt = g.prepare("SELECT rule_json FROM rules ORDER BY name ASC")?;
        let rules: Vec<GuardRule> = stmt
            .query_map([], |row| {
                let j: String = row.get(0)?;
                Ok(serde_json::from_str(&j).unwrap_or_else(|e| {
                    tracing::warn!(error = %e, "corrupt rule json skipped");
                    GuardRule {
                        name: "__corrupt__".into(),
                        pattern: "never".into(),
                        stage: fg_core::CheckStage::Regex,
                        action: SafetyAction::Allow,
                        risk_level: RiskLevel::L1,
                        reason: "corrupt".into(),
                        scope: fg_core::RuleScope::Command,
                    }
                }))
            })?
            .filter_map(|r| r.ok())
            .filter(|r| r.name != "__corrupt__")
            .collect();
        if epoch == 0 {
            return Ok(None);
        }
        tracing::info!(
            epoch = epoch,
            count = rules.len(),
            "rules loaded from store"
        );
        Ok(Some(RuleSet {
            epoch: epoch as u64,
            rules,
        }))
    }

    pub fn save_rule(&self, rule: &GuardRule) -> Result<(), rusqlite::Error> {
        let g = self.db.lock().expect("audit mutex poisoned");
        let j = serde_json::to_string(rule).unwrap_or_default();
        g.execute(
            "INSERT OR REPLACE INTO rules (name, rule_json) VALUES (?1, ?2)",
            params![rule.name, j],
        )?;
        Ok(())
    }

    pub fn delete_rule(&self, name: &str) -> Result<(), rusqlite::Error> {
        let g = self.db.lock().expect("audit mutex poisoned");
        g.execute("DELETE FROM rules WHERE name=?1", params![name])?;
        Ok(())
    }

    pub fn save_epoch(&self, epoch: u64) -> Result<(), rusqlite::Error> {
        let g = self.db.lock().expect("audit mutex poisoned");
        g.execute(
            "INSERT OR REPLACE INTO rule_meta (key, value) VALUES ('epoch', ?1)",
            params![epoch as i64],
        )?;
        Ok(())
    }

    pub fn report_tcc_event(
        &self,
        permission: &str,
        requester: &str,
        result: &str,
        reason: &str,
    ) -> Result<uuid::Uuid, rusqlite::Error> {
        let audit_id = uuid::Uuid::new_v4();
        let ts = chrono::Utc::now().to_rfc3339();
        let g = self.db.lock().expect("audit mutex poisoned");
        g.execute(
            "INSERT INTO tcc_events (audit_id, ts, permission, requester, result, reason)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![audit_id.to_string(), ts, permission, requester, result, reason],
        )?;
        tracing::info!(
            audit_id = %audit_id,
            permission = permission,
            requester = requester,
            result = result,
            "TCC event reported (audit aggregation H1)"
        );
        Ok(audit_id)
    }

    pub fn list_tcc_events(&self, limit: usize) -> Result<Vec<TccEventRecord>, rusqlite::Error> {
        let g = self.db.lock().expect("audit mutex poisoned");
        let mut stmt = g.prepare(
            "SELECT audit_id, ts, permission, requester, result, reason
             FROM tcc_events ORDER BY ts DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            let ts_str: String = row.get(1)?;
            let ts = chrono::DateTime::parse_from_rfc3339(&ts_str)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now());
            let id_str: String = row.get(0)?;
            let audit_id =
                uuid::Uuid::parse_str(&id_str).unwrap_or_else(|_| uuid::Uuid::nil());
            Ok(TccEventRecord {
                audit_id,
                ts,
                permission: row.get(2)?,
                requester: row.get(3)?,
                result: row.get(4)?,
                reason: row.get(5)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS audit_events (
    audit_id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    event_type TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    requester TEXT NOT NULL,
    action TEXT NOT NULL,
    inferred_category TEXT NOT NULL,
    verdict_json TEXT NOT NULL,
    approved_by TEXT,
    seatbelt_required INTEGER NOT NULL,
    outcome TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_events(tenant_id);

CREATE TABLE IF NOT EXISTS rules (
    name TEXT PRIMARY KEY,
    rule_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rule_meta (
    key TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tcc_events (
    audit_id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    permission TEXT NOT NULL,
    requester TEXT NOT NULL,
    result TEXT NOT NULL,
    reason TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tcc_ts ON tcc_events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_tcc_permission ON tcc_events(permission);
"#;

fn insert_audit_event(conn: &Connection, ev: &AuditEvent) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO audit_events
         (audit_id, ts, event_type, tenant_id, requester, action,
          inferred_category, verdict_json, approved_by, seatbelt_required, outcome)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        params![
            ev.audit_id.to_string(),
            ev.ts.to_rfc3339(),
            ev.event_type,
            ev.tenant_id,
            ev.requester,
            ev.action,
            ev.inferred_category,
            ev.verdict_json,
            ev.approved_by,
            ev.seatbelt_required as i64,
            ev.outcome,
        ],
    )?;
    Ok(())
}

fn row_to_event(row: &rusqlite::Row) -> rusqlite::Result<AuditEvent> {
    let ts_str: String = row.get(1)?;
    let ts = chrono::DateTime::parse_from_rfc3339(&ts_str)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());
    let audit_id_str: String = row.get(0)?;
    let audit_id = uuid::Uuid::parse_str(&audit_id_str).unwrap_or_else(|_| uuid::Uuid::nil());
    Ok(AuditEvent {
        audit_id,
        ts,
        event_type: row.get(2)?,
        tenant_id: row.get(3)?,
        requester: row.get(4)?,
        action: row.get(5)?,
        inferred_category: row.get(6)?,
        verdict_json: row.get(7)?,
        approved_by: row.get(8)?,
        seatbelt_required: row.get::<_, i64>(9)? != 0,
        outcome: row.get(10)?,
    })
}

fn event_to_record(ev: AuditEvent) -> Option<AuditRecord> {
    let verdict: GuardVerdict = serde_json::from_str(&ev.verdict_json).ok()?;
    Some(AuditRecord {
        id: ev.audit_id,
        ts: ev.ts,
        tenant_id: ev.tenant_id,
        verdict,
        raw_content_redacted: ev.action,
    })
}

fn io_err(e: rusqlite::Error) -> std::io::Error {
    std::io::Error::other(e.to_string())
}
