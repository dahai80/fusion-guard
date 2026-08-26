use fg_core::GuardVerdict;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub id: uuid::Uuid,
    pub ts: chrono::DateTime<chrono::Utc>,
    pub verdict: GuardVerdict,
    pub raw_content_redacted: String,
}

pub struct AuditStore {
    records: Mutex<Vec<AuditRecord>>,
}

impl AuditStore {
    pub fn new() -> Self {
        Self {
            records: Mutex::new(Vec::new()),
        }
    }

    pub fn append(&self, verdict: GuardVerdict, raw_redacted: String) -> AuditRecord {
        let rec = AuditRecord {
            id: uuid::Uuid::new_v4(),
            ts: chrono::Utc::now(),
            verdict,
            raw_content_redacted: raw_redacted,
        };
        let mut g = self.records.lock().expect("audit mutex poisoned");
        g.push(rec.clone());
        tracing::info!(record_id = %rec.id, "audit record appended (in-mem stub)");
        rec
    }

    pub fn list(&self, limit: usize) -> Vec<AuditRecord> {
        let g = self.records.lock().expect("audit mutex poisoned");
        g.iter().rev().take(limit).cloned().collect()
    }
}

impl Default for AuditStore {
    fn default() -> Self {
        Self::new()
    }
}
