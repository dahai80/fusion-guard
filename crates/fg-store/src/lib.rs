use fg_core::GuardVerdict;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

pub const DEFAULT_TENANT: &str = "default";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub id: uuid::Uuid,
    pub ts: chrono::DateTime<chrono::Utc>,
    pub tenant_id: String,
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

    pub fn append(
        &self,
        tenant_id: &str,
        verdict: GuardVerdict,
        raw_redacted: String,
    ) -> AuditRecord {
        let rec = AuditRecord {
            id: uuid::Uuid::new_v4(),
            ts: chrono::Utc::now(),
            tenant_id: tenant_id.to_string(),
            verdict,
            raw_content_redacted: raw_redacted,
        };
        let mut g = self.records.lock().expect("audit mutex poisoned");
        g.push(rec.clone());
        tracing::info!(
            record_id = %rec.id,
            tenant = %rec.tenant_id,
            "audit record appended (in-mem stub)"
        );
        rec
    }

    pub fn list(&self, limit: usize) -> Vec<AuditRecord> {
        let g = self.records.lock().expect("audit mutex poisoned");
        g.iter().rev().take(limit).cloned().collect()
    }

    pub fn list_by_tenant(&self, tenant_id: &str, limit: usize) -> Vec<AuditRecord> {
        let g = self.records.lock().expect("audit mutex poisoned");
        g.iter()
            .rev()
            .filter(|r| r.tenant_id == tenant_id)
            .take(limit)
            .cloned()
            .collect()
    }
}

impl Default for AuditStore {
    fn default() -> Self {
        Self::new()
    }
}

