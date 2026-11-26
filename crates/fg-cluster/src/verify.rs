// verify.rs — federated audit chain segment verification (issue #52 primitive 1 consumer).
//
// Fetch remote node chain segment (AuditChainResponse.records) → dual tamper detection:
//   1. MAC: recompute HMAC-SHA256 over (record minus mac), compare against record.mac (constant time).
//   2. Link: prev_hash = sha256 of the full previous record including mac. Next record.prev_hash must == previous sha256(canonical_full).
// Any failure → broken_links++. Degraded records (no seq/prev_hash/mac) are treated as baseline, chain verification skipped (not counted broken).
// Mirrors multi-node audit_log.py._chain_payload (minus mac) + _canonical_full (including mac) algorithms.

use crate::key::{canonical_json, verify_mac};
use crate::AuditChainRecord;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChainVerifyResult {
    pub node_id: String,
    pub total_records: usize,
    pub verified_links: usize,
    pub broken_links: usize,
    pub baseline_records: usize,
    pub tampered: bool,
    pub first_broken_at: Option<usize>,
}

// Canonical over (record minus mac) — MAC signing input, must be deterministic.
// multi-node _chain_payload: {k:v for k,v in record.items() if k != "mac"}.
fn chain_payload(record: &AuditChainRecord) -> Vec<u8> {
    let mut v = serde_json::to_value(record).unwrap_or(serde_json::Value::Null);
    if let serde_json::Value::Object(ref mut map) = v {
        map.remove("mac");
    }
    canonical_json(&v)
}

// Canonical over the full record (including mac) — used for the prev_hash rolling anchor.
// multi-node _canonical_full: canonical_json over record (including mac).
fn canonical_full(record: &AuditChainRecord) -> Vec<u8> {
    let v = serde_json::to_value(record).unwrap_or(serde_json::Value::Null);
    canonical_json(&v)
}

// Whether the record is a degraded baseline (no chain fields) — multi-node pops seq/prev_hash/mac when chain computation fails.
fn is_baseline(record: &AuditChainRecord) -> bool {
    record.seq.is_none() || record.prev_hash.is_none() || record.mac.is_none()
}

// Verify a remote chain segment. chain_key = derive_audit_chain_key(cluster_token).
// records must be in ascending seq order (multi-node since_seq filter preserves order).
pub fn verify_chain_segment(
    node_id: &str,
    records: &[AuditChainRecord],
    chain_key: &[u8],
) -> ChainVerifyResult {
    let mut verified_links = 0usize;
    let mut broken_links = 0usize;
    let mut baseline_records = 0usize;
    let mut tampered = false;
    let mut first_broken_at: Option<usize> = None;
    let mut prev_full_hash: Option<String> = None;

    for (idx, rec) in records.iter().enumerate() {
        if is_baseline(rec) {
            // Degraded record: skip chain verification, reset anchor (next record re-baselines).
            baseline_records += 1;
            prev_full_hash = None;
            continue;
        }

        // 1. MAC verification — recompute HMAC over (record minus mac).
        let payload = chain_payload(rec);
        let mac_ok = rec
            .mac
            .as_ref()
            .map(|m| verify_mac(chain_key, &payload, m))
            .unwrap_or(false);
        if !mac_ok {
            broken_links += 1;
            tampered = true;
            if first_broken_at.is_none() {
                first_broken_at = Some(idx);
            }
            prev_full_hash = None;
            continue;
        }

        // 2. Link verification — prev_hash must == previous full-record sha256 (first record with baseline prev_hash="" is skipped).
        if let Some(ref expected_prev) = prev_full_hash {
            let actual_prev = rec.prev_hash.as_deref().unwrap_or("");
            // multi-node first record prev_hash = "" (empty-string baseline), not a broken link.
            if actual_prev.is_empty() {
                verified_links += 1;
            } else if actual_prev != expected_prev.as_str() {
                broken_links += 1;
                tampered = true;
                if first_broken_at.is_none() {
                    first_broken_at = Some(idx);
                }
                prev_full_hash = None;
                continue;
            } else {
                verified_links += 1;
            }
        } else {
            // Previous record was baseline/first — current prev_hash must be empty string (multi-node first record) or is unverified.
            verified_links += 1;
        }

        // Rolling anchor = sha256 of the current full record (link target of the next record's prev_hash).
        let full = canonical_full(rec);
        let hash = hex::encode(Sha256::digest(&full));
        prev_full_hash = Some(hash);
    }

    ChainVerifyResult {
        node_id: node_id.to_string(),
        total_records: records.len(),
        verified_links,
        broken_links,
        baseline_records,
        tampered,
        first_broken_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{derive_audit_chain_key, mac_payload};

    fn make_record(seq: u64, prev_hash: &str, chain_key: &[u8], action: &str) -> AuditChainRecord {
        let mut rec = AuditChainRecord {
            ts: "2026-08-28T12:00:00Z".into(),
            actor: "test".into(),
            action: action.into(),
            path: "".into(),
            method: "".into(),
            node_id: "n1".into(),
            result: "ok".into(),
            detail: "".into(),
            seq: Some(seq),
            prev_hash: Some(prev_hash.into()),
            mac: None,
        };
        let payload = chain_payload(&rec);
        rec.mac = Some(mac_payload(chain_key, &payload));
        rec
    }

    #[test]
    fn clean_chain_verifies() {
        let token = "tok-chain-clean";
        let key = derive_audit_chain_key(token);
        // First record prev_hash="" baseline, subsequent links.
        let r0 = make_record(1, "", &key, "a0");
        let full0 = hex::encode(Sha256::digest(canonical_full(&r0)));
        let r1 = make_record(2, &full0, &key, "a1");
        let res = verify_chain_segment("n1", &[r0, r1], &key);
        assert!(!res.tampered);
        assert_eq!(res.broken_links, 0);
        assert_eq!(res.verified_links, 2);
    }

    #[test]
    fn tampered_field_breaks_mac() {
        let token = "tok-chain-tamper";
        let key = derive_audit_chain_key(token);
        let mut r0 = make_record(1, "", &key, "a0");
        // Tampered action field → recomputed MAC mismatch (original mac kept).
        r0.action = "tampered".into();
        let res = verify_chain_segment("n1", &[r0], &key);
        assert!(res.tampered);
        assert_eq!(res.broken_links, 1);
        assert_eq!(res.first_broken_at, Some(0));
    }

    #[test]
    fn broken_prev_hash_link_detected() {
        let token = "tok-chain-link";
        let key = derive_audit_chain_key(token);
        let r0 = make_record(1, "", &key, "a0");
        // r1.prev_hash deliberately wrong (not r0's full sha256).
        let r1 = make_record(2, "deadbeef", &key, "a1");
        let res = verify_chain_segment("n1", &[r0, r1], &key);
        assert!(res.tampered);
        assert_eq!(res.broken_links, 1);
    }

    #[test]
    fn baseline_records_skipped() {
        let token = "tok-chain-baseline";
        let key = derive_audit_chain_key(token);
        // Degraded record without chain fields → baseline, not broken.
        let baseline = AuditChainRecord {
            ts: "t".into(),
            actor: "a".into(),
            action: "x".into(),
            path: "".into(),
            method: "".into(),
            node_id: "n".into(),
            result: "".into(),
            detail: "".into(),
            seq: None,
            prev_hash: None,
            mac: None,
        };
        let res = verify_chain_segment("n1", &[baseline], &key);
        assert!(!res.tampered);
        assert_eq!(res.baseline_records, 1);
        assert_eq!(res.broken_links, 0);
    }
}
