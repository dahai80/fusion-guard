// verify.rs — federated 审计链段验证 (issue #52 原语 1 消费方)。
//
// 拉远端节点链段 (AuditChainResponse.records) → 双重篡改检出:
//   1. MAC: 重算 HMAC-SHA256 over (record 减 mac), 与 record.mac 比对 (常量时间)。
//   2. 链接: prev_hash = 含 mac 的完整前序记录 sha256。下条 record.prev_hash 须 == 前条 sha256(canonical_full)。
// 任一失败 → broken_links++。降级记录 (无 seq/prev_hash/mac) 视为基线, 跳过链校验 (不视为 broken)。
// 镜像 multi-node audit_log.py._chain_payload (减 mac) + _canonical_full (含 mac) 算法。

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

// canonical over (record 减 mac) — MAC 签名输入, 须确定性。
// multi-node _chain_payload: {k:v for k,v in record.items() if k != "mac"}。
fn chain_payload(record: &AuditChainRecord) -> Vec<u8> {
    let mut v = serde_json::to_value(record).unwrap_or(serde_json::Value::Null);
    if let serde_json::Value::Object(ref mut map) = v {
        map.remove("mac");
    }
    canonical_json(&v)
}

// canonical over 完整记录 (含 mac) — prev_hash 滚动锚点用。
// multi-node _canonical_full: canonical_json over record (含 mac)。
fn canonical_full(record: &AuditChainRecord) -> Vec<u8> {
    let v = serde_json::to_value(record).unwrap_or(serde_json::Value::Null);
    canonical_json(&v)
}

// 记录是否为降级基线 (无链字段) — multi-node 链计算失败时 pop seq/prev_hash/mac。
fn is_baseline(record: &AuditChainRecord) -> bool {
    record.seq.is_none() || record.prev_hash.is_none() || record.mac.is_none()
}

// 验证远端链段。chain_key = derive_audit_chain_key(cluster_token)。
// records 须按 seq 升序 (multi-node since_seq 过滤后仍保序)。
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
            // 降级记录: 跳过链校验, 重置锚点 (下条重新基线)。
            baseline_records += 1;
            prev_full_hash = None;
            continue;
        }

        // 1. MAC 校验 — 重算 HMAC over (record 减 mac)。
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

        // 2. 链接校验 — prev_hash 须 == 前条完整记录 sha256 (首条基线 prev_hash="" 跳过)。
        if let Some(ref expected_prev) = prev_full_hash {
            let actual_prev = rec.prev_hash.as_deref().unwrap_or("");
            // multi-node 首条 prev_hash = "" (空串基线), 非断链。
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
            // 前条基线/首条 — 当前 prev_hash 须为空串 (multi-node 首条) 或不校验。
            verified_links += 1;
        }

        // 滚动锚点 = 当前完整记录 sha256 (下条 prev_hash 链接目标)。
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
        // 首条 prev_hash="" 基线, 后续链接。
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
        // 篡改 action 字段 → 重算 MAC 不匹配 (但保留原 mac)。
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
        // r1.prev_hash 故意错误 (非 r0 完整 sha256)。
        let r1 = make_record(2, "deadbeef", &key, "a1");
        let res = verify_chain_segment("n1", &[r0, r1], &key);
        assert!(res.tampered);
        assert_eq!(res.broken_links, 1);
    }

    #[test]
    fn baseline_records_skipped() {
        let token = "tok-chain-baseline";
        let key = derive_audit_chain_key(token);
        // 无链字段降级记录 → baseline, 不 broken。
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
