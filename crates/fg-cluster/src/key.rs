// key.rs — HKDF-SHA256 domain-separated key derivation + HMAC-SHA256 signing/verification.
// Mirrors fusion-multi-node security/cluster_key.py (issue #52 contract), algorithms must be byte-identical.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

// Domain-separated info labels — v1 suffix allows conflict-free future upgrades (v2 label → new key space, old MACs invalid).
// Identical to multi-node _AUDIT_CHAIN_INFO / _RULE_EPOCH_INFO / _CONFIRM_RELAY_INFO.
const AUDIT_CHAIN_INFO: &[u8] = b"fusion-multinode-audit-chain-v1";
const RULE_EPOCH_INFO: &[u8] = b"fusion-multinode-rule-epoch-v1";
const CONFIRM_RELAY_INFO: &[u8] = b"fusion-multinode-confirm-relay-v1";

const KEY_LEN: usize = 32; // SHA256 → 32 bytes

type HmacSha256 = Hmac<Sha256>;

// HKDF-SHA256 derivation — salt=None (matches multi-node _hkdf_derive).
fn hkdf_derive(secret: &str, info: &[u8]) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(None, secret.as_bytes());
    let mut okm = [0u8; KEY_LEN];
    hk.expand(info, &mut okm)
        .expect("32 bytes is within the HKDF-SHA256 output limit");
    okm
}

// Audit chain MAC key — derived from cluster_token, audit-chain domain.
pub fn derive_audit_chain_key(cluster_token: &str) -> [u8; KEY_LEN] {
    hkdf_derive(cluster_token, AUDIT_CHAIN_INFO)
}

// Rule epoch MAC key — rule-epoch domain.
pub fn derive_rule_epoch_key(cluster_token: &str) -> [u8; KEY_LEN] {
    hkdf_derive(cluster_token, RULE_EPOCH_INFO)
}

// Confirm relay MAC key — confirm-relay domain.
pub fn derive_confirm_relay_key(cluster_token: &str) -> [u8; KEY_LEN] {
    hkdf_derive(cluster_token, CONFIRM_RELAY_INFO)
}

// HMAC-SHA256 → hex string (carried by records/requests). Mirrors multi-node mac_payload.
pub fn mac_payload(key: &[u8], canonical: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(canonical);
    hex::encode(mac.finalize().into_bytes())
}

// Constant-time MAC verification — empty mac → false (no panic). Mirrors multi-node verify_mac.
pub fn verify_mac(key: &[u8], canonical: &[u8], mac_hex: &str) -> bool {
    if mac_hex.is_empty() {
        return false;
    }
    let mut mac = match HmacSha256::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(canonical);
    mac.verify_slice(hex::decode(mac_hex).unwrap_or_default().as_slice())
        .is_ok()
}

// Canonical JSON — sorted keys + no whitespace + ensure_ascii=False (non-ASCII unescaped, utf-8 encoded).
// Signing input must be deterministic: key order/whitespace/escaping mismatch → MAC mismatch. guard and multi-node must share the algorithm.
// Mirrors multi-node canonical_json: json.dumps(payload, sort_keys=True, separators=(",",":"), ensure_ascii=False)
pub fn canonical_json(payload: &serde_json::Value) -> Vec<u8> {
    // serde_json does not escape non-ASCII by default (ensure_ascii=False equivalent), but keys must be explicitly sorted + compact separators.
    let mut buf = Vec::new();
    let formatter = serde_json::ser::CompactFormatter;
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, formatter);
    serialize_sorted(payload, &mut ser);
    buf
}

// Recursive serialization, object keys sorted lexicographically (matches Python json.dumps(sort_keys=True)).
fn serialize_sorted<W: std::io::Write>(
    value: &serde_json::Value,
    ser: &mut serde_json::Serializer<W, serde_json::ser::CompactFormatter>,
) {
    use serde::Serialize;
    match value {
        serde_json::Value::Object(map) => {
            // Collect keys, sort, serialize in order.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut ordered = serde_json::Map::new();
            for k in keys {
                if let Some(v) = map.get(k) {
                    ordered.insert(k.clone(), v.clone());
                }
            }
            serde_json::Value::Object(ordered)
                .serialize(ser)
                .unwrap_or_default();
        }
        other => other.serialize(ser).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "test-cluster-token-12345";

    #[test]
    fn hkdf_derive_deterministic() {
        // Same token + same info → same key (HKDF deterministic).
        let k1 = derive_audit_chain_key(TOKEN);
        let k2 = derive_audit_chain_key(TOKEN);
        assert_eq!(k1, k2);
    }

    #[test]
    fn hkdf_domain_separated() {
        // 3 domain keys differ (different info labels → different outputs).
        let ka = derive_audit_chain_key(TOKEN);
        let kr = derive_rule_epoch_key(TOKEN);
        let kc = derive_confirm_relay_key(TOKEN);
        assert_ne!(ka, kr);
        assert_ne!(ka, kc);
        assert_ne!(kr, kc);
    }

    #[test]
    fn mac_roundtrip() {
        let key = derive_confirm_relay_key(TOKEN);
        let payload = serde_json::json!({"confirm_id":"c1","node_id":"n1","action":"allow","epoch":5,"ts":"2026-08-28T12:00:00Z"});
        let canon = canonical_json(&payload);
        let mac = mac_payload(&key, &canon);
        assert!(verify_mac(&key, &canon, &mac));
    }

    #[test]
    fn verify_mac_rejects_tampered() {
        let key = derive_audit_chain_key(TOKEN);
        let canon = canonical_json(&serde_json::json!({"a":1}));
        let mac = mac_payload(&key, &canon);
        // Tampered payload → MAC mismatch.
        let tampered = canonical_json(&serde_json::json!({"a":2}));
        assert!(!verify_mac(&key, &tampered, &mac));
    }

    #[test]
    fn verify_mac_rejects_empty() {
        let key = derive_audit_chain_key(TOKEN);
        assert!(!verify_mac(&key, b"x", ""));
    }

    #[test]
    fn canonical_json_sorted_compact() {
        // Sorted keys + no whitespace + non-ASCII unescaped (utf-8).
        let v = serde_json::json!({"b":2,"a":1,"c":"café"});
        let out = String::from_utf8(canonical_json(&v)).unwrap();
        assert_eq!(out, r#"{"a":1,"b":2,"c":"café"}"#);
    }

    #[test]
    fn canonical_json_deterministic_across_orders() {
        // Different insertion orders → same output (sorting guarantees determinism).
        let v1 = serde_json::json!({"z":1,"a":2,"m":3});
        let v2 = serde_json::json!({"a":2,"m":3,"z":1});
        assert_eq!(canonical_json(&v1), canonical_json(&v2));
    }
}
