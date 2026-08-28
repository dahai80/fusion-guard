// key.rs — HKDF-SHA256 域分离密钥派生 + HMAC-SHA256 签名/验签。
// 镜像 fusion-multi-node security/cluster_key.py (issue #52 契约), 算法须逐字节一致。

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

// 域分离 info 标签 — v1 后缀便于未来无冲突升级 (v2 标签 → 新密钥空间, 旧 MAC 失效)。
// 与 multi-node _AUDIT_CHAIN_INFO / _RULE_EPOCH_INFO / _CONFIRM_RELAY_INFO 完全一致。
const AUDIT_CHAIN_INFO: &[u8] = b"fusion-multinode-audit-chain-v1";
const RULE_EPOCH_INFO: &[u8] = b"fusion-multinode-rule-epoch-v1";
const CONFIRM_RELAY_INFO: &[u8] = b"fusion-multinode-confirm-relay-v1";

const KEY_LEN: usize = 32; // SHA256 → 32 字节

type HmacSha256 = Hmac<Sha256>;

// HKDF-SHA256 派生 — salt=None (与 multi-node _hkdf_derive 一致)。
fn hkdf_derive(secret: &str, info: &[u8]) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(None, secret.as_bytes());
    let mut okm = [0u8; KEY_LEN];
    hk.expand(info, &mut okm)
        .expect("32 字节在 HKDF-SHA256 输出上限内");
    okm
}

// 审计链 MAC 密钥 — 派生自 cluster_token, audit-chain 域。
pub fn derive_audit_chain_key(cluster_token: &str) -> [u8; KEY_LEN] {
    hkdf_derive(cluster_token, AUDIT_CHAIN_INFO)
}

// 规则纪元 MAC 密钥 — rule-epoch 域。
pub fn derive_rule_epoch_key(cluster_token: &str) -> [u8; KEY_LEN] {
    hkdf_derive(cluster_token, RULE_EPOCH_INFO)
}

// confirm 中继 MAC 密钥 — confirm-relay 域。
pub fn derive_confirm_relay_key(cluster_token: &str) -> [u8; KEY_LEN] {
    hkdf_derive(cluster_token, CONFIRM_RELAY_INFO)
}

// HMAC-SHA256 → hex 字符串 (记录/请求携带)。镜像 multi-node mac_payload。
pub fn mac_payload(key: &[u8], canonical: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC 接受任意长度密钥");
    mac.update(canonical);
    hex::encode(mac.finalize().into_bytes())
}

// 常量时间 MAC 校验 — 空 mac → False (不抛)。镜像 multi-node verify_mac。
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

// 规范 JSON — 键排序 + 无空白 + ensure_ascii=False (中文不转义, utf-8 编码)。
// 签名输入须确定性: 键序/空白/转义不一致 → MAC 不匹配。guard 与多节点须同算法。
// 镜像 multi-node canonical_json: json.dumps(payload, sort_keys=True, separators=(",",":"), ensure_ascii=False)
pub fn canonical_json(payload: &serde_json::Value) -> Vec<u8> {
    // serde_json 默认不转义非 ASCII (ensure_ascii=False 等价), 但须显式排序键 + 紧凑分隔。
    let mut buf = Vec::new();
    let formatter = serde_json::ser::CompactFormatter;
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, formatter);
    serialize_sorted(payload, &mut ser);
    buf
}

// 递归序列化, 对象键按字典序排序 (与 Python json.dumps(sort_keys=True) 一致)。
fn serialize_sorted<W: std::io::Write>(
    value: &serde_json::Value,
    ser: &mut serde_json::Serializer<W, serde_json::ser::CompactFormatter>,
) {
    use serde::Serialize;
    match value {
        serde_json::Value::Object(map) => {
            // 收集键, 排序, 按序序列化。
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
        // 同 token + 同 info → 同密钥 (HKDF 确定性)。
        let k1 = derive_audit_chain_key(TOKEN);
        let k2 = derive_audit_chain_key(TOKEN);
        assert_eq!(k1, k2);
    }

    #[test]
    fn hkdf_domain_separated() {
        // 3 域密钥互异 (info 标签不同 → 不同输出)。
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
        // 篡改 payload → MAC 不匹配。
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
        // 键排序 + 无空白 + 中文不转义 (utf-8)。
        let v = serde_json::json!({"b":2,"a":1,"c":"中文"});
        let out = String::from_utf8(canonical_json(&v)).unwrap();
        assert_eq!(out, r#"{"a":1,"b":2,"c":"中文"}"#);
    }

    #[test]
    fn canonical_json_deterministic_across_orders() {
        // 不同插入顺序 → 同输出 (排序保证确定性)。
        let v1 = serde_json::json!({"z":1,"a":2,"m":3});
        let v2 = serde_json::json!({"a":2,"m":3,"z":1});
        assert_eq!(canonical_json(&v1), canonical_json(&v2));
    }
}
