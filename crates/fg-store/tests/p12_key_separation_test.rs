// P1-2 (audit §1.6): HKDF 域分离 + 版本化轮换。
// 三测: (1) 域分离 — 同 master 派生 chain-HMAC key != token-AES-GCM key;
//       (2) 轮换 — 旧审计行用旧 version 派生 key 验链, 新行用新 version, verify_chain 透过;
//       (3) token 轮换后旧 token 解密 — put @v1, rotate→v2, get_tenant 仍解 v1 token (用 v1 派生 key)。
//
// 需要 FUSION_GUARD_TOKEN_KEY (AuditStore::open → TokenStore 加载密钥)。
// test-helpers feature: derive_chain_key / derive_token_key 暴露供断言域分离。

use std::path::PathBuf;

use fg_store::token_store::{derive_chain_key, derive_token_key};
use fg_store::AuditStore;
use zeroize::Zeroizing;

const TEST_KEY_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn ensure_env_key() {
    if std::env::var("FUSION_GUARD_TOKEN_KEY").is_err() {
        std::env::set_var("FUSION_GUARD_TOKEN_KEY", TEST_KEY_HEX);
    }
}

fn temp_env() -> (PathBuf, PathBuf) {
    ensure_env_key();
    let dir = std::env::temp_dir().join(format!(
        "fg-p12-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("guard-p12.db");
    std::env::set_var("FUSION_GUARD_DATA_DIR", &dir);
    (db, dir)
}

fn cleanup(dir: &std::path::Path) {
    std::fs::remove_dir_all(dir).ok();
}

// 域分离: 同 master, 同 version, chain key != token key (不同 info label → HKDF 独立输出)。
// 防单点泄露双失守: chain key 泄 → 不可解 token; token key 泄 → 不可伪造审计链。
#[test]
fn key_separation_chain_ne_token() {
    ensure_env_key();
    let master = Zeroizing::new([0x42u8; 32]);
    let chain = derive_chain_key(&master, 1);
    let token = derive_token_key(&master, 1);
    assert_ne!(
        chain.as_slice(),
        token.as_slice(),
        "chain-HMAC key must differ from token-AES-GCM key (HKDF domain separation, P1-2 §1.6)"
    );
    // 确定性: 同 master + 同 version 重算一致 (跨重启验旧链/解旧 token 可重算)。
    let chain2 = derive_chain_key(&master, 1);
    assert_eq!(
        chain.as_slice(),
        chain2.as_slice(),
        "derivation deterministic"
    );
}

// 版本化: 不同 version 派生不同 key (轮换语义 — bump version 即换 key)。
#[test]
fn key_version_derives_distinct() {
    ensure_env_key();
    let master = Zeroizing::new([0x07u8; 32]);
    let k1 = derive_chain_key(&master, 1);
    let k2 = derive_chain_key(&master, 2);
    assert_ne!(k1.as_slice(), k2.as_slice(), "v1 key != v2 key (rotation)");
    let t1 = derive_token_key(&master, 1);
    let t2 = derive_token_key(&master, 2);
    assert_ne!(t1.as_slice(), t2.as_slice(), "v1 token key != v2 token key");
}

// 轮换 + 旧行验链: 写 v1 行 → rotate v2 → 写 v2 行 → verify_chain 透过
// (旧行用 v1 派生 chain key 验, 新行用 v2; 每行存 key_version, verify 按行版本派生)。
#[tokio::test]
async fn rotation_old_audit_rows_verify_with_old_key() {
    let (db, dir) = temp_env();
    let store = AuditStore::open(&db).unwrap();

    assert_eq!(store.current_key_version(), 1, "start at v1");

    let now = chrono::Utc::now();
    store
        .insert_event_at_ts("rot", now, "rm -rf /v1-a")
        .unwrap();
    store
        .insert_event_at_ts("rot", now, "rm -rf /v1-b")
        .unwrap();

    let v_before = store.verify_chain(Some("rot")).unwrap();
    assert!(!v_before.tampered, "v1 chain clean pre-rotation");
    assert_eq!(v_before.total_rows, 2, "2 v1 rows pre-rotation");

    let new_v = store.rotate_key().unwrap();
    assert_eq!(new_v, 2, "rotate → v2");
    assert_eq!(store.current_key_version(), 2, "live version now 2");

    store
        .insert_event_at_ts("rot", now, "rm -rf /v2-a")
        .unwrap();
    store
        .insert_event_at_ts("rot", now, "rm -rf /v2-b")
        .unwrap();

    let v_after = store.verify_chain(Some("rot")).unwrap();
    assert!(
        !v_after.tampered,
        "mixed v1+v2 chain verifies (per-row version derivation, P1-2)"
    );
    assert_eq!(v_after.broken_links, 0, "no broken links across rotation");
    assert_eq!(v_after.total_rows, 4, "all 4 rows in verify scope (v1+v2)");

    let rows = store.list_events(Some("rot"), 100).unwrap();
    assert_eq!(rows.len(), 4, "4 rows v1+v2");

    cleanup(&dir);
}

// token 轮换后旧 token 解密: put @v1 → rotate v2 → get_tenant 仍解出 v1 token 原文。
// get_tenant 读行的 key_version, 用 v1 派生 token key 解 (旧 token 不随轮换失效)。
#[tokio::test]
async fn token_reveals_after_rotation() {
    let (db, dir) = temp_env();
    let store = AuditStore::open(&db).unwrap();

    let tokens = store.tokens();
    let secret = "sk-live-abc123";
    tokens.put_tenant("tok-v1", secret, "default").unwrap();

    let got_before = tokens.get_tenant("tok-v1", "default").unwrap();
    assert_eq!(got_before, secret, "reveal works pre-rotation");

    let new_v = store.rotate_key().unwrap();
    assert_eq!(new_v, 2);

    // v2 写新 token。
    tokens
        .put_tenant("tok-v2", "sk-new-xyz", "default")
        .unwrap();

    // v1 旧 token 仍可解 (用 v1 派生 key, 行存 key_version=1)。
    let got_old = tokens.get_tenant("tok-v1", "default").unwrap();
    assert_eq!(
        got_old, secret,
        "v1 token decrypts after rotation (per-row key_version, P1-2)"
    );
    // v2 新 token 也可解 (用 v2 派生 key)。
    let got_new = tokens.get_tenant("tok-v2", "default").unwrap();
    assert_eq!(got_new, "sk-new-xyz", "v2 token decrypts with v2 key");

    cleanup(&dir);
}
