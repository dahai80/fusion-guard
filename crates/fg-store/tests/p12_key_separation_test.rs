// P1-2 (audit §1.6): HKDF domain separation + versioned rotation.
// Three tests: (1) domain separation — same master derives chain-HMAC key != token-AES-GCM key;
//       (2) rotation — old audit rows verify with a key derived from the old version, new rows use the new
//       version, verify_chain passes;
//       (3) old token decrypts after rotation — put @v1, rotate -> v2, get_tenant still decrypts the v1 token
//       (using the v1-derived key).
//
// Requires FUSION_GUARD_TOKEN_KEY (AuditStore::open -> TokenStore loads the key).
// test-helpers feature: derive_chain_key / derive_token_key exposed so domain separation can be asserted.

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

// Domain separation: same master, same version, chain key != token key (different info labels -> independent HKDF output).
// Prevents a single leak from failing both: chain key leak -> tokens stay undecryptable; token key leak -> audit chain stays unforgeable.
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
    // Deterministic: same master + same version recomputes identically (old chain/token verifiable across restart).
    let chain2 = derive_chain_key(&master, 1);
    assert_eq!(
        chain.as_slice(),
        chain2.as_slice(),
        "derivation deterministic"
    );
}

// Versioned: different versions derive different keys (rotation semantics — bumping the version swaps the key).
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

// Rotation + old-row chain verification: write v1 rows -> rotate to v2 -> write v2 rows -> verify_chain passes
// (old rows verify with the v1-derived chain key, new rows with v2; each row stores key_version, verify derives per row).
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
    assert_eq!(new_v, 2, "rotate -> v2");
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

// Old token decrypts after token-key rotation: put @v1 -> rotate to v2 -> get_tenant still reveals the v1 plaintext.
// get_tenant reads the row's key_version and decrypts with the v1-derived token key (old tokens do not break on rotation).
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

    // Write a new token under v2.
    tokens
        .put_tenant("tok-v2", "sk-new-xyz", "default")
        .unwrap();

    // The old v1 token still decrypts (v1-derived key; row stores key_version=1).
    let got_old = tokens.get_tenant("tok-v1", "default").unwrap();
    assert_eq!(
        got_old, secret,
        "v1 token decrypts after rotation (per-row key_version, P1-2)"
    );
    // The new v2 token also decrypts (v2-derived key).
    let got_new = tokens.get_tenant("tok-v2", "default").unwrap();
    assert_eq!(got_new, "sk-new-xyz", "v2 token decrypts with v2 key");

    cleanup(&dir);
}
