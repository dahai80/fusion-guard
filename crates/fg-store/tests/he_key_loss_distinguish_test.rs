// H-E (product-audit §5, item c+d): distinguish key loss from real tampering + full-chain verifiability after rotation.
//
// Defect (item d): losing the master -> every audit-chain HMAC mismatches -> the old logic always reported
// tampered=true, indistinguishable from real tampering. Fix: per-version key_anchor. On a mismatching row, verify
// checks the anchor: anchor mismatches a recomputation from the current master -> key_version_unknown_rows++
// (key loss, not tampering); anchor matches -> real tampering; anchor missing (legacy NULL) -> fail-closed tamper.
//
// (item c): rotation = bump version (master unchanged). Old rows verify with a key derived from the old version;
// verify passes. Re-hashing the audit chain is rejected (it would break tamper-evidence); per-row key_version
// already makes old rows verify with the old key, so "historical rows verifiable after rotation" holds by design.
// This test extends p12 to all 4 chains (audit/tcc/rules/dead-letter) + tokens and confirms it.
//
// Requires FUSION_GUARD_TOKEN_KEY + FUSION_GUARD_ALLOW_ENV_KEY (so AuditStore::open does not block on Keychain).

use std::path::PathBuf;
use std::sync::Mutex;

use fg_core::{CheckStage, RiskLevel, SafetyAction};
use fg_rules::GuardRule;
use fg_store::AuditStore;

// All 4 tests in this file mutate process-level env (FUSION_GUARD_TOKEN_KEY toggles between KEY_A/KEY_B, plus
// FUSION_GUARD_DATA_DIR pointing at each test's own temp dir). Running in parallel would make AuditStore::open
// read a master/dir another test just set -> key_loss tests load the wrong key -> flaky. A static Mutex serializes
// all tests in this file.
static ENV_GUARD: Mutex<()> = Mutex::new(());

const KEY_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
// A different master from KEY_A (simulates a wrongly regenerated/recovered new key after key loss).
const KEY_B: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

fn temp_env() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "fg-he-dl-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("guard-he.db");
    std::env::set_var("FUSION_GUARD_DATA_DIR", &dir);
    db
}

fn cleanup(dir: &std::path::Path) {
    std::fs::remove_dir_all(dir).ok();
}

// (item c) After rotation, all 4 chains + tokens verify: write v1 -> rotate to v2 -> write v2 -> verify_all_chains passes.
// Proves "historical rows verifiable after rotation" holds, with no re-hash/re-encrypt needed (re-hash breaks tamper-evidence, rejected).
#[tokio::test]
async fn rotation_all_chains_and_tokens_verify() {
    let _env_guard = ENV_GUARD.lock().unwrap();
    std::env::set_var("FUSION_GUARD_TOKEN_KEY", KEY_A);
    std::env::set_var("FUSION_GUARD_ALLOW_ENV_KEY", "1");
    let db = temp_env();
    let store = AuditStore::open(&db).unwrap();
    let now = chrono::Utc::now();

    // v1: audit row + tcc chain + rule mutation + token.
    store.insert_event_at_ts("rot", now, "rm -rf /v1").unwrap();
    store
        .report_tcc_event("Accessibility", "app-a", "granted", "user")
        .unwrap();
    let rule = GuardRule {
        name: "r1".into(),
        pattern: "rm -rf".into(),
        stage: CheckStage::Regex,
        action: SafetyAction::Block,
        risk_level: RiskLevel::L4,
        reason: "rm -rf block".into(),
        scope: fg_core::RuleScope::Command,
    };
    store.save_rule(&rule).unwrap();
    let tokens = store.tokens();
    tokens
        .put_tenant("tok-v1", "sk-v1-secret", "default")
        .unwrap();

    assert_eq!(store.current_key_version(), 1);
    let before = store.verify_all_chains(Some("rot")).unwrap();
    assert!(!before.tampered, "v1 all chains clean");
    assert!(!before.key_loss, "v1 no key loss");

    let new_v = store.rotate_key().unwrap();
    assert_eq!(new_v, 2);

    // v2: write one more row on each chain (mixed v1+v2).
    store.insert_event_at_ts("rot", now, "rm -rf /v2").unwrap();
    store
        .report_tcc_event("Camera", "app-b", "denied", "tcc")
        .unwrap();
    let rule2 = GuardRule {
        name: "r2".into(),
        pattern: "curl|sh".into(),
        stage: CheckStage::Regex,
        action: SafetyAction::Block,
        risk_level: RiskLevel::L4,
        reason: "curl|sh block".into(),
        scope: fg_core::RuleScope::Command,
    };
    store.save_rule(&rule2).unwrap();
    tokens
        .put_tenant("tok-v2", "sk-v2-secret", "default")
        .unwrap();

    let after = store.verify_all_chains(Some("rot")).unwrap();
    assert!(
        !after.tampered,
        "mixed v1+v2 all 4 chains verify (per-row version, P1-2 + H-E item c)"
    );
    assert!(
        !after.key_loss,
        "rotation with the same master has no key loss"
    );
    assert_eq!(
        after.audit.broken_links, 0,
        "audit chain has no broken links"
    );
    assert_eq!(after.tcc.broken_links, 0, "tcc chain has no broken links");
    assert_eq!(
        after.rules.broken_links, 0,
        "rules chain has no broken links"
    );
    assert_eq!(
        after.dead_letter.broken_links, 0,
        "dead_letter chain has no broken links"
    );

    // The old v1 token still decrypts with the v1-derived key (old tokens do not break on rotation).
    let got_v1 = tokens.get_tenant("tok-v1", "default").unwrap();
    assert_eq!(got_v1, "sk-v1-secret", "v1 token decrypts after rotation");
    let got_v2 = tokens.get_tenant("tok-v2", "default").unwrap();
    assert_eq!(got_v2, "sk-v2-secret", "v2 token decrypts");

    let dir = db.parent().unwrap();
    cleanup(dir);
}

// (item d) Key loss: build the DB and write rows with KEY_A -> reopen with KEY_B -> verify_all_chains reports
// key_version_unknown_rows > 0 + key_loss=true, but tampered=false (not real tampering).
#[tokio::test]
async fn key_loss_reports_unknown_not_tampered() {
    let _env_guard = ENV_GUARD.lock().unwrap();
    std::env::set_var("FUSION_GUARD_ALLOW_ENV_KEY", "1");
    std::env::set_var("FUSION_GUARD_TOKEN_KEY", KEY_A);
    let db = temp_env();
    let store = AuditStore::open(&db).unwrap();
    let now = chrono::Utc::now();

    // Write audit rows (land with key_version=1 + anchors derived from KEY_A).
    store.insert_event_at_ts("kt", now, "rm -rf /loss").unwrap();
    store
        .report_tcc_event("Accessibility", "app-x", "granted", "u")
        .unwrap();
    drop(store);

    // Reopen with master B (simulates mistakenly using a new key after key loss; env explicitly provided bypasses the virgin gate).
    std::env::set_var("FUSION_GUARD_TOKEN_KEY", KEY_B);
    let store2 = AuditStore::open(&db).unwrap();

    let v = store2.verify_all_chains(Some("kt")).unwrap();
    // Row HMACs were derived from KEY_A and mismatch master B's derivation -> broken. But the anchors (KEY_A-derived)
    // also mismatch a recomputation from master B -> KeyLoss (not Tamper).
    assert!(
        v.audit.key_version_unknown_rows > 0,
        "audit rows lost their key -> key_version_unknown_rows > 0 (H-E item d)"
    );
    assert!(
        v.audit.broken_links > 0,
        "lost-key rows cannot verify -> broken_links > 0"
    );
    assert!(
        !v.audit.tampered,
        "key loss is not real tampering -> tampered=false (H-E item d core distinction)"
    );
    assert!(v.key_loss, "aggregated key_loss=true");
    assert!(
        !v.tampered,
        "pure key loss (no real tampering) -> aggregated tampered=false"
    );
    // The tcc chain is lost the same way.
    assert!(
        v.tcc.key_version_unknown_rows > 0,
        "tcc chain key loss is distinguished the same way"
    );

    let dir = db.parent().unwrap();
    cleanup(dir);
}

// (item d) Real tampering: directly modify a row's event_hash under the same master -> anchor matches (master can
// derive it) -> tampered=true, key_version_unknown_rows=0.
#[tokio::test]
async fn real_tamper_reports_tampered_not_key_loss() {
    let _env_guard = ENV_GUARD.lock().unwrap();
    std::env::set_var("FUSION_GUARD_ALLOW_ENV_KEY", "1");
    std::env::set_var("FUSION_GUARD_TOKEN_KEY", KEY_A);
    let db = temp_env();
    let store = AuditStore::open(&db).unwrap();
    let now = chrono::Utc::now();

    store.insert_event_at_ts("tp", now, "rm -rf /ok").unwrap();
    store
        .insert_event_at_ts("tp", now, "rm -rf /tamper")
        .unwrap();

    // Use the write connection to tamper with the 2nd row's event_hash directly (same master, anchor still matches).
    {
        let w = store.audit_writer_handle();
        let w = w.lock().unwrap();
        w.execute(
            "UPDATE audit_events SET event_hash = 'deadbeef' WHERE rowid = \
             (SELECT rowid FROM audit_events ORDER BY rowid DESC LIMIT 1)",
            [],
        )
        .unwrap();
    }

    let v = store.verify_all_chains(Some("tp")).unwrap();
    assert!(
        v.audit.tampered,
        "same-master event_hash modification = real tampering -> tampered=true (H-E item d)"
    );
    assert!(
        v.audit.key_version_unknown_rows == 0,
        "real tampering is not key loss -> key_version_unknown_rows=0"
    );
    assert!(v.tampered, "aggregated tampered=true");
    assert!(!v.key_loss, "real tampering -> key_loss=false");

    let dir = db.parent().unwrap();
    cleanup(dir);
}

// (item d) Anchor missing (legacy NULL) -> fail-closed tamper. An attacker clearing anchors cannot disguise the act as key loss.
#[tokio::test]
async fn missing_anchor_fail_closed_as_tamper() {
    let _env_guard = ENV_GUARD.lock().unwrap();
    std::env::set_var("FUSION_GUARD_ALLOW_ENV_KEY", "1");
    std::env::set_var("FUSION_GUARD_TOKEN_KEY", KEY_A);
    let db = temp_env();
    let store = AuditStore::open(&db).unwrap();
    let now = chrono::Utc::now();

    store
        .insert_event_at_ts("ma", now, "rm -rf /anchor")
        .unwrap();

    // Tamper with an audit row's event_hash (forcing an HMAC mismatch) + clear the v1 anchor in token.db to NULL.
    {
        let w = store.audit_writer_handle();
        let w = w.lock().unwrap();
        w.execute(
            "UPDATE audit_events SET event_hash = 'cafebabe' WHERE rowid = \
             (SELECT rowid FROM audit_events ORDER BY rowid DESC LIMIT 1)",
            [],
        )
        .unwrap();
        let token_db = db.with_file_name("token.db");
        let tc = rusqlite::Connection::open(&token_db).unwrap();
        tc.execute(
            "UPDATE key_versions SET key_anchor = NULL WHERE version = 1",
            [],
        )
        .unwrap();
    }

    let v = store.verify_all_chains(Some("ma")).unwrap();
    assert!(
        v.audit.tampered,
        "anchor NULL + HMAC mismatch -> fail-closed tampered=true (H-E, attackers clearing anchors get no hiding place)"
    );
    assert!(
        v.audit.key_version_unknown_rows == 0,
        "missing anchor does not count as key loss -> key_version_unknown_rows=0"
    );

    let dir = db.parent().unwrap();
    cleanup(dir);
}
