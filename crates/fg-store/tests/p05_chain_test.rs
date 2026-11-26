// P0-5 (audit §1.4): TCC chain + rule mutation chain + dead-letter HMAC/reimport + all-chains aggregate verification.
// The dead-letter file is written by the store's internal spool_dead_letter (with prev_hmac/hmac); tests cannot call
// that private fn directly. Instead we construct a valid dead-letter file directly (computing hmac with the same
// algorithm as the store) to verify verify_dead_letter + reimport_dead_letter.
//
// Requires FUSION_GUARD_TOKEN_KEY (AuditStore::open -> TokenStore loads the key) + the test-helpers feature
// (insert_event_at_ts exposed so valid audit chain rows with a ts can be constructed).

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use fg_core::{CheckStage, GuardVerdict, RiskLevel, SafetyAction};
use fg_rules::GuardRule;
use fg_store::token_store::derive_chain_key;
use fg_store::AuditStore;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

const TEST_KEY_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn ensure_env_key() {
    if std::env::var("FUSION_GUARD_TOKEN_KEY").is_err() {
        std::env::set_var("FUSION_GUARD_TOKEN_KEY", TEST_KEY_HEX);
    }
}

fn verdict(action: SafetyAction, risk: RiskLevel, cat: &str) -> GuardVerdict {
    GuardVerdict {
        action,
        risk_level: risk,
        reason: "test".into(),
        stage: CheckStage::Regex,
        requires_approval: false,
        redacted_content: None,
        seatbelt_required: false,
        action_id: None,
        verdict_epoch: 1,
        verdict_ttl_secs: 30,
        inferred_category: cat.into(),
        category_hint: None,
    }
}

fn temp_env() -> (PathBuf, PathBuf) {
    ensure_env_key();
    let dir = std::env::temp_dir().join(format!(
        "fg-p05-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("guard-p05.db");
    std::env::set_var("FUSION_GUARD_DATA_DIR", &dir);
    (db, dir)
}

fn cleanup(dir: &std::path::Path) {
    std::fs::remove_dir_all(dir).ok();
}

// Same key as the store (injected via env; the store reads the same env) -> the test-side hmac recomputation must match the store's.
fn test_key() -> [u8; 32] {
    let hex = std::env::var("FUSION_GUARD_TOKEN_KEY").unwrap_or_else(|_| TEST_KEY_HEX.into());
    let mut out = [0u8; 32];
    let bytes = hex::decode(hex).unwrap();
    out.copy_from_slice(&bytes[..32]);
    out
}

// TCC chain: report several events -> verify_tcc_chain clean, all-chains aggregate tampered=false.
#[tokio::test]
async fn tcc_chain_verify_clean() {
    let (db, dir) = temp_env();
    let store = AuditStore::open(&db).unwrap();

    store
        .report_tcc_event("Accessibility", "app-a", "granted", "user-init")
        .unwrap();
    store
        .report_tcc_event("ScreenRecording", "app-b", "denied", "not-authorized")
        .unwrap();
    store
        .report_tcc_event("FullDiskAccess", "app-c", "granted", "user-init")
        .unwrap();

    let v = store.verify_tcc_chain().unwrap();
    assert_eq!(v.total_rows, 3);
    assert_eq!(v.broken_links, 0);
    assert!(!v.tampered, "TCC chain clean (3 events)");
    assert_eq!(v.verified_links, 3);

    // All-chains aggregate: audit empty + tcc clean + rules (may hold the epoch seed mutation) + dead_letter empty -> tampered=false.
    let all = store.verify_all_chains(None).unwrap();
    assert!(!all.tampered, "all-chains clean (no tamper anywhere)");
    assert_eq!(all.tcc.total_rows, 3);

    cleanup(&dir);
}

// Rule mutation chain: save_rule + delete_rule + save_epoch -> verify_rules_chain clean, recording the mutation sequence.
#[tokio::test]
async fn rule_mutation_chain_verify_clean() {
    let (db, dir) = temp_env();
    let store = AuditStore::open(&db).unwrap();

    let rule = GuardRule {
        name: "block-rmrf".into(),
        pattern: r"rm\s+-rf".into(),
        stage: CheckStage::Regex,
        action: SafetyAction::Block,
        risk_level: RiskLevel::L4,
        reason: "rm -rf block".into(),
        scope: fg_core::RuleScope::Command,
    };
    store.save_rule(&rule).unwrap();
    store.save_epoch(2).unwrap();
    store.delete_rule("block-rmrf").unwrap();

    let v = store.verify_rules_chain().unwrap();
    // save_rule + save_epoch + delete_rule = 3 mutation rows (+ the seed epoch 1, seeded by AuditEngine at startup).
    // The test uses the store directly without the AuditEngine seed, so rule_mutations holds only these 3 rows.
    assert_eq!(v.total_rows, 3);
    assert_eq!(v.broken_links, 0);
    assert!(!v.tampered, "rule mutation chain clean (3 mutations)");
    assert_eq!(v.verified_links, 3);

    cleanup(&dir);
}

// Rule mutation chain tamper: UPDATE rule_mutations.event_hash directly -> verify_rules_chain detects tampered.
#[tokio::test]
async fn rule_mutation_chain_detects_tamper() {
    let (db, dir) = temp_env();
    let store = AuditStore::open(&db).unwrap();

    let rule = GuardRule {
        name: "block-curl".into(),
        pattern: r"curl\s+pipe".into(),
        stage: CheckStage::Regex,
        action: SafetyAction::Block,
        risk_level: RiskLevel::L4,
        reason: "curl pipe block".into(),
        scope: fg_core::RuleScope::Command,
    };
    store.save_rule(&rule).unwrap();
    store.save_rule(&rule).unwrap(); // second row -> chain of 2

    // Tamper with the first row's event_hash (simulating a direct DB edit).
    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute(
        "UPDATE rule_mutations SET event_hash='deadbeef' WHERE mutation_id=\
         (SELECT mutation_id FROM rule_mutations ORDER BY rowid ASC LIMIT 1)",
        [],
    )
    .unwrap();
    drop(conn);

    let v = store.verify_rules_chain().unwrap();
    assert!(
        v.tampered,
        "rule mutation chain MUST detect tampered event_hash"
    );
    assert!(v.broken_links >= 1, "at least 1 broken link");
    assert!(v.first_broken_at.is_some());

    cleanup(&dir);
}

// Dead-letter file verify + reimport: construct a valid dead-letter file (same-algorithm hmac) -> verify clean -> reimport back into audit_events.
#[tokio::test]
async fn dead_letter_verify_and_reimport() {
    let (db, dir) = temp_env();
    let store = AuditStore::open(&db).unwrap();
    let dl_path = db.with_extension("deadletter");

    // Construct 2 valid dead-letter rows (hmac chain: prev_hmac = previous row's hmac, hmac = HMAC(key, prev_hmac||payload)).
    let key = test_key();
    let mut prev_hmac =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    use std::io::Write;
    let mut f = std::fs::File::create(&dl_path).unwrap();
    for i in 0..2 {
        let ev = fg_store::AuditEvent {
            audit_id: uuid::Uuid::new_v4(),
            ts: chrono::Utc::now(),
            event_type: "evaluate".into(),
            tenant_id: "default".into(),
            requester: format!("app-{}", i),
            action: "block".into(),
            inferred_category: "shell_exec".into(),
            verdict_json: serde_json::to_string(&verdict(
                SafetyAction::Block,
                RiskLevel::L4,
                "shell_exec",
            ))
            .unwrap(),
            approved_by: None,
            seatbelt_required: true,
            outcome: "blocked".into(),
            prev_hash: String::new(),
            event_hash: String::new(),
        };
        let payload = ev.payload_bytes();
        let dkey = derive_chain_key(&Zeroizing::new(key), 1);
        let mut mac = HmacSha256::new_from_slice(&dkey[..]).unwrap();
        mac.update(prev_hmac.as_bytes());
        mac.update(&payload);
        let hmac_hex = hex::encode(mac.finalize().into_bytes());
        let ev_json = serde_json::to_string(&ev).unwrap();
        let line = format!(
            "{{\"prev_hmac\":\"{}\",\"hmac\":\"{}\",\"key_version\":1,\"reason\":\"queue full\",\"event\":{}}}\n",
            prev_hmac, hmac_hex, ev_json
        );
        f.write_all(line.as_bytes()).unwrap();
        prev_hmac = hmac_hex;
    }
    drop(f);
    let _ = std::fs::set_permissions(&dl_path, std::fs::Permissions::from_mode(0o600));

    // verify_dead_letter clean (2 rows with a continuous hmac chain).
    let v = store.verify_dead_letter();
    assert_eq!(v.total_rows, 2);
    assert_eq!(v.broken_links, 0);
    assert!(!v.tampered, "dead-letter chain clean (2 valid hmac rows)");
    assert_eq!(v.verified_links, 2);

    // reimport -> rows go back into audit_events continuing the main chain; the dead-letter file is cleared.
    let imported = store.reimport_dead_letter().unwrap();
    assert_eq!(imported, 2, "2 dead-letter events reimported");

    // The dead-letter file is cleared.
    let remaining = std::fs::read_to_string(&dl_path).unwrap();
    assert!(
        remaining.trim().is_empty(),
        "dead-letter file cleared after reimport"
    );

    // audit_events holds 2 rows (reimported); the main chain continues and verifies clean.
    let av = store.verify_chain(None).unwrap();
    assert_eq!(av.total_rows, 2);
    assert!(
        !av.tampered,
        "audit chain clean after reimport (continued from dead-letter)"
    );

    cleanup(&dir);
}

// Dead-letter tamper: change one row's hmac -> verify_dead_letter detects tampered + reimport refuses (no rows imported).
#[tokio::test]
async fn dead_letter_tamper_detected_and_reimport_aborts() {
    let (db, dir) = temp_env();
    let store = AuditStore::open(&db).unwrap();
    let dl_path = db.with_extension("deadletter");

    let key = test_key();
    let mut prev_hmac =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    use std::io::Write;
    let mut f = std::fs::File::create(&dl_path).unwrap();
    for i in 0..2 {
        let ev = fg_store::AuditEvent {
            audit_id: uuid::Uuid::new_v4(),
            ts: chrono::Utc::now(),
            event_type: "evaluate".into(),
            tenant_id: "default".into(),
            requester: format!("app-{}", i),
            action: "block".into(),
            inferred_category: "shell_exec".into(),
            verdict_json: serde_json::to_string(&verdict(
                SafetyAction::Block,
                RiskLevel::L4,
                "shell_exec",
            ))
            .unwrap(),
            approved_by: None,
            seatbelt_required: true,
            outcome: "blocked".into(),
            prev_hash: String::new(),
            event_hash: String::new(),
        };
        let payload = ev.payload_bytes();
        let dkey = derive_chain_key(&Zeroizing::new(key), 1);
        let mut mac = HmacSha256::new_from_slice(&dkey[..]).unwrap();
        mac.update(prev_hmac.as_bytes());
        mac.update(&payload);
        let hmac_hex = hex::encode(mac.finalize().into_bytes());
        let ev_json = serde_json::to_string(&ev).unwrap();
        let line = format!(
            "{{\"prev_hmac\":\"{}\",\"hmac\":\"{}\",\"key_version\":1,\"reason\":\"queue full\",\"event\":{}}}\n",
            prev_hmac, hmac_hex, ev_json
        );
        f.write_all(line.as_bytes()).unwrap();
        prev_hmac = hmac_hex;
    }
    drop(f);

    // Tamper with the first row's hmac.
    let content = std::fs::read_to_string(&dl_path).unwrap();
    let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
    let mut tampered_line = lines[0].replace("\"hmac\":\"", "\"hmac\":\"deadbeef");
    // Keep the rest of the line. The replace above only changes the first hmac occurrence (this row's hmac field);
    // prev_hmac does not contain "hmac":".
    tampered_line.push('\n');
    let second_line = format!("{}\n", lines[1]);
    std::fs::write(&dl_path, format!("{}{}", tampered_line, second_line)).unwrap();

    let v = store.verify_dead_letter();
    assert!(v.tampered, "dead-letter MUST detect tampered hmac");
    assert!(v.broken_links >= 1);

    // reimport signature verification fails -> refuse to import any rows (returns Err).
    let res = store.reimport_dead_letter();
    assert!(
        res.is_err(),
        "reimport MUST abort on tampered dead-letter (no partial import)"
    );

    // audit_events is still empty (nothing imported).
    let av = store.verify_chain(None).unwrap();
    assert_eq!(
        av.total_rows, 0,
        "no events imported from tampered dead-letter"
    );

    cleanup(&dir);
}

// All-chains aggregate: audit + tcc + rules + dead-letter all hold data -> verify_all_chains fully clean, tampered=false.
#[tokio::test]
async fn all_chains_aggregate_clean() {
    let (db, dir) = temp_env();
    let store = AuditStore::open(&db).unwrap();

    // audit chain: 1 row (low risk).
    store
        .insert_event_at_ts("default", chrono::Utc::now(), "ls -la")
        .unwrap();

    // tcc chain: 1 row.
    store
        .report_tcc_event("Microphone", "app-x", "granted", "user-init")
        .unwrap();

    // rules chain: 1 mutation.
    let rule = GuardRule {
        name: "block-sudo".into(),
        pattern: r"^sudo\b".into(),
        stage: CheckStage::Regex,
        action: SafetyAction::Block,
        risk_level: RiskLevel::L4,
        reason: "sudo block".into(),
        scope: fg_core::RuleScope::Command,
    };
    store.save_rule(&rule).unwrap();

    // Dead-letter empty (no queue-full events) -> dead_letter.total_rows=0 clean.

    let all = store.verify_all_chains(None).unwrap();
    assert!(!all.tampered, "all chains clean in aggregate");
    assert!(all.audit.total_rows >= 1);
    assert_eq!(all.tcc.total_rows, 1);
    assert_eq!(all.rules.total_rows, 1);
    assert_eq!(all.dead_letter.total_rows, 0);

    cleanup(&dir);
}
