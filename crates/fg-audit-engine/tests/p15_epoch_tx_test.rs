// P1-5 (audit §P1-5): epoch orchestration-layer transactionalization — concurrent add_rule never loses an epoch bump.
//
// add_rule's three steps (persist rule → in-memory add → persist epoch) are not atomic. Without the orchestration
// mutex, two concurrent threads:
//   T1 reads epoch=N, T2 reads epoch=N → each bumps to N+1 and writes → one bump is lost; the epoch stays monotonic
// but diverges from the rule count.
// Fix: AuditEngine holds rule_orch_lock (Mutex); add/update/remove hold it throughout, serializing the three-step
// orchestration.
//
// Acceptance: N threads add_rule concurrently → final epoch == start+N (no lost bumps) and all N rules persisted
// (none lost).
// Isolated env: dedicated DATA_DIR + TOKEN_KEY.

use std::path::PathBuf;
use std::sync::Arc;

use fg_audit_engine::AuditEngine;
use fg_core::{CheckStage, RiskLevel, RuleScope, SafetyAction};
use fg_rules::GuardRule;
use fg_store::AuditStore;

const TEST_KEY_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const CONCURRENT_ADDS: usize = 16;

fn ensure_env_key() {
    if std::env::var("FUSION_GUARD_TOKEN_KEY").is_err() {
        std::env::set_var("FUSION_GUARD_TOKEN_KEY", TEST_KEY_HEX);
    }
}

fn temp_env() -> (PathBuf, PathBuf) {
    ensure_env_key();
    let dir = std::env::temp_dir().join(format!(
        "fg-p15-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("guard-p15.db");
    std::env::set_var("FUSION_GUARD_DATA_DIR", &dir);
    (db, dir)
}

fn cleanup(dir: &std::path::Path) {
    std::fs::remove_dir_all(dir).ok();
}

fn make_rule(idx: usize) -> GuardRule {
    GuardRule {
        name: format!("p15-concurrent-{}", idx),
        pattern: format!("dangerous_pattern_{}", idx),
        stage: CheckStage::Regex,
        action: SafetyAction::Block,
        risk_level: RiskLevel::L4,
        reason: format!("P1-5 concurrent test rule {}", idx),
        scope: RuleScope::Command,
    }
}

// P1-5 core: 16 threads add_rule concurrently → epoch strictly increases by 16 (no lost bumps), all 16 rules persisted.
#[test]
fn concurrent_add_rule_no_lost_epoch_bump() {
    let (db, dir) = temp_env();
    let store = Arc::new(AuditStore::open(&db).unwrap());
    let engine = Arc::new(AuditEngine::new(store.clone()).unwrap());

    let start_epoch = engine.epoch();
    tracing::info!(start_epoch, "P1-5: concurrent add_rule starting epoch");

    // 16 threads add_rule concurrently, each adding one unique rule.
    let mut handles = Vec::with_capacity(CONCURRENT_ADDS);
    for i in 0..CONCURRENT_ADDS {
        let eng = Arc::clone(&engine);
        handles.push(std::thread::spawn(move || {
            let rule = make_rule(i);
            eng.add_rule(rule).expect("add_rule must succeed")
        }));
    }
    let epochs: Vec<u64> = handles
        .into_iter()
        .map(|h| h.join().expect("thread panicked"))
        .collect();

    let final_epoch = engine.epoch();

    // Acceptance 1: epoch strictly increases by CONCURRENT_ADDS (no lost bumps). Without the lock, concurrent adds
    // lose bumps → final < start+N.
    assert_eq!(
        final_epoch,
        start_epoch + CONCURRENT_ADDS as u64,
        "P1-5: epoch must strictly increase by {} after concurrent add_rule (no lost bumps), start={} final={}",
        CONCURRENT_ADDS,
        start_epoch,
        final_epoch
    );

    // Acceptance 2: epochs returned by the threads are monotonic and unique (each bump serialized, no duplicates).
    let mut sorted = epochs.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        CONCURRENT_ADDS,
        "P1-5: epochs returned by add_rule must be unique (no two threads bump the same value), got epochs={:?}",
        epochs
    );

    // Acceptance 3: all 16 rules persisted (reload the ruleset, count includes the 16 new rules).
    let reloaded = store
        .load_rules()
        .expect("load_rules query")
        .expect("ruleset persisted after concurrent adds");
    for i in 0..CONCURRENT_ADDS {
        let name = format!("p15-concurrent-{}", i);
        let found = reloaded.rules.iter().any(|r| r.name == name);
        assert!(
            found,
            "P1-5: rule {} must be persisted after concurrent add_rule (no lost rules)",
            name
        );
    }

    cleanup(&dir);
}

// P1-5 control: sequential single-thread add_rule → epoch strictly increases by N (baseline, proving the concurrent
// test does not pass by accident).
#[test]
fn sequential_add_rule_epoch_strictly_increases() {
    let (db, dir) = temp_env();
    let store = Arc::new(AuditStore::open(&db).unwrap());
    let engine = AuditEngine::new(store).unwrap();

    let start_epoch = engine.epoch();
    for i in 0..CONCURRENT_ADDS {
        let ep = engine.add_rule(make_rule(100 + i)).expect("add_rule");
        assert_eq!(
            ep,
            start_epoch + 1 + i as u64,
            "P1-5: sequential add_rule epoch must strictly +1 each time"
        );
    }
    assert_eq!(
        engine.epoch(),
        start_epoch + CONCURRENT_ADDS as u64,
        "P1-5: sequential add_rule final epoch"
    );

    cleanup(&dir);
}
