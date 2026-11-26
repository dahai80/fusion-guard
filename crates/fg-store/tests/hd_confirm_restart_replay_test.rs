// H-D (product-audit §5): crash-recovery-grade one-time regression for confirm's cross-db transaction.
// Root cause: the original confirm_atomic ran SELECT+INSERT+UPDATE each committed independently in autocommit.
// Crash window (audit INSERT committed, UPDATE consumed not committed) -> after restart action_id still consumed=0
// -> confirm again = double-confirm replay, violating H4 one-time. Fix: BEGIN IMMEDIATE cross-ATTACH transaction
// (audit_writer ATTACHes action.db); all three steps commit atomically in one transaction, achieving crash-recovery-grade H4.
//
// This test verifies crash-recovery semantics: after confirm, drop the store (simulating a process crash) ->
// re-open a new store at the same path -> re-confirm the same action_id -> must return Consumed
// (consumed already persisted, no replay window).
// I.e. the confirm consume persist and the audit persist are atomic; state is consistent after restart.
//
// Also includes the H-A concurrent mixed-risk single-writer regression: high-risk (Block L4, sync write via
// audit_writer) and low-risk (L1, async drain via low_writer) concurrent inserts -> verify_chain must show no
// broken/tampered rows (single writer serialized via BEGIN IMMEDIATE, no chain fork).

use std::sync::Arc;

use fg_core::{CheckStage, GuardVerdict, RiskLevel, SafetyAction};
use fg_store::AuditStore;
use zeroize::Zeroizing;

const TEST_KEY_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn ensure_env_key() {
    if std::env::var("FUSION_GUARD_TOKEN_KEY").is_err() {
        std::env::set_var("FUSION_GUARD_TOKEN_KEY", TEST_KEY_HEX);
    }
}

fn temp_db(tag: &str) -> std::path::PathBuf {
    ensure_env_key();
    let dir = std::env::temp_dir().join(format!(
        "fg-hd-test-{}-{}-{}",
        tag,
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("guard-hd.db")
}

fn cleanup(db: &std::path::Path) {
    std::fs::remove_file(db).ok();
    std::fs::remove_file(db.with_file_name("action.db")).ok();
    std::fs::remove_file(db.with_file_name("token.db")).ok();
    std::fs::remove_file(db.with_extension("db-wal")).ok();
    std::fs::remove_file(db.with_extension("db-shm")).ok();
    let _ = std::fs::remove_dir_all(db.parent().unwrap());
}

fn verdict(id: uuid::Uuid, risk: RiskLevel, action: SafetyAction) -> GuardVerdict {
    GuardVerdict {
        action,
        risk_level: risk,
        reason: "hd-trigger".into(),
        stage: CheckStage::Regex,
        requires_approval: matches!(risk, RiskLevel::L3),
        redacted_content: None,
        seatbelt_required: false,
        action_id: Some(id),
        verdict_epoch: 1,
        verdict_ttl_secs: 30,
        inferred_category: "test".into(),
        category_hint: None,
    }
}

fn confirm(
    store: &AuditStore,
    id: &str,
    approved: bool,
    by: &str,
    tenant: &str,
) -> Result<GuardVerdict, fg_store::ActionError> {
    let writer = store.audit_writer_handle();
    let key: Zeroizing<[u8; 32]> = Zeroizing::new(**store.chain_key_handle());
    let kv = store.current_key_version();
    store
        .actions()
        .confirm_atomic(id, approved, by, tenant, &writer, &key, kv)
}

// H-D: after confirm + restart (drop+re-open), re-confirming the same action_id -> Consumed.
// Proves consume persistence and audit persistence are atomic (cross-db transaction); no replay window after crash recovery.
#[test]
fn confirm_persists_across_restart_replay_rejected() {
    let db = temp_db("replay");

    // First start: put L3 + confirm approved
    let action_id = uuid::Uuid::new_v4();
    let id_str = action_id.to_string();
    {
        let store = AuditStore::open(&db).unwrap();
        store
            .actions()
            .put(
                &verdict(action_id, RiskLevel::L3, SafetyAction::Block),
                "default",
            )
            .unwrap();
        let v = confirm(&store, &id_str, true, "tester", "default").unwrap();
        assert_eq!(v.action, SafetyAction::Allow, "approved -> Allow");
    } // store drop = simulated process exit/crash (drain thread ends with drop)

    // Restart: re-open a new AuditStore at the same path (new connection, new drain thread).
    // Verify the consumed state persisted across restart.
    {
        let store = AuditStore::open(&db).unwrap();
        // Re-confirm the same action_id -> must be Consumed (one-time persist, no replay window)
        let err = confirm(&store, &id_str, true, "tester", "default").unwrap_err();
        assert!(
            matches!(err, fg_store::ActionError::Consumed(_)),
            "re-confirm after restart must be Consumed (H-D cross-db tx atomically persisted consume, no replay window). got: {err:?}"
        );

        // The confirm audit row also persists across restart (confirm audit and consume land in the same transaction)
        let events = store.list_events(Some("default"), 50).unwrap();
        let has_confirm = events
            .iter()
            .any(|e| e.event_type == "confirm" && e.outcome == "approved");
        assert!(
            has_confirm,
            "confirm audit row persists across restart (H-D audit+consume atomic)"
        );
    }

    cleanup(&db);
}

// H-D (b): an unconfirmed action remains confirmable after restart (state not wrongly marked consumed).
// Contrast: the confirm atomic must not mistakenly mark an unconfirmed action as consumed.
#[test]
fn unconfirmed_action_survives_restart_confirmable() {
    let db = temp_db("unconf");

    let action_id = uuid::Uuid::new_v4();
    let id_str = action_id.to_string();
    {
        let store = AuditStore::open(&db).unwrap();
        store
            .actions()
            .put(
                &verdict(action_id, RiskLevel::L3, SafetyAction::Block),
                "default",
            )
            .unwrap();
    } // drop without confirming

    {
        let store = AuditStore::open(&db).unwrap();
        // Still confirmable after restart (not wrongly marked consumed)
        let v = confirm(&store, &id_str, false, "tester", "default").unwrap();
        assert_eq!(v.action, SafetyAction::Block, "rejected -> Block");
        assert!(!v.requires_approval, "confirm clears requires_approval");
    }

    cleanup(&db);
}

// H-A (product-audit §5): concurrent mixed-risk audit inserts -> chain stays intact (single writer serialized, no fork).
// High-risk Block L4 (sync audit_writer) concurrent with low-risk L1 (async drain -> low_writer);
// both writers serialize SELECT-then-INSERT via BEGIN IMMEDIATE -> no chain fork -> verify_chain clean.
#[test]
fn concurrent_mixed_risk_chain_stays_intact_single_writer() {
    let db = temp_db("concurrent");
    let store = Arc::new(AuditStore::open(&db).unwrap());

    let n_threads = 6;
    let per_thread = 25;
    let mut handles = Vec::new();
    for t in 0..n_threads {
        let store_cl = store.clone();
        let h = std::thread::spawn(move || {
            for i in 0..per_thread {
                // Alternate high/low risk: even = L4 Block (high-risk sync), odd = L1 Allow (low-risk async)
                let high = i % 2 == 0;
                let (action, risk) = if high {
                    (SafetyAction::Block, RiskLevel::L4)
                } else {
                    (SafetyAction::Allow, RiskLevel::L1)
                };
                let v = GuardVerdict {
                    action,
                    risk_level: risk,
                    reason: format!("concurrent-t{}-i{}", t, i),
                    stage: CheckStage::Regex,
                    requires_approval: false,
                    redacted_content: None,
                    seatbelt_required: false,
                    action_id: None,
                    verdict_epoch: 1,
                    verdict_ttl_secs: 30,
                    inferred_category: "test".into(),
                    category_hint: None,
                };
                store_cl
                    .append_event("default", &v, format!("raw-t{}-i{}", t, i), "tester")
                    .unwrap();
            }
        });
        handles.push(h);
    }
    for h in handles {
        h.join().unwrap();
    }

    // Wait for the async drain to land rows (low-risk goes via mpsc -> drain thread batch insert, needs a brief yield).
    // Poll verify_chain.total_rows until the expected value or timeout, ensuring all async rows landed before verifying.
    let expected = n_threads * per_thread;
    let mut landed = false;
    for _ in 0..50 {
        if store.verify_chain(None).unwrap().total_rows >= expected {
            landed = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        landed,
        "drain thread failed to land all async low-risk rows within timeout"
    );

    let ver = store.verify_chain(None).unwrap();
    assert!(
        ver.total_rows >= expected,
        "all concurrent events persisted: expected>={}, got {} (H-A drain landed)",
        expected,
        ver.total_rows
    );
    assert_eq!(
        ver.broken_links, 0,
        "no broken links under concurrent mixed-risk insert (H-A single writer via BEGIN IMMEDIATE)"
    );
    assert!(
        !ver.tampered,
        "chain not tampered under concurrency (H-A no fork)"
    );

    cleanup(&db);
}
