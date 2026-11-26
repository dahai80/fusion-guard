// P1-3 (audit §2.5): pending action put fail-closed.
// An L3 verdict (requires_approval) needs the confirm flow; if actions().put() fails the action_id cannot be
// delivered (the caller's confirm finds no row → permanent dead end). A put failure refuses the evaluation
// instead of returning a verdict with an action_id.
// Durability semantics consistent with the H7 audit-write fail-closed (both writes happen in the same evaluate).
//
// Fault injection: drop the pending_actions table → the put's INSERT raises a SQLite error.
// Requires FUSION_GUARD_TOKEN_KEY (AuditStore::open → TokenStore loads the key).
// test-helpers feature (forwarded to fg-store).

use std::path::PathBuf;

use fg_audit_engine::AuditEngine;
use fg_core::{ContentType, GuardError, SafetyAction};
use fg_store::AuditStore;
use std::sync::Arc;

const TEST_KEY_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn ensure_env_key() {
    if std::env::var("FUSION_GUARD_TOKEN_KEY").is_err() {
        std::env::set_var("FUSION_GUARD_TOKEN_KEY", TEST_KEY_HEX);
    }
}

fn temp_env() -> (PathBuf, PathBuf) {
    ensure_env_key();
    let dir = std::env::temp_dir().join(format!(
        "fg-p13-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("guard-p13.db");
    std::env::set_var("FUSION_GUARD_DATA_DIR", &dir);
    (db, dir)
}

fn cleanup(dir: &std::path::Path) {
    std::fs::remove_dir_all(dir).ok();
}

// L3 verdict + put failure → evaluate returns an Engine err, no action_id delivered.
// L3 trigger: shell content with $(...) process substitution → tokenizer Block L3 (requires_approval).
#[tokio::test]
async fn l3_put_failure_refuses_evaluate() {
    let (db, dir) = temp_env();
    let store = Arc::new(AuditStore::open(&db).unwrap());
    let engine = AuditEngine::new(store.clone()).unwrap();

    // baseline: a normal L3 verdict returns a verdict with action_id (put succeeds).
    let ok = engine
        .evaluate("echo $(whoami)", 0, "default", ContentType::Shell, None)
        .unwrap();
    assert!(
        ok.requires_approval || ok.action == SafetyAction::Block,
        "baseline L3/Block hit"
    );
    assert!(ok.action_id.is_some(), "baseline returns action_id");

    // fault injection: drop the pending_actions table → subsequent put INSERT errors.
    {
        let w = store.audit_writer_handle();
        let w = w.lock().unwrap();
        w.execute_batch("DROP TABLE pending_actions").unwrap();
    }

    // put failure → evaluate fail-closed, returns Engine err (not a verdict with action_id).
    let res = engine.evaluate("echo $(id)", 0, "default", ContentType::Shell, None);
    assert!(
        matches!(res, Err(GuardError::Engine(_))),
        "L3 put failure must fail-closed (P1-3), got {:?}",
        res
    );
    if let Err(GuardError::Engine(msg)) = &res {
        assert!(
            msg.contains("pending action persist failed"),
            "error message tags pending action failure: {}",
            msg
        );
    }

    cleanup(&dir);
}

// L4 Block + put failure → also fail-closed (consistent durability semantics, not L3-specific).
// L4 trigger: rm -rf on a sensitive path → tokenizer Block L4.
#[tokio::test]
async fn l4_put_failure_refuses_evaluate() {
    let (db, dir) = temp_env();
    let store = Arc::new(AuditStore::open(&db).unwrap());
    let engine = AuditEngine::new(store.clone()).unwrap();

    let ok = engine
        .evaluate("rm -rf /", 0, "default", ContentType::Shell, None)
        .unwrap();
    assert_eq!(ok.action, SafetyAction::Block, "baseline L4 Block");
    assert!(ok.action_id.is_some());

    {
        let w = store.audit_writer_handle();
        let w = w.lock().unwrap();
        w.execute_batch("DROP TABLE pending_actions").unwrap();
    }

    let res = engine.evaluate("rm -rf /etc", 0, "default", ContentType::Shell, None);
    assert!(
        matches!(res, Err(GuardError::Engine(_))),
        "L4 put failure must fail-closed (P1-3, H7 durable consistency), got {:?}",
        res
    );

    cleanup(&dir);
}
