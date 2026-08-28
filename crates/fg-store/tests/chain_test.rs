use fg_core::{CheckStage, GuardVerdict, RiskLevel, SafetyAction};
use fg_store::AuditStore;

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

fn temp_db() -> std::path::PathBuf {
    ensure_env_key();
    let dir = std::env::temp_dir().join(format!(
        "fg-chain-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("guard-chain.db")
}

#[tokio::test]
async fn empty_store_chain_clean() {
    let path = temp_db();
    let store = AuditStore::open(&path).unwrap();
    let v = store.verify_chain(None).unwrap();
    assert_eq!(v.total_rows, 0);
    assert!(!v.tampered);
    assert_eq!(v.broken_links, 0);
    std::fs::remove_file(&path).ok();
}

#[tokio::test]
async fn chain_links_verify_clean() {
    let path = temp_db();
    let store = AuditStore::open(&path).unwrap();
    for i in 0..5 {
        let v = verdict(SafetyAction::Block, RiskLevel::L4, &format!("cat-{}", i));
        store
            .append_event("alpha", &v, format!("rm -rf /{}", i), "tester")
            .unwrap();
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let recs = store.list_events(Some("alpha"), 100).unwrap();
    assert_eq!(recs.len(), 5);
    for ev in &recs {
        assert!(!ev.event_hash.is_empty(), "event_hash must be populated");
        assert!(!ev.prev_hash.is_empty(), "prev_hash must be populated");
    }

    let v = store.verify_chain(None).unwrap();
    assert_eq!(v.total_rows, 5);
    assert_eq!(v.verified_links, 5);
    assert_eq!(v.broken_links, 0);
    assert!(!v.tampered);
    std::fs::remove_file(&path).ok();
}

#[tokio::test]
async fn tamper_outcome_detected() {
    let path = temp_db();
    let store = AuditStore::open(&path).unwrap();
    let v = verdict(SafetyAction::Block, RiskLevel::L4, "rm-rf");
    store
        .append_event("alpha", &v, "rm -rf /x".into(), "tester")
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let audit_id = store.list_events(Some("alpha"), 10).unwrap()[0]
        .audit_id
        .to_string();
    let writer = store.audit_writer_handle();
    {
        let g = writer.lock().unwrap();
        g.execute(
            "UPDATE audit_events SET outcome = 'allowed' WHERE audit_id = ?1",
            rusqlite::params![audit_id],
        )
        .unwrap();
    }

    let v = store.verify_chain(None).unwrap();
    assert!(v.tampered, "tampered outcome must be detected");
    assert_eq!(v.broken_links, 1);
    assert_eq!(v.first_broken_at, Some(0));
    std::fs::remove_file(&path).ok();
}

#[tokio::test]
async fn mixed_hashed_unhashed_counted() {
    let path = temp_db();
    let store = AuditStore::open(&path).unwrap();
    let v = verdict(SafetyAction::Block, RiskLevel::L4, "rm-rf");
    store
        .append_event("alpha", &v, "rm -rf /x".into(), "tester")
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let writer = store.audit_writer_handle();
    {
        let g = writer.lock().unwrap();
        g.execute(
            "INSERT INTO audit_events
             (audit_id, ts, event_type, tenant_id, requester, action,
              inferred_category, verdict_json, approved_by, seatbelt_required, outcome,
              prev_hash, event_hash)
             VALUES ('legacy-id','2026-01-01T00:00:00Z','evaluate','legacy','u','a',
                     'c','{}',NULL,0,'allowed','','')",
            [],
        )
        .unwrap();
    }

    let v = store.verify_chain(None).unwrap();
    assert_eq!(v.total_rows, 2);
    assert_eq!(
        v.unhashed_rows, 1,
        "legacy empty-hash row counted as unhashed"
    );
    assert_eq!(
        v.broken_links, 1,
        "empty-hash row is a broken link (C7 fix)"
    );
    assert!(
        v.tampered,
        "empty-hash row must flag tamper (C7: no silent escape)"
    );
    std::fs::remove_file(&path).ok();
}
