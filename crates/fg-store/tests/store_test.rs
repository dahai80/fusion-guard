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
        "fg-store-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("guard-test.db")
}

#[tokio::test]
async fn high_risk_sync_persist() {
    let path = temp_db();
    let store = AuditStore::open(&path).unwrap();
    let v = verdict(SafetyAction::Block, RiskLevel::L4, "rm-rf");
    store
        .append_event("alpha", &v, "rm -rf /x".into(), "tester")
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let recs = store.list_events(Some("alpha"), 10).unwrap();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].outcome, "blocked");
    assert_eq!(recs[0].tenant_id, "alpha");
    assert_eq!(recs[0].requester, "tester");
    std::fs::remove_file(&path).ok();
}

#[tokio::test]
async fn low_risk_async_batch() {
    let path = temp_db();
    let store = AuditStore::open(&path).unwrap();
    let v = verdict(SafetyAction::Allow, RiskLevel::L1, "clean");
    for i in 0..5 {
        store
            .append_event("beta", &v, format!("ls {}", i), "tester")
            .unwrap();
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let recs = store.list_events(Some("beta"), 10).unwrap();
    assert_eq!(
        recs.len(),
        5,
        "all low-risk events persisted via async batch"
    );
    std::fs::remove_file(&path).ok();
}

#[tokio::test]
async fn tenant_isolation() {
    let path = temp_db();
    let store = AuditStore::open(&path).unwrap();
    let block = verdict(SafetyAction::Block, RiskLevel::L4, "rm-rf");
    let allow = verdict(SafetyAction::Allow, RiskLevel::L1, "clean");
    store
        .append_event("t1", &block, "rm -rf".into(), "r")
        .unwrap();
    store.append_event("t2", &allow, "ls".into(), "r").unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let t1 = store.list_events(Some("t1"), 10).unwrap();
    let t2 = store.list_events(Some("t2"), 10).unwrap();
    let all = store.list_events(None, 10).unwrap();
    assert_eq!(t1.len(), 1);
    assert_eq!(t2.len(), 1);
    assert_eq!(all.len(), 2);
    std::fs::remove_file(&path).ok();
}

// P0-3 (audit §1.2): 高风险 audit_writer synchronous=FULL (fsync on commit, 断电不丢 H7 行);
// 低风险 low_writer synchronous=NORMAL (性能换耐久分级, L1/L2 异步批量可丢)。
#[test]
fn p0_3_tiered_synchronous_pragma() {
    let path = temp_db();
    let store = AuditStore::open(&path).unwrap();
    // SQLite PRAGMA synchronous: 2=FULL, 1=NORMAL (整数回读)。
    let high = store.writer_sync_pragma(true);
    let low = store.writer_sync_pragma(false);
    assert_eq!(
        high, 2,
        "high-risk audit_writer must be FULL (fsync on commit); got {high}"
    );
    assert_eq!(low, 1, "low-risk low_writer must be NORMAL; got {low}");
    std::fs::remove_file(&path).ok();
}
