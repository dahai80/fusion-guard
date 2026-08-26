use fg_core::{CheckStage, GuardVerdict, RiskLevel, SafetyAction};
use fg_store::{ActionError, ActionStore};
use rusqlite::Connection;

fn temp_conn() -> Connection {
    let dir = std::env::temp_dir().join(format!(
        "fg-action-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("action-test.db");
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
        .unwrap();
    conn
}

fn verdict(id: uuid::Uuid, risk: RiskLevel, action: SafetyAction) -> GuardVerdict {
    GuardVerdict {
        action,
        risk_level: risk,
        reason: "test".into(),
        stage: CheckStage::Regex,
        requires_approval: matches!(risk, RiskLevel::L3),
        redacted_content: None,
        seatbelt_required: false,
        action_id: Some(id),
        verdict_epoch: 1,
        verdict_ttl_secs: 30,
        inferred_category: "test".into(),
    }
}

#[test]
fn put_confirm_approved_consumes() {
    let store = ActionStore::open(temp_conn()).unwrap();
    let id = uuid::Uuid::new_v4();
    store
        .put(&verdict(id, RiskLevel::L3, SafetyAction::Block))
        .unwrap();
    let v = store.confirm(&id.to_string(), true, "tester").unwrap();
    assert_eq!(v.action, SafetyAction::Allow);
    let err = store.confirm(&id.to_string(), true, "tester").unwrap_err();
    assert!(matches!(err, ActionError::Consumed(_)));
}

#[test]
fn confirm_rejected_blocks() {
    let store = ActionStore::open(temp_conn()).unwrap();
    let id = uuid::Uuid::new_v4();
    store
        .put(&verdict(id, RiskLevel::L3, SafetyAction::Block))
        .unwrap();
    let v = store.confirm(&id.to_string(), false, "tester").unwrap();
    assert_eq!(v.action, SafetyAction::Block);
    let err = store.confirm(&id.to_string(), true, "tester").unwrap_err();
    assert!(matches!(err, ActionError::Consumed(_)));
}

#[test]
fn l4_absolute_rejects_confirm() {
    let store = ActionStore::open(temp_conn()).unwrap();
    let id = uuid::Uuid::new_v4();
    store
        .put(&verdict(id, RiskLevel::L4, SafetyAction::Block))
        .unwrap();
    let err = store.confirm(&id.to_string(), true, "tester").unwrap_err();
    assert!(matches!(err, ActionError::AbsoluteBlock(_)));
}

#[test]
fn missing_action_errors() {
    let store = ActionStore::open(temp_conn()).unwrap();
    let err = store
        .confirm("00000000-0000-0000-0000-000000000000", true, "x")
        .unwrap_err();
    assert!(matches!(err, ActionError::NotFound(_)));
}

#[test]
fn no_action_id_skips() {
    let store = ActionStore::open(temp_conn()).unwrap();
    let mut v = verdict(uuid::Uuid::new_v4(), RiskLevel::L1, SafetyAction::Allow);
    v.action_id = None;
    store.put(&v).unwrap();
}

#[test]
fn evict_expired_removes_old() {
    let store = ActionStore::open(temp_conn()).unwrap();
    let id = uuid::Uuid::new_v4();
    store
        .put(&verdict(id, RiskLevel::L3, SafetyAction::Block))
        .unwrap();
    let n = store.evict_expired().unwrap();
    assert_eq!(n, 0, "fresh action not evicted");
}
