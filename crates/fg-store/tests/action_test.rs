use fg_core::{CheckStage, GuardVerdict, RiskLevel, SafetyAction};
use fg_store::{ActionError, AuditStore};
use rusqlite::Connection;
use zeroize::Zeroizing;

const TEST_KEY_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn ensure_env_key() {
    if std::env::var("FUSION_GUARD_TOKEN_KEY").is_err() {
        std::env::set_var("FUSION_GUARD_TOKEN_KEY", TEST_KEY_HEX);
    }
}

fn temp_db() -> std::path::PathBuf {
    ensure_env_key();
    let dir = std::env::temp_dir().join(format!(
        "fg-action-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("guard-action.db")
}

fn open_store() -> (AuditStore, std::path::PathBuf) {
    let path = temp_db();
    let store = AuditStore::open(&path).unwrap();
    (store, path)
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
        category_hint: None,
    }
}

fn confirm(
    store: &AuditStore,
    id: &str,
    approved: bool,
    by: &str,
    tenant: &str,
) -> Result<GuardVerdict, ActionError> {
    let writer = store.audit_writer_handle();
    let key: Zeroizing<[u8; 32]> = Zeroizing::new(**store.chain_key_handle());
    let kv = store.current_key_version();
    store
        .actions()
        .confirm_atomic(id, approved, by, tenant, &writer, &key, kv)
}

// C9 tamper helper: open a separate connection and rewrite the risk_level field inside verdict_json (column untouched).
// After C11 risk_level serializes lowercase ("l4"/"l3"), so we replace the lowercase strings.
// P1-7: pending_actions lives in action.db (sibling of the audit.db path). Tampering must open action.db, not audit.db.
fn tamper_verdict_json(path: &std::path::Path, action_id: &str, new_risk_json: &str) {
    let action_db = path.with_file_name("action.db");
    let conn = Connection::open(&action_db).unwrap();
    let row: String = conn
        .query_row(
            "SELECT verdict_json FROM pending_actions WHERE action_id = ?1",
            rusqlite::params![action_id],
            |r| r.get(0),
        )
        .unwrap();
    let tampered = row
        .replace("\"l4\"", new_risk_json)
        .replace("\"l3\"", new_risk_json);
    conn.execute(
        "UPDATE pending_actions SET verdict_json = ?1 WHERE action_id = ?2",
        rusqlite::params![tampered, action_id],
    )
    .unwrap();
}

#[test]
fn put_confirm_approved_consumes() {
    let (store, _p) = open_store();
    let id = uuid::Uuid::new_v4();
    store
        .actions()
        .put(&verdict(id, RiskLevel::L3, SafetyAction::Block), "default")
        .unwrap();
    let v = confirm(&store, &id.to_string(), true, "tester", "default").unwrap();
    assert_eq!(v.action, SafetyAction::Allow);
    let err = confirm(&store, &id.to_string(), true, "tester", "default").unwrap_err();
    assert!(matches!(err, ActionError::Consumed(_)));
}

#[test]
fn confirm_rejected_blocks() {
    let (store, _p) = open_store();
    let id = uuid::Uuid::new_v4();
    store
        .actions()
        .put(&verdict(id, RiskLevel::L3, SafetyAction::Block), "default")
        .unwrap();
    let v = confirm(&store, &id.to_string(), false, "tester", "default").unwrap();
    assert_eq!(v.action, SafetyAction::Block);
    let err = confirm(&store, &id.to_string(), true, "tester", "default").unwrap_err();
    assert!(matches!(err, ActionError::Consumed(_)));
}

#[test]
fn l4_absolute_rejects_confirm() {
    let (store, _p) = open_store();
    let id = uuid::Uuid::new_v4();
    store
        .actions()
        .put(&verdict(id, RiskLevel::L4, SafetyAction::Block), "default")
        .unwrap();
    let err = confirm(&store, &id.to_string(), true, "tester", "default").unwrap_err();
    assert!(matches!(err, ActionError::AbsoluteBlock(_)));
}

#[test]
fn missing_action_errors() {
    let (store, _p) = open_store();
    let err = confirm(
        &store,
        "00000000-0000-0000-0000-000000000000",
        true,
        "x",
        "default",
    )
    .unwrap_err();
    assert!(matches!(err, ActionError::NotFound(_)));
}

#[test]
fn no_action_id_skips() {
    let (store, _p) = open_store();
    let mut v = verdict(uuid::Uuid::new_v4(), RiskLevel::L1, SafetyAction::Allow);
    v.action_id = None;
    store.actions().put(&v, "default").unwrap();
}

#[test]
fn evict_expired_removes_old() {
    let (store, _p) = open_store();
    let id = uuid::Uuid::new_v4();
    store
        .actions()
        .put(&verdict(id, RiskLevel::L3, SafetyAction::Block), "default")
        .unwrap();
    let n = store.actions().evict_expired().unwrap();
    assert_eq!(n, 0, "fresh action not evicted");
}

// C9: H8 checks the risk_level column, not the JSON blob.
// (1) L4 put -> tamper verdict_json risk_level to "L3", column stays L4 -> H8 column check blocks with AbsoluteBlock.
// (2) L3 put -> tamper verdict_json risk_level to "L4", column stays L3 -> cross-check yields RiskTampered.
#[test]
fn c9_h8_checks_risk_column_not_json() {
    let (store, path) = open_store();
    let id = uuid::Uuid::new_v4();
    let mut v = verdict(id, RiskLevel::L4, SafetyAction::Block);
    v.requires_approval = false;
    store.actions().put(&v, "default").unwrap();

    // Tamper verdict_json: "l4" -> "l3" (risk_level column untouched = L4). C11 lowercase.
    tamper_verdict_json(&path, &id.to_string(), "\"l3\"");
    let err = confirm(&store, &id.to_string(), true, "tester", "default").unwrap_err();
    assert!(
        matches!(err, ActionError::AbsoluteBlock(_)),
        "H8 checks the risk_level column (L4) and blocks; tampered JSON l3 must not bypass it (C9)"
    );

    // L3 put -> tamper JSON to l4, column stays L3 -> cross-check yields RiskTampered.
    let id2 = uuid::Uuid::new_v4();
    let v2 = verdict(id2, RiskLevel::L3, SafetyAction::Block);
    store.actions().put(&v2, "default").unwrap();
    tamper_verdict_json(&path, &id2.to_string(), "\"l4\"");
    let err = confirm(&store, &id2.to_string(), true, "tester", "default").unwrap_err();
    assert!(
        matches!(err, ActionError::RiskTampered { .. }),
        "column L3 vs tampered JSON L4 mismatch must reject with RiskTampered (C9 cross-check)"
    );
}

// C20: cross-tenant confirm is denied. action_id leaks to tenant-B; B confirms -> CrossTenant.
#[test]
fn c20_cross_tenant_confirm_denied() {
    let (store, _p) = open_store();
    let id = uuid::Uuid::new_v4();
    store
        .actions()
        .put(&verdict(id, RiskLevel::L3, SafetyAction::Block), "tenant-a")
        .unwrap();
    let v = confirm(&store, &id.to_string(), true, "a-user", "tenant-a").unwrap();
    assert_eq!(v.action, SafetyAction::Allow);

    let id2 = uuid::Uuid::new_v4();
    store
        .actions()
        .put(
            &verdict(id2, RiskLevel::L3, SafetyAction::Block),
            "tenant-a",
        )
        .unwrap();
    let err = confirm(&store, &id2.to_string(), true, "b-user", "tenant-b").unwrap_err();
    assert!(
        matches!(err, ActionError::CrossTenant { .. }),
        "cross-tenant confirm must be denied (C20)"
    );
}

// L2+A8: confirm audit and consume are atomic. After a successful confirm, audit_events has a confirm row.
#[test]
fn l2_confirm_audit_atomic_persisted() {
    let (store, _p) = open_store();
    let id = uuid::Uuid::new_v4();
    store
        .actions()
        .put(&verdict(id, RiskLevel::L3, SafetyAction::Block), "default")
        .unwrap();
    let v = confirm(&store, &id.to_string(), true, "tester", "default").unwrap();
    assert_eq!(v.action, SafetyAction::Allow);

    let events = store.list_events(Some("default"), 50).unwrap();
    let has_confirm = events
        .iter()
        .any(|e| e.event_type == "confirm" && e.outcome == "approved");
    assert!(
        has_confirm,
        "confirm audit must be atomically persisted (L2+A8)"
    );
}
