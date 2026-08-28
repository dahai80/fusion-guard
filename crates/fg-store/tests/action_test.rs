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

// C9 篡改 helper: 另开独立连接改 verdict_json 中 risk_level 字段 (列不动)。
// C11 后 risk_level 序列化 lowercase ("l4"/"l3"), 故替换小写串。
// P1-7: pending_actions 在 action.db (sibling of audit.db path)。篡改须开 action.db 非 audit.db。
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

// C9: H8 查 risk_level 列非 JSON blob。
// (1) L4 put → 篡改 verdict_json risk_level 改 "L3", 列仍 L4 → H8 查列拦截 AbsoluteBlock。
// (2) L3 put → 篡改 verdict_json risk_level 改 "L4", 列仍 L3 → 交叉校验 RiskTampered。
#[test]
fn c9_h8_checks_risk_column_not_json() {
    let (store, path) = open_store();
    let id = uuid::Uuid::new_v4();
    let mut v = verdict(id, RiskLevel::L4, SafetyAction::Block);
    v.requires_approval = false;
    store.actions().put(&v, "default").unwrap();

    // 篡改 verdict_json: "l4" → "l3" (列 risk_level 不动 = L4)。C11 lowercase。
    tamper_verdict_json(&path, &id.to_string(), "\"l3\"");
    let err = confirm(&store, &id.to_string(), true, "tester", "default").unwrap_err();
    assert!(
        matches!(err, ActionError::AbsoluteBlock(_)),
        "H8 查 risk_level 列 (L4) 拦截, 不被篡改的 JSON l3 绕过 (C9)"
    );

    // L3 put → 篡改 JSON 改 l4, 列仍 L3 → 交叉校验 RiskTampered。
    let id2 = uuid::Uuid::new_v4();
    let v2 = verdict(id2, RiskLevel::L3, SafetyAction::Block);
    store.actions().put(&v2, "default").unwrap();
    tamper_verdict_json(&path, &id2.to_string(), "\"l4\"");
    let err = confirm(&store, &id2.to_string(), true, "tester", "default").unwrap_err();
    assert!(
        matches!(err, ActionError::RiskTampered { .. }),
        "列 L3 与篡改 JSON L4 不一致 → RiskTampered 拒 (C9 交叉校验)"
    );
}

// C20: 跨租户 confirm 拒绝。action_id 泄露给 tenant-B, B confirm → CrossTenant。
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
        "跨租户 confirm 必须拒绝 (C20)"
    );
}

// L2+A8: confirm 审计与 consume 原子。confirm 成功后 audit_events 有 confirm 行。
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
    assert!(has_confirm, "confirm 审计必须原子落库 (L2+A8)");
}
