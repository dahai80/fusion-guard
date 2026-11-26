// P1-7 (audit §3.5): write-path physical DB split tests.
// Verifies audit.db / token.db / action.db are physically split, each with its own WAL, and that the confirm
// cross-db transaction is atomic. Root cause: 5+ connections opening one guard.db shared a single WAL write lock,
// so the H7 audit_writer hot path (synchronous=FULL, per-row fsync) was blocked by token/action put lock contention.
// After the split each file has its own WAL; writes no longer mutually exclude.

use std::os::unix::fs::PermissionsExt;

use fg_core::{CheckStage, GuardVerdict, RiskLevel, SafetyAction};
use fg_store::AuditStore;
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
        "fg-p17-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("guard-p17.db")
}

fn mode(p: &std::path::Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

fn verdict(id: uuid::Uuid, risk: RiskLevel, action: SafetyAction) -> GuardVerdict {
    GuardVerdict {
        action,
        risk_level: risk,
        reason: "p17-trigger".into(),
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

// P1-7 (a): after open, token.db / action.db sibling files exist physically and all three DBs are 0o600.
#[test]
fn split_creates_sibling_db_files_hardened() {
    let db = temp_db();
    let _store = AuditStore::open(&db).unwrap();
    let token_db = db.with_file_name("token.db");
    let action_db = db.with_file_name("action.db");
    assert!(
        db.exists(),
        "audit.db (db_path) must exist after open (P1-7)"
    );
    assert!(
        token_db.exists(),
        "token.db sibling must exist after open (P1-7)"
    );
    assert!(
        action_db.exists(),
        "action.db sibling must exist after open (P1-7)"
    );
    assert_eq!(mode(&db), 0o600, "audit.db 0o600 (P1-7, C21)");
    assert_eq!(mode(&token_db), 0o600, "token.db 0o600 (P1-7, C21)");
    assert_eq!(mode(&action_db), 0o600, "action.db 0o600 (P1-7, C21)");
    std::fs::remove_file(&db).ok();
    std::fs::remove_file(&token_db).ok();
    std::fs::remove_file(&action_db).ok();
    let _ = std::fs::remove_dir_all(db.parent().unwrap());
}

// P1-7 (b): pending_actions lives in action.db (sibling); audit.db (db_path) main has no such table.
// In the old single-file DB pending_actions lived in guard.db main; after the split it migrates to action.db
// and audit.db main keeps no residual copy.
#[test]
fn pending_actions_lives_in_action_db_not_audit_db() {
    let db = temp_db();
    let store = AuditStore::open(&db).unwrap();
    let id = uuid::Uuid::new_v4();
    store
        .actions()
        .put(&verdict(id, RiskLevel::L3, SafetyAction::Block), "default")
        .unwrap();

    // audit.db (db_path) main: pending_actions must not exist (migrated to action.db).
    let audit_conn = Connection::open(&db).unwrap();
    let audit_has: bool = audit_conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='pending_actions')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        !audit_has,
        "pending_actions must NOT exist in audit.db main after P1-7 split (migrated to action.db)"
    );

    // action.db sibling: pending_actions exists and the just-put row is queryable.
    let action_db = db.with_file_name("action.db");
    let action_conn = Connection::open(&action_db).unwrap();
    let action_has: bool = action_conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='pending_actions')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        action_has,
        "pending_actions must exist in action.db sibling after P1-7 split"
    );
    let count: i64 = action_conn
        .query_row(
            "SELECT COUNT(*) FROM pending_actions WHERE action_id = ?1",
            rusqlite::params![id.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        count, 1,
        "put row must land in action.db pending_actions (P1-7)"
    );

    std::fs::remove_file(&db).ok();
    std::fs::remove_file(&action_db).ok();
    std::fs::remove_file(db.with_file_name("token.db")).ok();
    let _ = std::fs::remove_dir_all(db.parent().unwrap());
}

// P1-7 (c)+(d): confirm cross-db transaction atomicity — audit_events written to audit.db + consumed marked in
// action.db, both in one transaction, succeeding or failing together. An approved confirm -> verdict Allow +
// action.db consumed=1 + a confirm row in audit.db.
#[test]
fn confirm_atomic_across_split_dbs() {
    let db = temp_db();
    let store = AuditStore::open(&db).unwrap();
    let id = uuid::Uuid::new_v4();
    store
        .actions()
        .put(&verdict(id, RiskLevel::L3, SafetyAction::Block), "default")
        .unwrap();

    // confirm: audit_writer ATTACHes action.db; the cross-db transaction makes the audit_events INSERT + consumed
    // UPDATE atomic.
    let v = confirm(&store, &id.to_string(), true, "tester", "default").unwrap();
    assert_eq!(v.action, SafetyAction::Allow, "approved -> Allow");
    assert!(
        !v.requires_approval,
        "approved -> requires_approval cleared"
    );

    // action.db: consumed=1 (the UPDATE side of the cross-db transaction).
    let action_db = db.with_file_name("action.db");
    let action_conn = Connection::open(&action_db).unwrap();
    let consumed: i64 = action_conn
        .query_row(
            "SELECT consumed FROM pending_actions WHERE action_id = ?1",
            rusqlite::params![id.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        consumed, 1,
        "consumed=1 in action.db after confirm (cross-db UPDATE)"
    );

    // audit.db: the confirm audit row is persisted (the INSERT side of the cross-db transaction).
    let events = store.list_events(Some("default"), 50).unwrap();
    let has_confirm = events
        .iter()
        .any(|e| e.event_type == "confirm" && e.outcome == "approved");
    assert!(
        has_confirm,
        "confirm audit row in audit.db (cross-db INSERT, L2+A8)"
    );

    // Re-confirm -> Consumed (one-time; consumed already persisted by the cross-db transaction).
    let err = confirm(&store, &id.to_string(), true, "tester", "default").unwrap_err();
    assert!(
        matches!(err, fg_store::ActionError::Consumed(_)),
        "replay rejected Consumed after cross-db confirm (H4 one-time persists)"
    );

    std::fs::remove_file(&db).ok();
    std::fs::remove_file(&action_db).ok();
    std::fs::remove_file(db.with_file_name("token.db")).ok();
    let _ = std::fs::remove_dir_all(db.parent().unwrap());
}

// P1-7: migration of legacy single-file guard.db residual tables (pending_actions/tokens/key_versions).
// Simulate the legacy DB: create the residual tables+rows at db_path before open; after open,
// drop_legacy_split_tables should DROP the residuals.
// All three tables are transient (pending TTL 30s / token TTL 300s); rows are not copied, only the residual tables DROPped.
#[test]
fn legacy_single_file_residual_tables_dropped_on_open() {
    let db = temp_db();

    // Build the legacy DB: create residual tables (with rows, simulating pre-upgrade data) in single-file guard.db main.
    {
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE pending_actions (action_id TEXT PRIMARY KEY, junk INTEGER);
             CREATE TABLE tokens (tok_id TEXT PRIMARY KEY, junk INTEGER);
             CREATE TABLE key_versions (kv INTEGER PRIMARY KEY, junk INTEGER);
             INSERT INTO pending_actions VALUES ('legacy-1', 1);
             INSERT INTO tokens VALUES ('legacy-tok', 1);
             INSERT INTO key_versions VALUES (1, 1);",
        )
        .unwrap();
    }

    // open triggers drop_legacy_split_tables: residual tables must be DROPped from audit.db (db_path) main.
    let _store = AuditStore::open(&db).unwrap();

    let audit_conn = Connection::open(&db).unwrap();
    for tbl in ["pending_actions", "tokens", "key_versions"] {
        let exists: bool = audit_conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                rusqlite::params![tbl],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            !exists,
            "legacy residual table {} must be dropped from audit.db after open (P1-7 migration)",
            tbl
        );
    }

    std::fs::remove_file(&db).ok();
    std::fs::remove_file(db.with_file_name("action.db")).ok();
    std::fs::remove_file(db.with_file_name("token.db")).ok();
    let _ = std::fs::remove_dir_all(db.parent().unwrap());
}
