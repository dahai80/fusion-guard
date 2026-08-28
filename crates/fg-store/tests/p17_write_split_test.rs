// P1-7 (audit §3.5): 写路径物理分库测试。
// 验证 audit.db / token.db / action.db 物理分文件各持独立 WAL, confirm 跨库事务原子。
// 缺陷根因: 5+ 连接同开 guard.db 共享单 WAL 写锁, H7 audit_writer (synchronous=FULL,
// per-row fsync) 热路径被 token/action put 抢锁阻塞。分库后各文件独立 WAL, 写不互斥。

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

// P1-7 (a): open 后 token.db / action.db sibling 物理文件存在, 三库均 0o600。
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

// P1-7 (b): pending_actions 在 action.db (sibling), audit.db (db_path) main 无此表。
// 旧单文件库 pending_actions 在 guard.db main; 分库后迁 action.db, audit.db main 不残留。
#[test]
fn pending_actions_lives_in_action_db_not_audit_db() {
    let db = temp_db();
    let store = AuditStore::open(&db).unwrap();
    let id = uuid::Uuid::new_v4();
    store
        .actions()
        .put(&verdict(id, RiskLevel::L3, SafetyAction::Block), "default")
        .unwrap();

    // audit.db (db_path) main: pending_actions 应不存在 (已迁 action.db)。
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

    // action.db sibling: pending_actions 存在, 且能查到刚 put 的行。
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

// P1-7 (c)+(d): confirm 跨库事务原子 —— audit_events 写 audit.db + consumed 标 action.db,
// 两者同事务, 同成功或同失败。confirm approved → verdict Allow + action.db consumed=1 + audit.db 有 confirm 行。
#[test]
fn confirm_atomic_across_split_dbs() {
    let db = temp_db();
    let store = AuditStore::open(&db).unwrap();
    let id = uuid::Uuid::new_v4();
    store
        .actions()
        .put(&verdict(id, RiskLevel::L3, SafetyAction::Block), "default")
        .unwrap();

    // confirm: audit_writer ATTACH action.db, 跨库事务 audit_events INSERT + consumed UPDATE 原子。
    let v = confirm(&store, &id.to_string(), true, "tester", "default").unwrap();
    assert_eq!(v.action, SafetyAction::Allow, "approved → Allow");
    assert!(!v.requires_approval, "approved → requires_approval cleared");

    // action.db: consumed=1 (跨库事务的 UPDATE 侧)。
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

    // audit.db: confirm 审计行落库 (跨库事务的 INSERT 侧)。
    let events = store.list_events(Some("default"), 50).unwrap();
    let has_confirm = events
        .iter()
        .any(|e| e.event_type == "confirm" && e.outcome == "approved");
    assert!(
        has_confirm,
        "confirm audit row in audit.db (cross-db INSERT, L2+A8)"
    );

    // 重 confirm → Consumed (一次性, 跨库事务后 consumed 已持久)。
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

// P1-7: 旧单文件 guard.db 残留表 (pending_actions/tokens/key_versions) 迁移。
// 模拟旧库: open 前先在 db_path 建残留表+行, open 后 drop_legacy_split_tables 应 DROP 残留。
// 三表瞬态 (pending TTL 30s / token TTL 300s), 不拷行, 仅 DROP residual。
#[test]
fn legacy_single_file_residual_tables_dropped_on_open() {
    let db = temp_db();

    // 造旧库: 单文件 guard.db main 建残留表 (含行, 模拟升级前数据)。
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

    // open 触发 drop_legacy_split_tables: 残留表应从 audit.db (db_path) main DROP。
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
