// P0-4 (audit §1.3/§6): rotation + retention + archive + 增量 verify。
// 注入旧行 (超 30d) → enforce_retention 归档到 NDJSON + 删行 + VACUUM;
// 归档后剩余行链仍连续 (增量 verify 透过 checkpoint 锚定剩余首行, 不撞归档边界)。
// test-helpers feature 暴露 insert_event_at_ts (注入带指定 ts 合法链行)。
//
// 需要 FUSION_GUARD_TOKEN_KEY (AuditStore::open → TokenStore 加载密钥)。
// 归档目录隔离: FUSION_GUARD_ARCHIVE_DIR 指向临时目录, 避免污染 ~/.fusion-guard。

use std::path::PathBuf;

use fg_store::AuditStore;

const TEST_KEY_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn ensure_env_key() {
    if std::env::var("FUSION_GUARD_TOKEN_KEY").is_err() {
        std::env::set_var("FUSION_GUARD_TOKEN_KEY", TEST_KEY_HEX);
    }
}

// 临时数据目录: db + 独立归档目录 (per-store 解析自 db_path 同级, 隔离, 测试后清理)。
// 不设全局 FUSION_GUARD_ARCHIVE_DIR (并发测试 store 抢同一 env 会串扰);
// resolve_archive_dir(db_path) → db 同级 audit-archive/, 每 store 独立。
fn temp_env() -> (PathBuf, PathBuf, PathBuf) {
    ensure_env_key();
    let dir = std::env::temp_dir().join(format!(
        "fg-rot-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("guard-rot.db");
    let archive = dir.join("audit-archive");
    std::fs::create_dir_all(&archive).unwrap();
    std::env::set_var("FUSION_GUARD_DATA_DIR", &dir);
    (db, dir, archive)
}

fn cleanup(dir: &std::path::Path, archive: &std::path::Path) {
    std::fs::remove_dir_all(dir).ok();
    let _ = archive;
}

// 归档触发: 注入 5 旧行 (40d 前) + 2 新行 (now) → enforce_retention。
// 旧行归档到 NDJSON, 主库剩 2 新行; 增量 verify 干净 (不误报归档边界)。
#[tokio::test]
async fn rotation_archives_old_rows_and_keeps_chain() {
    let (db, dir, archive) = temp_env();
    let store = AuditStore::open(&db).unwrap();

    let old_ts = chrono::Utc::now() - chrono::Duration::days(40);
    for i in 0..5 {
        store
            .insert_event_at_ts("alpha", old_ts, &format!("rm -rf /old-{}", i))
            .unwrap();
    }
    let now_ts = chrono::Utc::now();
    for i in 0..2 {
        store
            .insert_event_at_ts("alpha", now_ts, &format!("echo hi-{}", i))
            .unwrap();
    }

    // 触发前: 7 行在主库。
    let before = store.list_events(Some("alpha"), 100).unwrap();
    assert_eq!(before.len(), 7, "7 rows before rotation");

    let report = store.enforce_retention().unwrap();
    assert_eq!(report.archived_rows, 5, "5 old rows archived");
    assert!(report.archive_path.is_some(), "archive path returned");
    let archive_path = PathBuf::from(report.archive_path.as_ref().unwrap());
    assert!(
        archive_path.exists(),
        "archive NDJSON file created at {}",
        archive_path.display()
    );
    assert!(
        archive_path.to_string_lossy().ends_with(".ndjson"),
        "archive file is .ndjson"
    );

    // 归档文件含 5 行 JSON (每行一事件, 含 prev_hash/event_hash)。
    let ndjson = std::fs::read_to_string(&archive_path).unwrap();
    let line_count = ndjson.lines().filter(|l| !l.is_empty()).count();
    assert_eq!(line_count, 5, "archive NDJSON has 5 event lines");

    // 主库剩 2 新行 (旧行已归档删)。
    let after = store.list_events(Some("alpha"), 100).unwrap();
    assert_eq!(after.len(), 2, "2 rows remain after rotation");

    // 归档后增量 verify 干净 (checkpoint 锚定剩余首行, 不撞归档边界悬空 prev_hash)。
    let v = store.verify_chain(None).unwrap();
    assert!(
        !v.tampered,
        "incremental verify must be clean after archive (P0-4 boundary checkpoint)"
    );
    assert_eq!(v.broken_links, 0, "no broken links post-archive");
    assert_eq!(v.total_rows, 2, "total_rows reflects remaining scope rows");

    // 再次 verify (纯增量, 无新增段) 仍干净 + 不重扫。
    let v2 = store.verify_chain(None).unwrap();
    assert!(!v2.tampered, "second incremental verify clean");

    cleanup(&dir, &archive);
}

// 归档后空库: 全部行超龄归档 → 主库空。下次插入须续链到归档段末 (非 genesis)。
// insert_audit_event 回退读 checkpoint 的 last_archived_hash 作 prev_hash。
#[tokio::test]
async fn rotation_to_empty_then_append_continues_chain() {
    let (db, dir, archive) = temp_env();
    let store = AuditStore::open(&db).unwrap();

    let old_ts = chrono::Utc::now() - chrono::Duration::days(40);
    for i in 0..3 {
        store
            .insert_event_at_ts("beta", old_ts, &format!("rm -rf /b-{}", i))
            .unwrap();
    }

    let report = store.enforce_retention().unwrap();
    assert_eq!(report.archived_rows, 3, "all 3 old rows archived");

    let after = store.list_events(Some("beta"), 100).unwrap();
    assert_eq!(after.len(), 0, "main DB empty after full archive");

    // 空库 verify (checkpoint 锚定归档段末) 干净。
    let v = store.verify_chain(None).unwrap();
    assert!(!v.tampered, "empty-DB verify clean post-archive");
    assert_eq!(v.total_rows, 0);

    // 新插入续链 (prev_hash = 归档段末 hash, 非 genesis)。读回行验证 prev_hash (insert_event_at_ts
    // 返回的 ev.prev_hash 未回填, 真值在落盘行)。
    let now_ts = chrono::Utc::now();
    store
        .insert_event_at_ts("beta", now_ts, "echo new")
        .unwrap();
    let new_rows = store.list_events(Some("beta"), 10).unwrap();
    assert_eq!(new_rows.len(), 1, "1 row after post-archive insert");
    let persisted = &new_rows[0];
    assert!(
        !persisted.prev_hash.is_empty(),
        "post-archive insert has prev_hash (chain continued from archive tail)"
    );
    assert_ne!(
        persisted.prev_hash, "0000000000000000000000000000000000000000000000000000000000000000",
        "post-archive insert prev_hash must NOT be genesis (continues archive tail)"
    );

    // 增量 verify 干净 (新行续链正确)。
    let v2 = store.verify_chain(None).unwrap();
    assert!(!v2.tampered, "verify clean after post-archive append");
    assert_eq!(v2.total_rows, 1);
    assert_eq!(v2.verified_links, 1);

    cleanup(&dir, &archive);
}

// retention: 归档目录内超 180d 的 .ndjson 文件被删除 (冷存到期)。
// retention 按文件名时间戳 (audit-YYYYMMDDTHHMMSS.ndjson) 判龄, 非 mtime。
// 直接写一个超期文件名 (200d 前) 的归档文件 → enforce_retention → 文件删除。
#[tokio::test]
async fn retention_prunes_expired_archive_files() {
    let (db, dir, archive) = temp_env();
    let store = AuditStore::open(&db).unwrap();

    // 直接在归档目录写一个文件名时间戳超 180d 的 .ndjson (模拟历史归档冷存到期)。
    let expired_ts = chrono::Utc::now() - chrono::Duration::days(200);
    let expired_name = format!("audit-{}.ndjson", expired_ts.format("%Y%m%dT%H%M%S"));
    let expired_path = archive.join(&expired_name);
    std::fs::write(&expired_path, "{}\n").unwrap();
    assert!(expired_path.exists());

    // 同时写一个近期归档文件 (30d 前), 不应被删。
    let recent_ts = chrono::Utc::now() - chrono::Duration::days(30);
    let recent_name = format!("audit-{}.ndjson", recent_ts.format("%Y%m%dT%H%M%S"));
    let recent_path = archive.join(&recent_name);
    std::fs::write(&recent_path, "{}\n").unwrap();
    assert!(recent_path.exists());

    let report = store.enforce_retention().unwrap();
    assert_eq!(
        report.pruned_archives, 1,
        "1 expired archive file pruned (180d retention), recent kept"
    );
    assert!(
        !expired_path.exists(),
        "expired archive file deleted after retention"
    );
    assert!(
        recent_path.exists(),
        "recent archive file kept (within 180d)"
    );

    cleanup(&dir, &archive);
}
