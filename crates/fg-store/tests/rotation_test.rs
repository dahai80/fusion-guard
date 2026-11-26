// P0-4 (audit §1.3/§6): rotation + retention + archive + incremental verify.
// Inject old rows (>30d) -> enforce_retention archives to NDJSON + deletes rows + VACUUM;
// after archiving, the remaining rows' chain stays continuous (incremental verify anchors the first remaining row
// via checkpoint, avoiding the archive boundary).
// test-helpers feature exposes insert_event_at_ts (inject a valid chain row with a specified ts).
//
// Requires FUSION_GUARD_TOKEN_KEY (AuditStore::open -> TokenStore loads the key).
// Archive dir isolation: FUSION_GUARD_ARCHIVE_DIR points at a temp dir, avoiding pollution of ~/.fusion-guard.

use std::path::PathBuf;

use fg_store::AuditStore;

const TEST_KEY_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn ensure_env_key() {
    if std::env::var("FUSION_GUARD_TOKEN_KEY").is_err() {
        std::env::set_var("FUSION_GUARD_TOKEN_KEY", TEST_KEY_HEX);
    }
}

// Temp data dir: db + a dedicated archive dir (resolved per-store next to db_path, isolated, cleaned after tests).
// The global FUSION_GUARD_ARCHIVE_DIR is not set (concurrent test stores grabbing the same env would crosstalk);
// resolve_archive_dir(db_path) -> audit-archive/ next to the db, independent per store.
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

// Archive trigger: inject 5 old rows (40d ago) + 2 fresh rows (now) -> enforce_retention.
// Old rows archive to NDJSON, 2 fresh rows remain in the main DB; incremental verify clean (no false archive-boundary report).
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

    // Before trigger: 7 rows in the main DB.
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

    // Archive file holds 5 JSON lines (one event per line, with prev_hash/event_hash).
    let ndjson = std::fs::read_to_string(&archive_path).unwrap();
    let line_count = ndjson.lines().filter(|l| !l.is_empty()).count();
    assert_eq!(line_count, 5, "archive NDJSON has 5 event lines");

    // 2 fresh rows remain in the main DB (old rows archived and deleted).
    let after = store.list_events(Some("alpha"), 100).unwrap();
    assert_eq!(after.len(), 2, "2 rows remain after rotation");

    // After archiving, incremental verify is clean (checkpoint anchors the first remaining row; no dangling prev_hash at the archive boundary).
    let v = store.verify_chain(None).unwrap();
    assert!(
        !v.tampered,
        "incremental verify must be clean after archive (P0-4 boundary checkpoint)"
    );
    assert_eq!(v.broken_links, 0, "no broken links post-archive");
    assert_eq!(v.total_rows, 2, "total_rows reflects remaining scope rows");

    // Verify again (pure incremental, no new segments): still clean + no rescan.
    let v2 = store.verify_chain(None).unwrap();
    assert!(!v2.tampered, "second incremental verify clean");

    cleanup(&dir, &archive);
}

// Empty DB after archiving: all rows aged out -> main DB empty. The next insert must continue the chain from the
// archive tail (not genesis).
// insert_audit_event falls back to reading the checkpoint's last_archived_hash as prev_hash.
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

    // Empty-DB verify (checkpoint anchored at the archive tail) clean.
    let v = store.verify_chain(None).unwrap();
    assert!(!v.tampered, "empty-DB verify clean post-archive");
    assert_eq!(v.total_rows, 0);

    // The new insert continues the chain (prev_hash = archive tail hash, not genesis). Verify prev_hash via the
    // read-back row (the ev.prev_hash returned by insert_event_at_ts is not backfilled; the true value lives in the persisted row).
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

    // Incremental verify clean (new row continues the chain correctly).
    let v2 = store.verify_chain(None).unwrap();
    assert!(!v2.tampered, "verify clean after post-archive append");
    assert_eq!(v2.total_rows, 1);
    assert_eq!(v2.verified_links, 1);

    cleanup(&dir, &archive);
}

// retention: .ndjson files older than 180d inside the archive dir are deleted (cold storage expiry).
// retention judges age by the filename timestamp (audit-YYYYMMDDTHHMMSS.ndjson), not mtime.
// Write an archive file whose filename is expired (200d ago) directly -> enforce_retention -> file deleted.
#[tokio::test]
async fn retention_prunes_expired_archive_files() {
    let (db, dir, archive) = temp_env();
    let store = AuditStore::open(&db).unwrap();

    // Write an .ndjson with a filename timestamp older than 180d directly into the archive dir (simulating historical cold storage expiry).
    let expired_ts = chrono::Utc::now() - chrono::Duration::days(200);
    let expired_name = format!("audit-{}.ndjson", expired_ts.format("%Y%m%dT%H%M%S"));
    let expired_path = archive.join(&expired_name);
    std::fs::write(&expired_path, "{}\n").unwrap();
    assert!(expired_path.exists());

    // Also write a recent archive file (30d ago); it must not be deleted.
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
