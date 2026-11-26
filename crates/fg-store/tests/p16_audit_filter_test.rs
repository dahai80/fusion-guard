// P1-6 (audit §3.2): audit.list filters + cursor pagination.
// The old handler only supported tenant_id + limit, forcing monitors to brute-force poll the full set. Added
// since/until/event_type/level_min filters + cursor pagination -> since=<last row ts> pulls only the increment.
// This test verifies the store-level list_filtered_page directly (pure SQL filtering, no socket dependency,
// deterministic coverage of every filter dimension + cursor continuation + has_more).
//
// Inserts rows with controlled ts/event_type/risk_level (insert_test_event, test-helpers) and asserts:
//   - since/until time-window filtering (RFC3339 lexicographic comparison).
//   - event_type exact match (returns only evaluate, excludes confirm).
//   - level_min risk-level floor (L3+ filters out L1/L2, json_extract NULL rows excluded).
//   - Cursor pagination: limit truncation + has_more=true + next_cursor pulls older rows; exhausted -> has_more=false.
//   - Combined filters: since + level_min + event_type applied simultaneously.
//
// Requires the test-helpers feature (insert_test_event). Requires FUSION_GUARD_TOKEN_KEY.

use fg_core::{RiskLevel, SafetyAction};
use fg_store::{AuditListFilter, AuditStore};

const TEST_KEY_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn ensure_env_key() {
    if std::env::var("FUSION_GUARD_TOKEN_KEY").is_err() {
        std::env::set_var("FUSION_GUARD_TOKEN_KEY", TEST_KEY_HEX);
    }
}

fn temp_db() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "fg-p16-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("guard-p16.db")
}

// Fixed time anchor: 2026-08-27 12:00:00 UTC, rows 10 minutes apart (ts lexicographic order == chronological order).
fn ts(minute_offset: i64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-08-27T12:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc)
        + chrono::Duration::minutes(minute_offset)
}

fn rfc(t: chrono::DateTime<chrono::Utc>) -> String {
    t.to_rfc3339()
}

// Insert 6 mixed rows: ts 0..50min, event_type evaluate/confirm, risk L1/L3/L4.
fn seed(store: &AuditStore) {
    // DESC order: ts50 > ts40 > ... > ts0.
    store
        .insert_test_event("t1", ts(0), "evaluate", RiskLevel::L1, SafetyAction::Allow)
        .unwrap();
    store
        .insert_test_event("t1", ts(10), "evaluate", RiskLevel::L3, SafetyAction::Block)
        .unwrap();
    store
        .insert_test_event("t1", ts(20), "confirm", RiskLevel::L3, SafetyAction::Allow)
        .unwrap();
    store
        .insert_test_event("t1", ts(30), "evaluate", RiskLevel::L4, SafetyAction::Block)
        .unwrap();
    store
        .insert_test_event("t1", ts(40), "evaluate", RiskLevel::L2, SafetyAction::Allow)
        .unwrap();
    store
        .insert_test_event("t1", ts(50), "evaluate", RiskLevel::L3, SafetyAction::Block)
        .unwrap();
}

#[test]
fn time_window_since_until_filter() {
    ensure_env_key();
    let db = temp_db();
    let store = AuditStore::open(&db).unwrap();
    seed(&store);

    // since=ts15, until=ts35 -> in-window [ts20, ts30], excluding ts0/10/40/50.
    let page = store.list_filtered_page(&AuditListFilter {
        tenant_id: Some("t1"),
        since: Some(&rfc(ts(15))),
        until: Some(&rfc(ts(35))),
        limit: 100,
        ..Default::default()
    });
    assert!(!page.has_more);
    assert_eq!(
        page.records.len(),
        2,
        "time window must keep 2 rows (ts20+ts30), got {}",
        page.records.len()
    );
    // DESC: ts30 precedes ts20.
    assert!(
        page.records[0].ts > page.records[1].ts,
        "must be sorted ts DESC"
    );

    std::fs::remove_file(&db).ok();
}

#[test]
fn event_type_filter_excludes_confirm() {
    ensure_env_key();
    let db = temp_db();
    let store = AuditStore::open(&db).unwrap();
    seed(&store);

    let page = store.list_filtered_page(&AuditListFilter {
        tenant_id: Some("t1"),
        event_type: Some("evaluate"),
        limit: 100,
        ..Default::default()
    });
    // 5 of the 6 rows are evaluate (ts20 is confirm), ts20 must be excluded.
    assert_eq!(
        page.records.len(),
        5,
        "event_type=evaluate must keep 5 rows (excluding confirm), got {}",
        page.records.len()
    );

    let page_confirm = store.list_filtered_page(&AuditListFilter {
        tenant_id: Some("t1"),
        event_type: Some("confirm"),
        limit: 100,
        ..Default::default()
    });
    assert_eq!(
        page_confirm.records.len(),
        1,
        "event_type=confirm must keep 1 row, got {}",
        page_confirm.records.len()
    );

    std::fs::remove_file(&db).ok();
}

#[test]
fn level_min_filter_keeps_high_risk_only() {
    ensure_env_key();
    let db = temp_db();
    let store = AuditStore::open(&db).unwrap();
    seed(&store);

    // level_min=l3 -> risk >= L3: ts10(L3), ts20(L3 confirm), ts30(L4), ts50(L3) = 4 rows.
    // Excludes ts0(L1), ts40(L2).
    let page = store.list_filtered_page(&AuditListFilter {
        tenant_id: Some("t1"),
        level_min: Some("l3"),
        limit: 100,
        ..Default::default()
    });
    assert_eq!(
        page.records.len(),
        4,
        "level_min=l3 must keep 4 rows (L3+L4), excluding L1/L2, got {}",
        page.records.len()
    );

    // level_min=l4 -> only ts30(L4) = 1 row.
    let page_l4 = store.list_filtered_page(&AuditListFilter {
        tenant_id: Some("t1"),
        level_min: Some("l4"),
        limit: 100,
        ..Default::default()
    });
    assert_eq!(
        page_l4.records.len(),
        1,
        "level_min=l4 must keep 1 row (L4 only), got {}",
        page_l4.records.len()
    );

    // level_min uppercase compatibility -> same result as lowercase.
    let page_upper = store.list_filtered_page(&AuditListFilter {
        tenant_id: Some("t1"),
        level_min: Some("L3"),
        limit: 100,
        ..Default::default()
    });
    assert_eq!(
        page_upper.records.len(),
        4,
        "level_min uppercase must behave identically to lowercase, got {}",
        page_upper.records.len()
    );

    std::fs::remove_file(&db).ok();
}

#[test]
fn cursor_pagination_walks_all_pages() {
    ensure_env_key();
    let db = temp_db();
    let store = AuditStore::open(&db).unwrap();
    seed(&store);

    // limit=2: page 1 holds 2 rows (ts50, ts40) + has_more + next_cursor.
    let mut page = store.list_filtered_page(&AuditListFilter {
        tenant_id: Some("t1"),
        limit: 2,
        ..Default::default()
    });
    assert_eq!(page.records.len(), 2, "page 1 must hold 2 rows");
    assert!(page.has_more, "6 rows with limit=2 must set has_more");
    let cursor1 = page
        .next_cursor
        .clone()
        .expect("has_more must return next_cursor");
    assert_eq!(page.records[0].ts, ts(50), "DESC first row must be ts50");
    assert_eq!(page.records[1].ts, ts(40), "DESC second row must be ts40");

    // Decode cursor1 to continue with page 2 (ts30, ts20).
    let (cts, cid) = decode_cursor(&cursor1);
    page = store.list_filtered_page(&AuditListFilter {
        tenant_id: Some("t1"),
        cursor_ts: Some(&cts),
        cursor_id: Some(&cid),
        limit: 2,
        ..Default::default()
    });
    assert_eq!(page.records.len(), 2, "page 2 must hold 2 rows");
    assert!(page.has_more, "2 rows remain unpulled, must set has_more");
    assert_eq!(page.records[0].ts, ts(30));
    assert_eq!(page.records[1].ts, ts(20));

    // Page 3 (ts10, ts0) -> has_more=false.
    let cursor2 = page.next_cursor.clone().unwrap();
    let (cts2, cid2) = decode_cursor(&cursor2);
    page = store.list_filtered_page(&AuditListFilter {
        tenant_id: Some("t1"),
        cursor_ts: Some(&cts2),
        cursor_id: Some(&cid2),
        limit: 2,
        ..Default::default()
    });
    assert_eq!(page.records.len(), 2, "page 3 must hold 2 rows");
    assert!(!page.has_more, "last page must have has_more=false");
    assert!(
        page.next_cursor.is_none(),
        "last page must have no next_cursor"
    );
    assert_eq!(page.records[0].ts, ts(10));
    assert_eq!(page.records[1].ts, ts(0));

    std::fs::remove_file(&db).ok();
}

#[test]
fn combined_filters_since_level_event_type() {
    ensure_env_key();
    let db = temp_db();
    let store = AuditStore::open(&db).unwrap();
    seed(&store);

    // since=ts15 + event_type=evaluate + level_min=l3:
    // all 6 rows -> since excludes ts0/10 (ts<15) -> [ts20,30,40,50]
    // -> event_type=evaluate excludes ts20(confirm) -> [ts30,40,50]
    // -> level_min=l3 excludes ts40(L2) -> [ts30(L4), ts50(L3)] = 2 rows.
    let page = store.list_filtered_page(&AuditListFilter {
        tenant_id: Some("t1"),
        since: Some(&rfc(ts(15))),
        event_type: Some("evaluate"),
        level_min: Some("l3"),
        limit: 100,
        ..Default::default()
    });
    assert_eq!(
        page.records.len(),
        2,
        "combined filters (since+event_type+level_min) must keep 2 rows (ts30+ts50), got {}",
        page.records.len()
    );
    assert_eq!(page.records[0].ts, ts(50), "DESC first is ts50");
    assert_eq!(page.records[1].ts, ts(30), "DESC second is ts30");

    std::fs::remove_file(&db).ok();
}

#[test]
fn empty_filter_returns_all_desc() {
    ensure_env_key();
    let db = temp_db();
    let store = AuditStore::open(&db).unwrap();
    seed(&store);

    // No filter (tenant + large limit only) -> all 6 rows DESC.
    let page = store.list_filtered_page(&AuditListFilter {
        tenant_id: Some("t1"),
        limit: 100,
        ..Default::default()
    });
    assert_eq!(
        page.records.len(),
        6,
        "no filter must return all 6 rows, got {}",
        page.records.len()
    );
    assert!(!page.has_more);
    // DESC order: ts50..ts0.
    for i in 0..5 {
        assert!(
            page.records[i].ts > page.records[i + 1].ts,
            "must be strictly DESC"
        );
    }

    std::fs::remove_file(&db).ok();
}

// Cursor is encoded "ts\x1faudit_id" -> decode both keys.
fn decode_cursor(c: &str) -> (String, String) {
    let mut parts = c.splitn(2, '\x1f');
    let ts = parts.next().unwrap_or("").to_string();
    let id = parts.next().unwrap_or("").to_string();
    (ts, id)
}
