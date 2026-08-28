// P1-6 (audit §3.2): audit.list 过滤 + 游标分页。
// 旧 handler 仅 tenant_id + limit, 监控只能暴力轮询全量。补 since/until/event_type/level_min
// 过滤 + 游标分页 → since=<上次末行 ts> 只拉增量。本测直接验证 store 层 list_filtered_page
// (纯 SQL 过滤, 不依赖套接字, 确定性覆盖各过滤维度 + 游标续拉 + has_more)。
//
// 插入可控 ts/event_type/risk_level 行 (insert_test_event, test-helpers), 断言:
//   - since/until 时间窗过滤 (RFC3339 字典序比较)。
//   - event_type 精确匹配 (只返 evaluate, 排除 confirm)。
//   - level_min 风险等级下限 (L3+ 过滤掉 L1/L2, json_extract NULL 行排除)。
//   - 游标分页: limit 截断 + has_more=true + next_cursor 续拉更旧行, 续完 has_more=false。
//   - 组合过滤: since + level_min + event_type 同时生效。
//
// 需 test-helpers feature (insert_test_event)。需 FUSION_GUARD_TOKEN_KEY。

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

// 固定时间锚: 2026-08-27 12:00:00 UTC, 各行隔 10 分钟 (ts 字典序 == 时间序)。
fn ts(minute_offset: i64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-08-27T12:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc)
        + chrono::Duration::minutes(minute_offset)
}

fn rfc(t: chrono::DateTime<chrono::Utc>) -> String {
    t.to_rfc3339()
}

// 插入 6 行混合: ts 0..50min, event_type evaluate/confirm, risk L1/L3/L4。
fn seed(store: &AuditStore) {
    // DESC 排序下顺序: ts50 > ts40 > ... > ts0。
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

    // since=ts15, until=ts35 → 窗口内 [ts20, ts30], 排除 ts0/10/40/50。
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
        "时间窗内须 2 行 (ts20+ts30), got {}",
        page.records.len()
    );
    // DESC: ts30 先于 ts20。
    assert!(page.records[0].ts > page.records[1].ts, "须按 ts DESC 排序");

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
    // 6 行中 5 行 evaluate (ts20 是 confirm), 须排除 ts20。
    assert_eq!(
        page.records.len(),
        5,
        "event_type=evaluate 须 5 行 (排除 confirm), got {}",
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
        "event_type=confirm 须 1 行, got {}",
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

    // level_min=l3 → risk >= L3: ts10(L3), ts20(L3 confirm), ts30(L4), ts50(L3) = 4 行。
    // 排除 ts0(L1), ts40(L2)。
    let page = store.list_filtered_page(&AuditListFilter {
        tenant_id: Some("t1"),
        level_min: Some("l3"),
        limit: 100,
        ..Default::default()
    });
    assert_eq!(
        page.records.len(),
        4,
        "level_min=l3 须 4 行 (L3+L4), 排除 L1/L2, got {}",
        page.records.len()
    );

    // level_min=l4 → 仅 ts30(L4) = 1 行。
    let page_l4 = store.list_filtered_page(&AuditListFilter {
        tenant_id: Some("t1"),
        level_min: Some("l4"),
        limit: 100,
        ..Default::default()
    });
    assert_eq!(
        page_l4.records.len(),
        1,
        "level_min=l4 须 1 行 (仅 L4), got {}",
        page_l4.records.len()
    );

    // level_min 大写兼容 → 同小写结果。
    let page_upper = store.list_filtered_page(&AuditListFilter {
        tenant_id: Some("t1"),
        level_min: Some("L3"),
        limit: 100,
        ..Default::default()
    });
    assert_eq!(
        page_upper.records.len(),
        4,
        "level_min 大写须与小写同效, got {}",
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

    // limit=2: 第 1 页 2 行 (ts50, ts40) + has_more + next_cursor。
    let mut page = store.list_filtered_page(&AuditListFilter {
        tenant_id: Some("t1"),
        limit: 2,
        ..Default::default()
    });
    assert_eq!(page.records.len(), 2, "第 1 页须 2 行");
    assert!(page.has_more, "6 行 limit=2 须 has_more");
    let cursor1 = page.next_cursor.clone().expect("有更多须返 next_cursor");
    assert_eq!(page.records[0].ts, ts(50), "DESC 首行须 ts50");
    assert_eq!(page.records[1].ts, ts(40), "DESC 次行须 ts40");

    // 解码 cursor1 续拉第 2 页 (ts30, ts20)。
    let (cts, cid) = decode_cursor(&cursor1);
    page = store.list_filtered_page(&AuditListFilter {
        tenant_id: Some("t1"),
        cursor_ts: Some(&cts),
        cursor_id: Some(&cid),
        limit: 2,
        ..Default::default()
    });
    assert_eq!(page.records.len(), 2, "第 2 页须 2 行");
    assert!(page.has_more, "仍有 2 行未拉, 须 has_more");
    assert_eq!(page.records[0].ts, ts(30));
    assert_eq!(page.records[1].ts, ts(20));

    // 第 3 页 (ts10, ts0) → has_more=false。
    let cursor2 = page.next_cursor.clone().unwrap();
    let (cts2, cid2) = decode_cursor(&cursor2);
    page = store.list_filtered_page(&AuditListFilter {
        tenant_id: Some("t1"),
        cursor_ts: Some(&cts2),
        cursor_id: Some(&cid2),
        limit: 2,
        ..Default::default()
    });
    assert_eq!(page.records.len(), 2, "第 3 页须 2 行");
    assert!(!page.has_more, "末页须 has_more=false");
    assert!(page.next_cursor.is_none(), "末页须无 next_cursor");
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
    // 全 6 行 → since 排除 ts0/10 (ts<15) → [ts20,30,40,50]
    // → event_type=evaluate 排除 ts20(confirm) → [ts30,40,50]
    // → level_min=l3 排除 ts40(L2) → [ts30(L4), ts50(L3)] = 2 行。
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
        "组合过滤 (since+event_type+level_min) 须 2 行 (ts30+ts50), got {}",
        page.records.len()
    );
    assert_eq!(page.records[0].ts, ts(50), "DESC 首 ts50");
    assert_eq!(page.records[1].ts, ts(30), "DESC 次 ts30");

    std::fs::remove_file(&db).ok();
}

#[test]
fn empty_filter_returns_all_desc() {
    ensure_env_key();
    let db = temp_db();
    let store = AuditStore::open(&db).unwrap();
    seed(&store);

    // 无过滤 (仅 tenant + 大 limit) → 全 6 行 DESC。
    let page = store.list_filtered_page(&AuditListFilter {
        tenant_id: Some("t1"),
        limit: 100,
        ..Default::default()
    });
    assert_eq!(
        page.records.len(),
        6,
        "无过滤须全 6 行, got {}",
        page.records.len()
    );
    assert!(!page.has_more);
    // DESC 序: ts50..ts0。
    for i in 0..5 {
        assert!(page.records[i].ts > page.records[i + 1].ts, "须严格 DESC");
    }

    std::fs::remove_file(&db).ok();
}

// cursor 编码 "ts\x1faudit_id" → 解双键。
fn decode_cursor(c: &str) -> (String, String) {
    let mut parts = c.splitn(2, '\x1f');
    let ts = parts.next().unwrap_or("").to_string();
    let id = parts.next().unwrap_or("").to_string();
    (ts, id)
}
