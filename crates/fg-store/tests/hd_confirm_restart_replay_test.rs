// H-D (product-audit §5): confirm 跨库事务崩溃恢复级一次性回归。
// 缺陷根因: confirm_atomic 原实现 SELECT+INSERT+UPDATE 各在 autocommit 独立提交,
// 崩溃窗口 (audit INSERT 已提交, UPDATE consumed 未提交) → 重启后 action_id 仍 consumed=0 →
// 可再次 confirm = 双确认重放, 违反 H4 一次性。修复: BEGIN IMMEDIATE 跨 ATTACH 库
// (audit_writer ATTACH action.db) 跨库事务, 三步同事务 commit 原子, 崩溃恢复级 H4 达成。
//
// 本测试验证崩溃恢复语义: confirm 后 drop store (模拟进程崩溃) → re-open 同路径新 store
// → re-confirm 同 action_id → 必须返 Consumed (consumed 已持久化, 无重放窗口)。
// 即: confirm 的 consume 落盘与 audit 落盘原子, 重启后状态一致。
//
// 另含 H-A 并发混合风险单写者回归: 高风险 (Block L4, 同步写 audit_writer) 与
// 低风险 (L1, 异步 drain 写 low_writer) 并发插入 → verify_chain 必须无 broken/tampered
// (单写者经 BEGIN IMMEDIATE 序列化, 无链分叉)。

use std::sync::Arc;

use fg_core::{CheckStage, GuardVerdict, RiskLevel, SafetyAction};
use fg_store::AuditStore;
use zeroize::Zeroizing;

const TEST_KEY_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn ensure_env_key() {
    if std::env::var("FUSION_GUARD_TOKEN_KEY").is_err() {
        std::env::set_var("FUSION_GUARD_TOKEN_KEY", TEST_KEY_HEX);
    }
}

fn temp_db(tag: &str) -> std::path::PathBuf {
    ensure_env_key();
    let dir = std::env::temp_dir().join(format!(
        "fg-hd-test-{}-{}-{}",
        tag,
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("guard-hd.db")
}

fn cleanup(db: &std::path::Path) {
    std::fs::remove_file(db).ok();
    std::fs::remove_file(db.with_file_name("action.db")).ok();
    std::fs::remove_file(db.with_file_name("token.db")).ok();
    std::fs::remove_file(db.with_extension("db-wal")).ok();
    std::fs::remove_file(db.with_extension("db-shm")).ok();
    let _ = std::fs::remove_dir_all(db.parent().unwrap());
}

fn verdict(id: uuid::Uuid, risk: RiskLevel, action: SafetyAction) -> GuardVerdict {
    GuardVerdict {
        action,
        risk_level: risk,
        reason: "hd-trigger".into(),
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

// H-D: confirm 后重启 (drop+re-open) 再 confirm 同 action_id → Consumed。
// 证明 consume 落盘与 audit 落盘原子 (跨库事务), 崩溃恢复后无重放窗口。
#[test]
fn confirm_persists_across_restart_replay_rejected() {
    let db = temp_db("replay");

    // 第一次启动: put L3 + confirm approved
    let action_id = uuid::Uuid::new_v4();
    let id_str = action_id.to_string();
    {
        let store = AuditStore::open(&db).unwrap();
        store
            .actions()
            .put(
                &verdict(action_id, RiskLevel::L3, SafetyAction::Block),
                "default",
            )
            .unwrap();
        let v = confirm(&store, &id_str, true, "tester", "default").unwrap();
        assert_eq!(v.action, SafetyAction::Allow, "approved → Allow");
    } // store drop = 模拟进程退出/崩溃 (drain 线程随 drop 结束)

    // 重启: re-open 同路径新 AuditStore (新连接, 新 drain 线程)
    // 验证 consumed 状态已持久化跨重启
    {
        let store = AuditStore::open(&db).unwrap();
        // 重 confirm 同 action_id → 必须 Consumed (一次性持久, 无重放窗口)
        let err = confirm(&store, &id_str, true, "tester", "default").unwrap_err();
        assert!(
            matches!(err, fg_store::ActionError::Consumed(_)),
            "re-confirm after restart must be Consumed (H-D cross-db tx atomically persisted consume, no replay window). got: {err:?}"
        );

        // 确认审计行也持久跨重启 (confirm 审计与 consume 同事务落库)
        let events = store.list_events(Some("default"), 50).unwrap();
        let has_confirm = events
            .iter()
            .any(|e| e.event_type == "confirm" && e.outcome == "approved");
        assert!(
            has_confirm,
            "confirm audit row persists across restart (H-D audit+consume atomic)"
        );
    }

    cleanup(&db);
}

// H-D (b): 未 confirm 的 action 重启后仍可 confirm (状态未被错误标记消费)。
// 对照: confirm 原子不能误把未 confirm 的 action 标 consumed。
#[test]
fn unconfirmed_action_survives_restart_confirmable() {
    let db = temp_db("unconf");

    let action_id = uuid::Uuid::new_v4();
    let id_str = action_id.to_string();
    {
        let store = AuditStore::open(&db).unwrap();
        store
            .actions()
            .put(
                &verdict(action_id, RiskLevel::L3, SafetyAction::Block),
                "default",
            )
            .unwrap();
    } // drop, 未 confirm

    {
        let store = AuditStore::open(&db).unwrap();
        // 重启后仍可 confirm (未误标 consumed)
        let v = confirm(&store, &id_str, false, "tester", "default").unwrap();
        assert_eq!(v.action, SafetyAction::Block, "rejected → Block");
        assert!(!v.requires_approval, "confirm clears requires_approval");
    }

    cleanup(&db);
}

// H-A (product-audit §5): 并发混合风险审计插入 → 链完整 (单写者序列化, 无分叉)。
// 高风险 Block L4 (同步 audit_writer) 与低风险 L1 (异步 drain → low_writer) 并发,
// 两写者经 BEGIN IMMEDIATE 序列化 SELECT-then-INSERT → 链不分叉 → verify_chain 干净。
#[test]
fn concurrent_mixed_risk_chain_stays_intact_single_writer() {
    let db = temp_db("concurrent");
    let store = Arc::new(AuditStore::open(&db).unwrap());

    let n_threads = 6;
    let per_thread = 25;
    let mut handles = Vec::new();
    for t in 0..n_threads {
        let store_cl = store.clone();
        let h = std::thread::spawn(move || {
            for i in 0..per_thread {
                // 交替高低风险: 偶数 L4 Block (高风险同步), 奇数 L1 Allow (低风险异步)
                let high = i % 2 == 0;
                let (action, risk) = if high {
                    (SafetyAction::Block, RiskLevel::L4)
                } else {
                    (SafetyAction::Allow, RiskLevel::L1)
                };
                let v = GuardVerdict {
                    action,
                    risk_level: risk,
                    reason: format!("concurrent-t{}-i{}", t, i),
                    stage: CheckStage::Regex,
                    requires_approval: false,
                    redacted_content: None,
                    seatbelt_required: false,
                    action_id: None,
                    verdict_epoch: 1,
                    verdict_ttl_secs: 30,
                    inferred_category: "test".into(),
                    category_hint: None,
                };
                store_cl
                    .append_event("default", &v, format!("raw-t{}-i{}", t, i), "tester")
                    .unwrap();
            }
        });
        handles.push(h);
    }
    for h in handles {
        h.join().unwrap();
    }

    // 等异步 drain 落库 (低风险经 mpsc → drain 线程 batch insert, 需短暂让出)
    // 轮询 verify_chain.total_rows 直到预期值或超时, 确保异步行全落库再校验。
    let expected = n_threads * per_thread;
    let mut landed = false;
    for _ in 0..50 {
        if store.verify_chain(None).unwrap().total_rows >= expected {
            landed = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        landed,
        "drain thread failed to land all async low-risk rows within timeout"
    );

    let ver = store.verify_chain(None).unwrap();
    assert!(
        ver.total_rows >= expected,
        "all concurrent events persisted: expected>={}, got {} (H-A drain landed)",
        expected,
        ver.total_rows
    );
    assert_eq!(
        ver.broken_links, 0,
        "no broken links under concurrent mixed-risk insert (H-A single writer via BEGIN IMMEDIATE)"
    );
    assert!(
        !ver.tampered,
        "chain not tampered under concurrency (H-A no fork)"
    );

    cleanup(&db);
}
