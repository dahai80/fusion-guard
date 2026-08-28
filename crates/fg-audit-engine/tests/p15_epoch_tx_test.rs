// P1-5 (audit §P1-5): epoch 编排层事务化 —— 并发 add_rule 不丢 epoch bump。
//
// add_rule 三步 (落盘 rule → 内存 add → 落盘 epoch) 非原子。无编排互斥锁时, 两线程并发:
//   T1 读 epoch=N, T2 读 epoch=N → 各自 bump N+1 写盘 → 丢一次 bump, epoch 单调但与规则数不一致。
// 修复: AuditEngine 持 rule_orch_lock (Mutex), add/update/remove 全程持锁序列化三步编排。
//
// 验收: N 线程并发 add_rule → 最终 epoch == 起始+N (无丢 bump), 且 N 条规则全落盘 (无丢规则)。
// 隔离 env: 独立 DATA_DIR + TOKEN_KEY。

use std::path::PathBuf;
use std::sync::Arc;

use fg_audit_engine::AuditEngine;
use fg_core::{CheckStage, RiskLevel, RuleScope, SafetyAction};
use fg_rules::GuardRule;
use fg_store::AuditStore;

const TEST_KEY_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const CONCURRENT_ADDS: usize = 16;

fn ensure_env_key() {
    if std::env::var("FUSION_GUARD_TOKEN_KEY").is_err() {
        std::env::set_var("FUSION_GUARD_TOKEN_KEY", TEST_KEY_HEX);
    }
}

fn temp_env() -> (PathBuf, PathBuf) {
    ensure_env_key();
    let dir = std::env::temp_dir().join(format!(
        "fg-p15-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("guard-p15.db");
    std::env::set_var("FUSION_GUARD_DATA_DIR", &dir);
    (db, dir)
}

fn cleanup(dir: &std::path::Path) {
    std::fs::remove_dir_all(dir).ok();
}

fn make_rule(idx: usize) -> GuardRule {
    GuardRule {
        name: format!("p15-concurrent-{}", idx),
        pattern: format!("dangerous_pattern_{}", idx),
        stage: CheckStage::Regex,
        action: SafetyAction::Block,
        risk_level: RiskLevel::L4,
        reason: format!("P1-5 concurrent test rule {}", idx),
        scope: RuleScope::Command,
    }
}

// P1-5 核心: 16 线程并发 add_rule → epoch 严格增 16 (无丢 bump), 16 规则全落盘。
#[test]
fn concurrent_add_rule_no_lost_epoch_bump() {
    let (db, dir) = temp_env();
    let store = Arc::new(AuditStore::open(&db).unwrap());
    let engine = Arc::new(AuditEngine::new(store.clone()).unwrap());

    let start_epoch = engine.epoch();
    tracing::info!(start_epoch, "P1-5: 并发 add_rule 起点 epoch");

    // 16 线程并发 add_rule, 各加 1 条唯一规则。
    let mut handles = Vec::with_capacity(CONCURRENT_ADDS);
    for i in 0..CONCURRENT_ADDS {
        let eng = Arc::clone(&engine);
        handles.push(std::thread::spawn(move || {
            let rule = make_rule(i);
            eng.add_rule(rule).expect("add_rule must succeed")
        }));
    }
    let epochs: Vec<u64> = handles
        .into_iter()
        .map(|h| h.join().expect("thread panicked"))
        .collect();

    let final_epoch = engine.epoch();

    // 验收 1: epoch 严格增 CONCURRENT_ADDS (无丢 bump)。无锁时并发会丢 bump → final < start+N。
    assert_eq!(
        final_epoch,
        start_epoch + CONCURRENT_ADDS as u64,
        "P1-5: 并发 add_rule 后 epoch 须严格增 {} (无丢 bump), start={} final={}",
        CONCURRENT_ADDS,
        start_epoch,
        final_epoch
    );

    // 验收 2: 各线程返回的 epoch 单调且唯一 (每个 bump 序列化, 不重复)。
    let mut sorted = epochs.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        CONCURRENT_ADDS,
        "P1-5: 各 add_rule 返回的 epoch 须唯一 (无两线程同 bump), got epochs={:?}",
        epochs
    );

    // 验收 3: 16 条规则全落盘 (重新 load 规则集, 数量含 16 新增)。
    let reloaded = store
        .load_rules()
        .expect("load_rules query")
        .expect("ruleset persisted after concurrent adds");
    for i in 0..CONCURRENT_ADDS {
        let name = format!("p15-concurrent-{}", i);
        let found = reloaded.rules.iter().any(|r| r.name == name);
        assert!(
            found,
            "P1-5: 并发 add_rule 后规则 {} 须落盘 (无丢规则)",
            name
        );
    }

    cleanup(&dir);
}

// P1-5 对照: 单线程连续 add_rule → epoch 严格增 N (基线, 证并发测试非偶然通过)。
#[test]
fn sequential_add_rule_epoch_strictly_increases() {
    let (db, dir) = temp_env();
    let store = Arc::new(AuditStore::open(&db).unwrap());
    let engine = AuditEngine::new(store).unwrap();

    let start_epoch = engine.epoch();
    for i in 0..CONCURRENT_ADDS {
        let ep = engine.add_rule(make_rule(100 + i)).expect("add_rule");
        assert_eq!(
            ep,
            start_epoch + 1 + i as u64,
            "P1-5: 连续 add_rule epoch 须严格 +1 每次"
        );
    }
    assert_eq!(
        engine.epoch(),
        start_epoch + CONCURRENT_ADDS as u64,
        "P1-5: 连续 add_rule 终态 epoch"
    );

    cleanup(&dir);
}
