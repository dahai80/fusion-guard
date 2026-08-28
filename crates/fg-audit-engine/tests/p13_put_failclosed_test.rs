// P1-3 (audit §2.5): pending action put fail-closed。
// L3 判定 (requires_approval) 需 confirm 流, actions().put() 失败 → action_id 不可交付
// (caller confirm 查无此行 → 永久死胡同)。put 失败拒评估, 不返带 action_id 的 verdict。
// 与 H7 审计写 fail-closed 耐久语义一致 (两套写同一次 evaluate)。
//
// 故障注入: 删 pending_actions 表 → put 的 INSERT 报 SQLite 错。
// 需要 FUSION_GUARD_TOKEN_KEY (AuditStore::open → TokenStore 加载密钥)。
// test-helpers feature (透传 fg-store)。

use std::path::PathBuf;

use fg_audit_engine::AuditEngine;
use fg_core::{ContentType, GuardError, SafetyAction};
use fg_store::AuditStore;
use std::sync::Arc;

const TEST_KEY_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn ensure_env_key() {
    if std::env::var("FUSION_GUARD_TOKEN_KEY").is_err() {
        std::env::set_var("FUSION_GUARD_TOKEN_KEY", TEST_KEY_HEX);
    }
}

fn temp_env() -> (PathBuf, PathBuf) {
    ensure_env_key();
    let dir = std::env::temp_dir().join(format!(
        "fg-p13-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("guard-p13.db");
    std::env::set_var("FUSION_GUARD_DATA_DIR", &dir);
    (db, dir)
}

fn cleanup(dir: &std::path::Path) {
    std::fs::remove_dir_all(dir).ok();
}

// L3 判定 + put 失败 → evaluate 返 Engine err, 不下发 action_id。
// L3 触发: shell 内容含 $(...) 进程替换 → tokenizer Block L3 (requires_approval)。
#[tokio::test]
async fn l3_put_failure_refuses_evaluate() {
    let (db, dir) = temp_env();
    let store = Arc::new(AuditStore::open(&db).unwrap());
    let engine = AuditEngine::new(store.clone()).unwrap();

    // baseline: 正常 L3 判定返带 action_id 的 verdict (put 成功)。
    let ok = engine
        .evaluate("echo $(whoami)", 0, "default", ContentType::Shell, None)
        .unwrap();
    assert!(
        ok.requires_approval || ok.action == SafetyAction::Block,
        "baseline L3/Block hit"
    );
    assert!(ok.action_id.is_some(), "baseline returns action_id");

    // 故障注入: 删 pending_actions 表 → 后续 put INSERT 报错。
    {
        let w = store.audit_writer_handle();
        let w = w.lock().unwrap();
        w.execute_batch("DROP TABLE pending_actions").unwrap();
    }

    // put 失败 → evaluate fail-closed, 返 Engine err (非带 action_id verdict)。
    let res = engine.evaluate("echo $(id)", 0, "default", ContentType::Shell, None);
    assert!(
        matches!(res, Err(GuardError::Engine(_))),
        "L3 put failure must fail-closed (P1-3), got {:?}",
        res
    );
    if let Err(GuardError::Engine(msg)) = &res {
        assert!(
            msg.contains("pending action persist failed"),
            "error message tags pending action failure: {}",
            msg
        );
    }

    cleanup(&dir);
}

// L4 Block + put 失败 → 同样 fail-closed (耐久语义一致, 非 L3 专属)。
// L4 触发: rm -rf 敏感路径 → tokenizer Block L4。
#[tokio::test]
async fn l4_put_failure_refuses_evaluate() {
    let (db, dir) = temp_env();
    let store = Arc::new(AuditStore::open(&db).unwrap());
    let engine = AuditEngine::new(store.clone()).unwrap();

    let ok = engine
        .evaluate("rm -rf /", 0, "default", ContentType::Shell, None)
        .unwrap();
    assert_eq!(ok.action, SafetyAction::Block, "baseline L4 Block");
    assert!(ok.action_id.is_some());

    {
        let w = store.audit_writer_handle();
        let w = w.lock().unwrap();
        w.execute_batch("DROP TABLE pending_actions").unwrap();
    }

    let res = engine.evaluate("rm -rf /etc", 0, "default", ContentType::Shell, None);
    assert!(
        matches!(res, Err(GuardError::Engine(_))),
        "L4 put failure must fail-closed (P1-3, H7 耐久一致), got {:?}",
        res
    );

    cleanup(&dir);
}
