// H-E (product-audit §5, item c+d): 密钥丢失 vs 真篡改区分 + 轮换全链可验。
//
// 缺陷 (item d): master 丢失 → 全量审计链 HMAC 不匹配 → 旧逻辑一律 tampered=true,
// 与真篡改不可区分。修复: per-version key_anchor。verify 不匹配行查锚点: 锚点与当前
// master 重算不匹配 → key_version_unknown_rows++ (密钥丢失, 非篡改); 锚点匹配 → 真篡改;
// 锚点缺失 (legacy NULL) → fail-closed 篡改。
//
// (item c): 轮换 = bump version (master 不变)。旧行用旧 version 派生 key 验, verify 透过。
// re-hash 审计链被拒 (会破坏防篡改); per-row key_version 已令旧行验旧 key, 故 "轮换后历史行
// 可验" 本就成立。本测扩 p12 到全 4 链 (audit/tcc/rules/dead-letter) + token, 证实透过。
//
// 需 FUSION_GUARD_TOKEN_KEY + FUSION_GUARD_ALLOW_ENV_KEY (AuditStore::open 不触 Keychain 阻塞)。

use std::path::PathBuf;
use std::sync::Mutex;

use fg_core::{CheckStage, RiskLevel, SafetyAction};
use fg_rules::GuardRule;
use fg_store::AuditStore;

// 本文件 4 测试均改进程级 env (FUSION_GUARD_TOKEN_KEY 在 KEY_A/KEY_B 间切, +
// FUSION_GUARD_DATA_DIR 各自 temp 目录)。并行会令 AuditStore::open 读到别测试刚设的
// master / 目录 → key_loss 测试误载错 key → flaky。静态 Mutex 序列化同文件所有测试。
static ENV_GUARD: Mutex<()> = Mutex::new(());

const KEY_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
// 与 KEY_A 不同的 master (模拟密钥丢失后重生成/恢复错误的新密钥)。
const KEY_B: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

fn temp_env() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "fg-he-dl-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("guard-he.db");
    std::env::set_var("FUSION_GUARD_DATA_DIR", &dir);
    db
}

fn cleanup(dir: &std::path::Path) {
    std::fs::remove_dir_all(dir).ok();
}

// (item c) 轮换后全 4 链 + token 可验: v1 写 → rotate v2 → v2 写 → verify_all_chains 透过。
// 证明 "轮换后历史行可验" 成立, 无需 re-hash/re-encrypt (re-hash 破坏防篡改, 拒)。
#[tokio::test]
async fn rotation_all_chains_and_tokens_verify() {
    let _env_guard = ENV_GUARD.lock().unwrap();
    std::env::set_var("FUSION_GUARD_TOKEN_KEY", KEY_A);
    std::env::set_var("FUSION_GUARD_ALLOW_ENV_KEY", "1");
    let db = temp_env();
    let store = AuditStore::open(&db).unwrap();
    let now = chrono::Utc::now();

    // v1: 审计行 + tcc 链 + 规则突变 + token。
    store.insert_event_at_ts("rot", now, "rm -rf /v1").unwrap();
    store
        .report_tcc_event("Accessibility", "app-a", "granted", "user")
        .unwrap();
    let rule = GuardRule {
        name: "r1".into(),
        pattern: "rm -rf".into(),
        stage: CheckStage::Regex,
        action: SafetyAction::Block,
        risk_level: RiskLevel::L4,
        reason: "rm -rf block".into(),
        scope: fg_core::RuleScope::Command,
    };
    store.save_rule(&rule).unwrap();
    let tokens = store.tokens();
    tokens
        .put_tenant("tok-v1", "sk-v1-secret", "default")
        .unwrap();

    assert_eq!(store.current_key_version(), 1);
    let before = store.verify_all_chains(Some("rot")).unwrap();
    assert!(!before.tampered, "v1 全链干净");
    assert!(!before.key_loss, "v1 无密钥丢失");

    let new_v = store.rotate_key().unwrap();
    assert_eq!(new_v, 2);

    // v2: 各链再写一行 (混合 v1+v2)。
    store.insert_event_at_ts("rot", now, "rm -rf /v2").unwrap();
    store
        .report_tcc_event("Camera", "app-b", "denied", "tcc")
        .unwrap();
    let rule2 = GuardRule {
        name: "r2".into(),
        pattern: "curl|sh".into(),
        stage: CheckStage::Regex,
        action: SafetyAction::Block,
        risk_level: RiskLevel::L4,
        reason: "curl|sh block".into(),
        scope: fg_core::RuleScope::Command,
    };
    store.save_rule(&rule2).unwrap();
    tokens
        .put_tenant("tok-v2", "sk-v2-secret", "default")
        .unwrap();

    let after = store.verify_all_chains(Some("rot")).unwrap();
    assert!(
        !after.tampered,
        "混合 v1+v2 全 4 链可验 (per-row version, P1-2 + H-E item c)"
    );
    assert!(!after.key_loss, "同 master 轮换无密钥丢失");
    assert_eq!(after.audit.broken_links, 0, "audit 链无断链");
    assert_eq!(after.tcc.broken_links, 0, "tcc 链无断链");
    assert_eq!(after.rules.broken_links, 0, "rules 链无断链");
    assert_eq!(after.dead_letter.broken_links, 0, "dead_letter 链无断链");

    // token v1 旧 token 用 v1 派生 key 仍解 (旧 token 不随轮换失效)。
    let got_v1 = tokens.get_tenant("tok-v1", "default").unwrap();
    assert_eq!(got_v1, "sk-v1-secret", "v1 token 轮换后可解");
    let got_v2 = tokens.get_tenant("tok-v2", "default").unwrap();
    assert_eq!(got_v2, "sk-v2-secret", "v2 token 可解");

    let dir = db.parent().unwrap();
    cleanup(dir);
}

// (item d) 密钥丢失: 用 KEY_A 建库写行 → 换 KEY_B 重开 → verify_all_chains 报
// key_version_unknown_rows > 0 + key_loss=true, 但 tampered=false (非真篡改)。
#[tokio::test]
async fn key_loss_reports_unknown_not_tampered() {
    let _env_guard = ENV_GUARD.lock().unwrap();
    std::env::set_var("FUSION_GUARD_ALLOW_ENV_KEY", "1");
    std::env::set_var("FUSION_GUARD_TOKEN_KEY", KEY_A);
    let db = temp_env();
    let store = AuditStore::open(&db).unwrap();
    let now = chrono::Utc::now();

    // 写审计行 (落 key_version=1 + 锚点用 KEY_A 派生)。
    store.insert_event_at_ts("kt", now, "rm -rf /loss").unwrap();
    store
        .report_tcc_event("Accessibility", "app-x", "granted", "u")
        .unwrap();
    drop(store);

    // 换 master B 重开 (模拟密钥丢失后误用新密钥, env 显式提供绕过 virgin 门)。
    std::env::set_var("FUSION_GUARD_TOKEN_KEY", KEY_B);
    let store2 = AuditStore::open(&db).unwrap();

    let v = store2.verify_all_chains(Some("kt")).unwrap();
    // 行 HMAC 用 KEY_A 派生, 现 master B 派生不匹配 → broken。但锚点 (KEY_A 派生)
    // 与 master B 重算不匹配 → KeyLoss (非 Tamper)。
    assert!(
        v.audit.key_version_unknown_rows > 0,
        "audit 行密钥丢失 → key_version_unknown_rows > 0 (H-E item d)"
    );
    assert!(v.audit.broken_links > 0, "丢失行不可验 → broken_links > 0");
    assert!(
        !v.audit.tampered,
        "密钥丢失非真篡改 → tampered=false (H-E item d 核心区分)"
    );
    assert!(v.key_loss, "聚合 key_loss=true");
    assert!(!v.tampered, "纯密钥丢失 (无真篡改) → 聚合 tampered=false");
    // tcc 链同理丢失。
    assert!(v.tcc.key_version_unknown_rows > 0, "tcc 链密钥丢失同样区分");

    let dir = db.parent().unwrap();
    cleanup(dir);
}

// (item d) 真篡改: 同 master 下直接改一行的 event_hash → 锚点匹配 (master 能派生)
// → tampered=true, key_version_unknown_rows=0。
#[tokio::test]
async fn real_tamper_reports_tampered_not_key_loss() {
    let _env_guard = ENV_GUARD.lock().unwrap();
    std::env::set_var("FUSION_GUARD_ALLOW_ENV_KEY", "1");
    std::env::set_var("FUSION_GUARD_TOKEN_KEY", KEY_A);
    let db = temp_env();
    let store = AuditStore::open(&db).unwrap();
    let now = chrono::Utc::now();

    store.insert_event_at_ts("tp", now, "rm -rf /ok").unwrap();
    store
        .insert_event_at_ts("tp", now, "rm -rf /tamper")
        .unwrap();

    // 用写连接直接篡改第 2 行的 event_hash (同 master, 锚点仍匹配)。
    {
        let w = store.audit_writer_handle();
        let w = w.lock().unwrap();
        w.execute(
            "UPDATE audit_events SET event_hash = 'deadbeef' WHERE rowid = \
             (SELECT rowid FROM audit_events ORDER BY rowid DESC LIMIT 1)",
            [],
        )
        .unwrap();
    }

    let v = store.verify_all_chains(Some("tp")).unwrap();
    assert!(
        v.audit.tampered,
        "同 master 改 event_hash = 真篡改 → tampered=true (H-E item d)"
    );
    assert!(
        v.audit.key_version_unknown_rows == 0,
        "真篡改非密钥丢失 → key_version_unknown_rows=0"
    );
    assert!(v.tampered, "聚合 tampered=true");
    assert!(!v.key_loss, "真篡改 → key_loss=false");

    let dir = db.parent().unwrap();
    cleanup(dir);
}

// (item d) 锚点缺失 (legacy NULL) → fail-closed 篡改。攻击者清锚点无法伪装成密钥丢失。
#[tokio::test]
async fn missing_anchor_fail_closed_as_tamper() {
    let _env_guard = ENV_GUARD.lock().unwrap();
    std::env::set_var("FUSION_GUARD_ALLOW_ENV_KEY", "1");
    std::env::set_var("FUSION_GUARD_TOKEN_KEY", KEY_A);
    let db = temp_env();
    let store = AuditStore::open(&db).unwrap();
    let now = chrono::Utc::now();

    store
        .insert_event_at_ts("ma", now, "rm -rf /anchor")
        .unwrap();

    // 篡改审计行 event_hash (令 HMAC 不匹配) + 清 token.db 的 v1 锚点为 NULL。
    {
        let w = store.audit_writer_handle();
        let w = w.lock().unwrap();
        w.execute(
            "UPDATE audit_events SET event_hash = 'cafebabe' WHERE rowid = \
             (SELECT rowid FROM audit_events ORDER BY rowid DESC LIMIT 1)",
            [],
        )
        .unwrap();
        let token_db = db.with_file_name("token.db");
        let tc = rusqlite::Connection::open(&token_db).unwrap();
        tc.execute(
            "UPDATE key_versions SET key_anchor = NULL WHERE version = 1",
            [],
        )
        .unwrap();
    }

    let v = store.verify_all_chains(Some("ma")).unwrap();
    assert!(
        v.audit.tampered,
        "锚点 NULL + HMAC 不匹配 → fail-closed tampered=true (H-E, 攻击者清锚点无藏身处)"
    );
    assert!(
        v.audit.key_version_unknown_rows == 0,
        "锚点缺失不当密钥丢失 → key_version_unknown_rows=0"
    );

    let dir = db.parent().unwrap();
    cleanup(dir);
}
