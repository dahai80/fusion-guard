// P0-5 (audit §1.4): TCC 链 + 规则突变链 + 死信 HMAC/reimport + 全链聚合校验。
// 死信文件由 store 内部 spool_dead_letter 写 (带 prev_hmac/hmac), 测试无法直接调私有 fn;
// 改用直接构造合法死信文件 (用与 store 同算法算 hmac) 验 verify_dead_letter + reimport_dead_letter。
//
// 需要 FUSION_GUARD_TOKEN_KEY (AuditStore::open → TokenStore 加载密钥) + test-helpers feature
// (insert_event_at_ts 暴露供构造带 ts 的合法 audit 链行)。

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use fg_core::{CheckStage, GuardVerdict, RiskLevel, SafetyAction};
use fg_rules::GuardRule;
use fg_store::token_store::derive_chain_key;
use fg_store::AuditStore;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

const TEST_KEY_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn ensure_env_key() {
    if std::env::var("FUSION_GUARD_TOKEN_KEY").is_err() {
        std::env::set_var("FUSION_GUARD_TOKEN_KEY", TEST_KEY_HEX);
    }
}

fn verdict(action: SafetyAction, risk: RiskLevel, cat: &str) -> GuardVerdict {
    GuardVerdict {
        action,
        risk_level: risk,
        reason: "test".into(),
        stage: CheckStage::Regex,
        requires_approval: false,
        redacted_content: None,
        seatbelt_required: false,
        action_id: None,
        verdict_epoch: 1,
        verdict_ttl_secs: 30,
        inferred_category: cat.into(),
        category_hint: None,
    }
}

fn temp_env() -> (PathBuf, PathBuf) {
    ensure_env_key();
    let dir = std::env::temp_dir().join(format!(
        "fg-p05-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("guard-p05.db");
    std::env::set_var("FUSION_GUARD_DATA_DIR", &dir);
    (db, dir)
}

fn cleanup(dir: &std::path::Path) {
    std::fs::remove_dir_all(dir).ok();
}

// 与 store 同 key (env 注入, store 读同一 env) → 测试端重算 hmac 须与 store 一致。
fn test_key() -> [u8; 32] {
    let hex = std::env::var("FUSION_GUARD_TOKEN_KEY").unwrap_or_else(|_| TEST_KEY_HEX.into());
    let mut out = [0u8; 32];
    let bytes = hex::decode(hex).unwrap();
    out.copy_from_slice(&bytes[..32]);
    out
}

// TCC 链: report 多条 → verify_tcc_chain 干净, 全链聚合 tampered=false。
#[tokio::test]
async fn tcc_chain_verify_clean() {
    let (db, dir) = temp_env();
    let store = AuditStore::open(&db).unwrap();

    store
        .report_tcc_event("Accessibility", "app-a", "granted", "user-init")
        .unwrap();
    store
        .report_tcc_event("ScreenRecording", "app-b", "denied", "not-authorized")
        .unwrap();
    store
        .report_tcc_event("FullDiskAccess", "app-c", "granted", "user-init")
        .unwrap();

    let v = store.verify_tcc_chain().unwrap();
    assert_eq!(v.total_rows, 3);
    assert_eq!(v.broken_links, 0);
    assert!(!v.tampered, "TCC chain clean (3 events)");
    assert_eq!(v.verified_links, 3);

    // 全链聚合: audit 空 + tcc 干净 + rules (可能有 epoch 种子突变) + dead_letter 空 → tampered=false。
    let all = store.verify_all_chains(None).unwrap();
    assert!(!all.tampered, "all-chains clean (no tamper anywhere)");
    assert_eq!(all.tcc.total_rows, 3);

    cleanup(&dir);
}

// 规则突变链: save_rule + delete_rule + save_epoch → verify_rules_chain 干净, 记录突变序列。
#[tokio::test]
async fn rule_mutation_chain_verify_clean() {
    let (db, dir) = temp_env();
    let store = AuditStore::open(&db).unwrap();

    let rule = GuardRule {
        name: "block-rmrf".into(),
        pattern: r"rm\s+-rf".into(),
        stage: CheckStage::Regex,
        action: SafetyAction::Block,
        risk_level: RiskLevel::L4,
        reason: "rm -rf block".into(),
        scope: fg_core::RuleScope::Command,
    };
    store.save_rule(&rule).unwrap();
    store.save_epoch(2).unwrap();
    store.delete_rule("block-rmrf").unwrap();

    let v = store.verify_rules_chain().unwrap();
    // save_rule + save_epoch + delete_rule = 3 突变行 (+ 种子 epoch 1, AuditEngine 启动种)。
    // 测试直接用 store 不经 AuditEngine 种子, 故 rule_mutations 仅本测试 3 条。
    assert_eq!(v.total_rows, 3);
    assert_eq!(v.broken_links, 0);
    assert!(!v.tampered, "rule mutation chain clean (3 mutations)");
    assert_eq!(v.verified_links, 3);

    cleanup(&dir);
}

// 规则突变链篡改: 直接 UPDATE rule_mutations.event_hash → verify_rules_chain 检出 tampered。
#[tokio::test]
async fn rule_mutation_chain_detects_tamper() {
    let (db, dir) = temp_env();
    let store = AuditStore::open(&db).unwrap();

    let rule = GuardRule {
        name: "block-curl".into(),
        pattern: r"curl\s+pipe".into(),
        stage: CheckStage::Regex,
        action: SafetyAction::Block,
        risk_level: RiskLevel::L4,
        reason: "curl pipe block".into(),
        scope: fg_core::RuleScope::Command,
    };
    store.save_rule(&rule).unwrap();
    store.save_rule(&rule).unwrap(); // 第二条 → 链 2 行

    // 篡改第一条 event_hash (模拟 DB 直接改)。
    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute(
        "UPDATE rule_mutations SET event_hash='deadbeef' WHERE mutation_id=\
         (SELECT mutation_id FROM rule_mutations ORDER BY rowid ASC LIMIT 1)",
        [],
    )
    .unwrap();
    drop(conn);

    let v = store.verify_rules_chain().unwrap();
    assert!(
        v.tampered,
        "rule mutation chain MUST detect tampered event_hash"
    );
    assert!(v.broken_links >= 1, "at least 1 broken link");
    assert!(v.first_broken_at.is_some());

    cleanup(&dir);
}

// 死信文件 verify + reimport: 构造合法死信文件 (同算法 hmac) → verify 干净 → reimport 导回 audit_events。
#[tokio::test]
async fn dead_letter_verify_and_reimport() {
    let (db, dir) = temp_env();
    let store = AuditStore::open(&db).unwrap();
    let dl_path = db.with_extension("deadletter");

    // 构造 2 条合法死信行 (hmac 链: prev_hmac=上一行 hmac, hmac=HMAC(key, prev_hmac‖payload))。
    let key = test_key();
    let mut prev_hmac =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    use std::io::Write;
    let mut f = std::fs::File::create(&dl_path).unwrap();
    for i in 0..2 {
        let ev = fg_store::AuditEvent {
            audit_id: uuid::Uuid::new_v4(),
            ts: chrono::Utc::now(),
            event_type: "evaluate".into(),
            tenant_id: "default".into(),
            requester: format!("app-{}", i),
            action: "block".into(),
            inferred_category: "shell_exec".into(),
            verdict_json: serde_json::to_string(&verdict(
                SafetyAction::Block,
                RiskLevel::L4,
                "shell_exec",
            ))
            .unwrap(),
            approved_by: None,
            seatbelt_required: true,
            outcome: "blocked".into(),
            prev_hash: String::new(),
            event_hash: String::new(),
        };
        let payload = ev.payload_bytes();
        let dkey = derive_chain_key(&Zeroizing::new(key), 1);
        let mut mac = HmacSha256::new_from_slice(&dkey[..]).unwrap();
        mac.update(prev_hmac.as_bytes());
        mac.update(&payload);
        let hmac_hex = hex::encode(mac.finalize().into_bytes());
        let ev_json = serde_json::to_string(&ev).unwrap();
        let line = format!(
            "{{\"prev_hmac\":\"{}\",\"hmac\":\"{}\",\"key_version\":1,\"reason\":\"queue full\",\"event\":{}}}\n",
            prev_hmac, hmac_hex, ev_json
        );
        f.write_all(line.as_bytes()).unwrap();
        prev_hmac = hmac_hex;
    }
    drop(f);
    let _ = std::fs::set_permissions(&dl_path, std::fs::Permissions::from_mode(0o600));

    // verify_dead_letter 干净 (2 行 hmac 链连续)。
    let v = store.verify_dead_letter();
    assert_eq!(v.total_rows, 2);
    assert_eq!(v.broken_links, 0);
    assert!(!v.tampered, "dead-letter chain clean (2 valid hmac rows)");
    assert_eq!(v.verified_links, 2);

    // reimport → 导回 audit_events 续主链, 死信文件清空。
    let imported = store.reimport_dead_letter().unwrap();
    assert_eq!(imported, 2, "2 dead-letter events reimported");

    // 死信文件清空。
    let remaining = std::fs::read_to_string(&dl_path).unwrap();
    assert!(
        remaining.trim().is_empty(),
        "dead-letter file cleared after reimport"
    );

    // audit_events 含 2 行 (导回), 主链续上 verify 干净。
    let av = store.verify_chain(None).unwrap();
    assert_eq!(av.total_rows, 2);
    assert!(
        !av.tampered,
        "audit chain clean after reimport (continued from dead-letter)"
    );

    cleanup(&dir);
}

// 死信篡改: 改一行 hmac → verify_dead_letter 检出 tampered + reimport 拒 (不导任何行)。
#[tokio::test]
async fn dead_letter_tamper_detected_and_reimport_aborts() {
    let (db, dir) = temp_env();
    let store = AuditStore::open(&db).unwrap();
    let dl_path = db.with_extension("deadletter");

    let key = test_key();
    let mut prev_hmac =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    use std::io::Write;
    let mut f = std::fs::File::create(&dl_path).unwrap();
    for i in 0..2 {
        let ev = fg_store::AuditEvent {
            audit_id: uuid::Uuid::new_v4(),
            ts: chrono::Utc::now(),
            event_type: "evaluate".into(),
            tenant_id: "default".into(),
            requester: format!("app-{}", i),
            action: "block".into(),
            inferred_category: "shell_exec".into(),
            verdict_json: serde_json::to_string(&verdict(
                SafetyAction::Block,
                RiskLevel::L4,
                "shell_exec",
            ))
            .unwrap(),
            approved_by: None,
            seatbelt_required: true,
            outcome: "blocked".into(),
            prev_hash: String::new(),
            event_hash: String::new(),
        };
        let payload = ev.payload_bytes();
        let dkey = derive_chain_key(&Zeroizing::new(key), 1);
        let mut mac = HmacSha256::new_from_slice(&dkey[..]).unwrap();
        mac.update(prev_hmac.as_bytes());
        mac.update(&payload);
        let hmac_hex = hex::encode(mac.finalize().into_bytes());
        let ev_json = serde_json::to_string(&ev).unwrap();
        let line = format!(
            "{{\"prev_hmac\":\"{}\",\"hmac\":\"{}\",\"key_version\":1,\"reason\":\"queue full\",\"event\":{}}}\n",
            prev_hmac, hmac_hex, ev_json
        );
        f.write_all(line.as_bytes()).unwrap();
        prev_hmac = hmac_hex;
    }
    drop(f);

    // 篡改第一行 hmac。
    let content = std::fs::read_to_string(&dl_path).unwrap();
    let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
    let mut tampered_line = lines[0].replace("\"hmac\":\"", "\"hmac\":\"deadbeef");
    // 保留行尾其余。上面 replace 只改首个 hmac 出现 (本行 hmac 字段), prev_hmac 不含 "hmac":"。
    tampered_line.push('\n');
    let second_line = format!("{}\n", lines[1]);
    std::fs::write(&dl_path, format!("{}{}", tampered_line, second_line)).unwrap();

    let v = store.verify_dead_letter();
    assert!(v.tampered, "dead-letter MUST detect tampered hmac");
    assert!(v.broken_links >= 1);

    // reimport 验签失败 → 拒绝导任何行 (返 Err)。
    let res = store.reimport_dead_letter();
    assert!(
        res.is_err(),
        "reimport MUST abort on tampered dead-letter (no partial import)"
    );

    // audit_events 仍空 (未导回任何行)。
    let av = store.verify_chain(None).unwrap();
    assert_eq!(
        av.total_rows, 0,
        "no events imported from tampered dead-letter"
    );

    cleanup(&dir);
}

// 全链聚合: 审计 + tcc + rules + 死信 全有数据 → verify_all_chains 全干净, tampered=false。
#[tokio::test]
async fn all_chains_aggregate_clean() {
    let (db, dir) = temp_env();
    let store = AuditStore::open(&db).unwrap();

    // audit 链: 1 行 (低风险)。
    store
        .insert_event_at_ts("default", chrono::Utc::now(), "ls -la")
        .unwrap();

    // tcc 链: 1 行。
    store
        .report_tcc_event("Microphone", "app-x", "granted", "user-init")
        .unwrap();

    // rules 链: 1 突变。
    let rule = GuardRule {
        name: "block-sudo".into(),
        pattern: r"^sudo\b".into(),
        stage: CheckStage::Regex,
        action: SafetyAction::Block,
        risk_level: RiskLevel::L4,
        reason: "sudo block".into(),
        scope: fg_core::RuleScope::Command,
    };
    store.save_rule(&rule).unwrap();

    // 死信空 (无 queue 满) → dead_letter.total_rows=0 干净。

    let all = store.verify_all_chains(None).unwrap();
    assert!(!all.tampered, "all chains clean in aggregate");
    assert!(all.audit.total_rows >= 1);
    assert_eq!(all.tcc.total_rows, 1);
    assert_eq!(all.rules.total_rows, 1);
    assert_eq!(all.dead_letter.total_rows, 0);

    cleanup(&dir);
}
