// P2-6 (audit §3.2/F6, PRD §6.3 H9): category_hint 边界传递 + 风险地板。
// 旧 IPC 不收 category_hint, 调用方 hint 在边界丢弃 → H9 半实现 (caller 无法传 hint)。
// 修: IPC 收 category_hint? 传入 AuditEngine::evaluate; hint 仅作风险地板 (max(推断,命中,hint))
// 抬等级永不压低, L3/L4 由真实规则命中驱动 (非 caller 声明), hint 地板封顶 L2。
// 需 FUSION_GUARD_TOKEN_KEY (AuditStore::open → TokenStore 加载密钥)。
// test-helpers feature 透传。

use std::path::PathBuf;
use std::sync::Arc;

use fg_audit_engine::{hint_risk_floor, AuditEngine};
use fg_core::{ContentType, RiskLevel, SafetyAction};
use fg_store::AuditStore;

const TEST_KEY_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn ensure_env_key() {
    if std::env::var("FUSION_GUARD_TOKEN_KEY").is_err() {
        std::env::set_var("FUSION_GUARD_TOKEN_KEY", TEST_KEY_HEX);
    }
}

fn temp_env() -> (PathBuf, PathBuf) {
    ensure_env_key();
    let dir = std::env::temp_dir().join(format!(
        "fg-p26-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("guard-p26.db");
    std::env::set_var("FUSION_GUARD_DATA_DIR", &dir);
    (db, dir)
}

fn cleanup(dir: &std::path::Path) {
    std::fs::remove_dir_all(dir).ok();
}

// hint_risk_floor 纯决策 (规则 5): 已知高风险 category → L2 地板; read/clean/未知 → None。
#[test]
fn hint_risk_floor_known_categories() {
    assert_eq!(hint_risk_floor("shell_exec"), Some(RiskLevel::L2));
    assert_eq!(hint_risk_floor("network"), Some(RiskLevel::L2));
    assert_eq!(hint_risk_floor("file_write"), Some(RiskLevel::L2));
}

#[test]
fn hint_risk_floor_low_or_unknown_is_none() {
    // read/clean: 调用方主张低风险不抬地板 (反方向不取信)。
    assert_eq!(hint_risk_floor("read"), None);
    assert_eq!(hint_risk_floor("clean"), None);
    // 未知 category: 不臆造风险 (caller 不能用未知名抬地板)。
    assert_eq!(hint_risk_floor("bogus_category"), None);
    assert_eq!(hint_risk_floor(""), None);
}

// H9 核心: hint 抬等级不压低。benign content (ls) 无 hit → L1 Allow;
// 传 category_hint="network" → 地板 L2 > L1 → risk 升 L2, action Allow→Redact。
#[tokio::test]
async fn hint_raises_floor_from_l1_to_l2() {
    let (db, dir) = temp_env();
    let store = Arc::new(AuditStore::open(&db).unwrap());
    let engine = AuditEngine::new(store.clone()).unwrap();

    // ls /tmp: 无规则命中, infer_category → "read" (L1 Allow)。
    let no_hint = engine
        .evaluate("ls /tmp", 0, "default", ContentType::Shell, None)
        .unwrap();
    assert_eq!(no_hint.risk_level, RiskLevel::L1, "无 hint 基线须 L1");
    assert_eq!(no_hint.action, SafetyAction::Allow, "无 hit 须 Allow");
    assert!(no_hint.category_hint.is_none(), "无 hint 须 None");

    // 同 content + hint "network": 地板 L2 > L1 → 抬 L2, action Redact。
    let with_hint = engine
        .evaluate("ls /tmp", 0, "default", ContentType::Shell, Some("network"))
        .unwrap();
    assert_eq!(
        with_hint.risk_level,
        RiskLevel::L2,
        "hint network 须抬 L2 地板"
    );
    assert_eq!(with_hint.action, SafetyAction::Redact, "Allow 须升 Redact");
    assert_eq!(
        with_hint.category_hint.as_deref(),
        Some("network"),
        "hint 须落 verdict"
    );
    // guard 推断的 inferred_category 仍是 read (content 权威), hint 不覆盖推断。
    assert_eq!(
        with_hint.inferred_category, "read",
        "hint 不覆盖 content 推断"
    );

    cleanup(&dir);
}

// H9 反向: hint 永不压低。rm -rf 命中 L4 Block; 传 hint "read" (低风险) → 仍 L4 Block。
// 防 v0.1 自证降级绕过 (调用方报 read 让 rm -rf 降 L1)。
#[tokio::test]
async fn hint_never_lowers_l4_block() {
    let (db, dir) = temp_env();
    let store = Arc::new(AuditStore::open(&db).unwrap());
    let engine = AuditEngine::new(store.clone()).unwrap();

    let v = engine
        .evaluate(
            "rm -rf /tmp/x",
            0,
            "default",
            ContentType::Shell,
            Some("read"),
        )
        .unwrap();
    assert_eq!(v.risk_level, RiskLevel::L4, "规则命中 L4 不被 hint 压低");
    assert_eq!(v.action, SafetyAction::Block, "Block 不被 hint 降级");
    assert_eq!(
        v.category_hint.as_deref(),
        Some("read"),
        "hint 仍落 verdict (审计可见调用方主张)"
    );
    // content 推断权威: inferred_category 非空且未被 hint "read" 覆盖 (hint 不改推断, 只抬地板)。
    assert!(!v.inferred_category.is_empty(), "content 推断须非空");
    assert_ne!(
        v.inferred_category, "read",
        "hint 不覆盖 content 推断 (H9 权威在 content)"
    );

    cleanup(&dir);
}

// hint 地板低于当前判定 → 无副作用 (地板只抬不压)。rm -rf 命中 L4 Block;
// 传 hint "shell_exec" (L2 地板) → 地板 L2 < 当前 L4 → 不改 risk/action (地板只在低于当前时抬)。
#[tokio::test]
async fn hint_floor_below_current_no_change() {
    let (db, dir) = temp_env();
    let store = Arc::new(AuditStore::open(&db).unwrap());
    let engine = AuditEngine::new(store.clone()).unwrap();

    let no_hint = engine
        .evaluate("rm -rf /tmp/y", 0, "default", ContentType::Shell, None)
        .unwrap();
    assert_eq!(no_hint.risk_level, RiskLevel::L4, "基线 L4");
    assert_eq!(no_hint.action, SafetyAction::Block);

    let with_hint = engine
        .evaluate(
            "rm -rf /tmp/y",
            0,
            "default",
            ContentType::Shell,
            Some("shell_exec"),
        )
        .unwrap();
    // shell_exec 地板 L2 < 当前 L4 → 不改 (地板只抬, 低于当前无副作用)。
    assert_eq!(with_hint.risk_level, RiskLevel::L4, "地板<当前 不改 risk");
    assert_eq!(
        with_hint.action,
        SafetyAction::Block,
        "地板<当前 不改 action"
    );
    assert_eq!(
        with_hint.category_hint.as_deref(),
        Some("shell_exec"),
        "hint 仍落 verdict"
    );

    cleanup(&dir);
}
