// P2-6 (audit §3.2/F6, PRD §6.3 H9): category_hint boundary passthrough + risk floor.
// The old IPC did not accept category_hint; the caller's hint was dropped at the boundary → H9 half-implemented
// (callers could not pass hints).
// Fix: IPC accepts category_hint? and passes it to AuditEngine::evaluate; the hint acts only as a risk floor
// (max(inferred, hit, hint)) — it can raise the level, never lower it; L3/L4 are driven by real rule hits (not
// caller claims); the hint floor caps at L2.
// Requires FUSION_GUARD_TOKEN_KEY (AuditStore::open → TokenStore loads the key).
// test-helpers feature forwarded.

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

// hint_risk_floor pure decision (Rule 5): known high-risk categories → L2 floor; read/clean/unknown → None.
#[test]
fn hint_risk_floor_known_categories() {
    assert_eq!(hint_risk_floor("shell_exec"), Some(RiskLevel::L2));
    assert_eq!(hint_risk_floor("network"), Some(RiskLevel::L2));
    assert_eq!(hint_risk_floor("file_write"), Some(RiskLevel::L2));
}

#[test]
fn hint_risk_floor_low_or_unknown_is_none() {
    // read/clean: a low-risk caller claim does not raise the floor (the reverse direction is not trusted).
    assert_eq!(hint_risk_floor("read"), None);
    assert_eq!(hint_risk_floor("clean"), None);
    // unknown category: do not invent risk (a caller cannot raise the floor with an unknown name).
    assert_eq!(hint_risk_floor("bogus_category"), None);
    assert_eq!(hint_risk_floor(""), None);
}

// H9 core: the hint raises the level, never lowers it. Benign content (ls) has no hit → L1 Allow;
// passing category_hint="network" → floor L2 > L1 → risk rises to L2, action Allow→Redact.
#[tokio::test]
async fn hint_raises_floor_from_l1_to_l2() {
    let (db, dir) = temp_env();
    let store = Arc::new(AuditStore::open(&db).unwrap());
    let engine = AuditEngine::new(store.clone()).unwrap();

    // ls /tmp: no rule hits, infer_category → "read" (L1 Allow).
    let no_hint = engine
        .evaluate("ls /tmp", 0, "default", ContentType::Shell, None)
        .unwrap();
    assert_eq!(
        no_hint.risk_level,
        RiskLevel::L1,
        "no-hint baseline must be L1"
    );
    assert_eq!(no_hint.action, SafetyAction::Allow, "no hit must be Allow");
    assert!(no_hint.category_hint.is_none(), "no hint must be None");

    // Same content + hint "network": floor L2 > L1 → raised to L2, action Redact.
    let with_hint = engine
        .evaluate("ls /tmp", 0, "default", ContentType::Shell, Some("network"))
        .unwrap();
    assert_eq!(
        with_hint.risk_level,
        RiskLevel::L2,
        "hint network must raise the L2 floor"
    );
    assert_eq!(
        with_hint.action,
        SafetyAction::Redact,
        "Allow must be raised to Redact"
    );
    assert_eq!(
        with_hint.category_hint.as_deref(),
        Some("network"),
        "hint must land on the verdict"
    );
    // The guard-inferred inferred_category stays "read" (content is authoritative); the hint does not override inference.
    assert_eq!(
        with_hint.inferred_category, "read",
        "hint does not override content inference"
    );

    cleanup(&dir);
}

// H9 reverse: the hint never lowers. rm -rf hits L4 Block; passing hint "read" (low risk) → still L4 Block.
// Prevents the v0.1 self-attested downgrade bypass (a caller reporting "read" to downgrade rm -rf to L1).
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
    assert_eq!(
        v.risk_level,
        RiskLevel::L4,
        "rule-hit L4 is not lowered by the hint"
    );
    assert_eq!(
        v.action,
        SafetyAction::Block,
        "Block is not downgraded by the hint"
    );
    assert_eq!(
        v.category_hint.as_deref(),
        Some("read"),
        "hint still lands on the verdict (audit-visible caller claim)"
    );
    // Content inference is authoritative: inferred_category is non-empty and not overridden by the hint "read"
    // (the hint does not change inference, only raises the floor).
    assert!(
        !v.inferred_category.is_empty(),
        "content inference must be non-empty"
    );
    assert_ne!(
        v.inferred_category, "read",
        "hint does not override content inference (H9 authority is content)"
    );

    cleanup(&dir);
}

// Hint floor below the current verdict → no side effects (the floor only raises, never lowers). rm -rf hits
// L4 Block; passing hint "shell_exec" (L2 floor) → floor L2 < current L4 → risk/action unchanged (the floor
// only raises when below the current level).
#[tokio::test]
async fn hint_floor_below_current_no_change() {
    let (db, dir) = temp_env();
    let store = Arc::new(AuditStore::open(&db).unwrap());
    let engine = AuditEngine::new(store.clone()).unwrap();

    let no_hint = engine
        .evaluate("rm -rf /tmp/y", 0, "default", ContentType::Shell, None)
        .unwrap();
    assert_eq!(no_hint.risk_level, RiskLevel::L4, "baseline L4");
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
    // shell_exec floor L2 < current L4 → unchanged (the floor only raises; below current it has no effect).
    assert_eq!(
        with_hint.risk_level,
        RiskLevel::L4,
        "floor<current does not change risk"
    );
    assert_eq!(
        with_hint.action,
        SafetyAction::Block,
        "floor<current does not change action"
    );
    assert_eq!(
        with_hint.category_hint.as_deref(),
        Some("shell_exec"),
        "hint still lands on the verdict"
    );

    cleanup(&dir);
}
