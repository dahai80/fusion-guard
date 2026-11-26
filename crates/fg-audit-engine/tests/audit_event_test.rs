// Issue #1/#3 (PRD §6.7 / D-10, frozen fusion-event contract): engine layer of the inbound guard.audit RPC.
// audit_event concatenates fusion-event trigger fields into content, reuses evaluate, and maps the verdict to the
// three-state decision.
// pass: clean trigger; block: target_path contains rm -rf; challenge: L3 requires_approval.
// audit_id comes from the append_event chain row; trigger_id echoed verbatim.
// Requires FUSION_GUARD_TOKEN_KEY (AuditStore::open → TokenStore loads the key).

use std::path::PathBuf;
use std::sync::Arc;

use fg_audit_engine::AuditEngine;
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
        "fg-audit-event-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("guard-audit-event.db");
    std::env::set_var("FUSION_GUARD_DATA_DIR", &dir);
    (db, dir)
}

fn cleanup(dir: &std::path::Path) {
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn audit_event_clean_trigger_passes() {
    let (db, dir) = temp_env();
    let store = Arc::new(AuditStore::open(&db).unwrap());
    let engine = AuditEngine::new(store.clone()).unwrap();

    let payload = serde_json::json!({"lines_changed": 42});
    let d = engine
        .audit_event(
            "trig-001",
            "fileModified",
            "/Users/dahai/src/a.swift",
            "fusion-code",
            &payload,
            "macbook",
            "default",
            "fusion-code",
        )
        .unwrap();
    assert_eq!(d.decision, "pass", "clean fileModified → pass: {d:?}");
    assert_eq!(d.trigger_id, "trig-001", "trigger_id echoed");
    assert_eq!(d.risk_level, 0, "clean → L1 (rank 0)");
    assert!(!d.audit_id.to_string().is_empty(), "audit_id assigned");
    cleanup(&dir);
}

#[tokio::test]
async fn audit_event_rm_rf_target_blocks() {
    let (db, dir) = temp_env();
    let store = Arc::new(AuditStore::open(&db).unwrap());
    let engine = AuditEngine::new(store.clone()).unwrap();

    let d = engine
        .audit_event(
            "trig-002",
            "fileModified",
            "rm -rf /etc",
            "fusion-code",
            &serde_json::Value::Null,
            "macbook",
            "default",
            "fusion-code",
        )
        .unwrap();
    assert_eq!(d.decision, "block", "rm -rf in target_path → block: {d:?}");
    assert!(d.risk_level >= 3, "Block → L4 risk rank");
    cleanup(&dir);
}

#[tokio::test]
async fn audit_event_trigger_id_echoed_in_response() {
    let (db, dir) = temp_env();
    let store = Arc::new(AuditStore::open(&db).unwrap());
    let engine = AuditEngine::new(store.clone()).unwrap();

    let d = engine
        .audit_event(
            "trig-echo-xyz",
            "systemWake",
            "",
            "fusion-agent-studio",
            &serde_json::json!({}),
            "node-a",
            "default",
            "fusion-agent-studio",
        )
        .unwrap();
    assert_eq!(d.trigger_id, "trig-echo-xyz");
    assert_eq!(d.decision, "pass");
    cleanup(&dir);
}

#[tokio::test]
async fn audit_event_pii_payload_passes_redacted() {
    let (db, dir) = temp_env();
    let store = Arc::new(AuditStore::open(&db).unwrap());
    let engine = AuditEngine::new(store.clone()).unwrap();

    let payload = serde_json::json!({"token": "ghp_abcdefABCDEF1234567890abcdef"});
    let d = engine
        .audit_event(
            "trig-003",
            "clipboardChanged",
            "/tmp/clip.txt",
            "fusion-doc",
            &payload,
            "macbook",
            "default",
            "fusion-doc",
        )
        .unwrap();
    assert_eq!(
        d.decision, "pass",
        "sensitive payload → Redact L2 maps to pass (DLP masking, not a permission denial): {d:?}"
    );
    assert_eq!(d.risk_level, 1, "Redact → L2 rank 1");
    cleanup(&dir);
}
