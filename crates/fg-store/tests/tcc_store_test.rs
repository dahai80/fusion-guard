use fg_store::AuditStore;

const TEST_KEY_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn ensure_env_key() {
    if std::env::var("FUSION_GUARD_TOKEN_KEY").is_err() {
        std::env::set_var("FUSION_GUARD_TOKEN_KEY", TEST_KEY_HEX);
    }
}

fn temp_db() -> std::path::PathBuf {
    ensure_env_key();
    let dir = std::env::temp_dir().join(format!(
        "fg-store-tcc-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("guard-tcc-test.db")
}

#[test]
fn tcc_event_persist_and_list() {
    let path = temp_db();
    let store = AuditStore::open(&path).unwrap();

    let id1 = store
        .report_tcc_event("accessibility", "fusion-cli", "granted", "user prompt")
        .unwrap();
    let id2 = store
        .report_tcc_event(
            "full_disk_access",
            "fusion-studio",
            "denied",
            "user declined",
        )
        .unwrap();
    assert_ne!(id1, id2, "audit ids must be distinct");

    let events = store.list_tcc_events(10).unwrap();
    assert_eq!(events.len(), 2, "both TCC events persisted");
    assert_eq!(events[0].permission, "full_disk_access");
    assert_eq!(events[0].requester, "fusion-studio");
    assert_eq!(events[0].result, "denied");
    assert_eq!(events[1].permission, "accessibility");
    assert_eq!(events[1].result, "granted");
    std::fs::remove_file(&path).ok();
}

#[test]
fn tcc_event_limit_respected() {
    let path = temp_db();
    let store = AuditStore::open(&path).unwrap();
    for i in 0..5 {
        store
            .report_tcc_event("microphone", "app", "granted", &format!("r{}", i))
            .unwrap();
    }
    let events = store.list_tcc_events(3).unwrap();
    assert_eq!(events.len(), 3, "limit caps results");
    std::fs::remove_file(&path).ok();
}
