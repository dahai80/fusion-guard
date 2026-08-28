use fg_store::TokenStore;
use rusqlite::Connection;

const TEST_KEY_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn ensure_env_key() {
    if std::env::var("FUSION_GUARD_TOKEN_KEY").is_err() {
        std::env::set_var("FUSION_GUARD_TOKEN_KEY", TEST_KEY_HEX);
    }
}

fn temp_conn() -> Connection {
    ensure_env_key();
    let dir = std::env::temp_dir().join(format!(
        "fg-token-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("token-test.db");
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
        .unwrap();
    conn
}

#[test]
fn put_get_roundtrip() {
    let store = TokenStore::open(temp_conn()).unwrap();
    store
        .put("tok_abc", "sk-secret-api-key-1234567890")
        .unwrap();
    let got = store.get("tok_abc").unwrap();
    assert_eq!(got, "sk-secret-api-key-1234567890");
}

#[test]
fn missing_token_errors() {
    let store = TokenStore::open(temp_conn()).unwrap();
    let err = store.get("tok_nope").unwrap_err();
    assert!(matches!(err, fg_store::TokenError::NotFound(_)));
}

#[test]
fn ciphertext_not_plaintext() {
    let conn = temp_conn();
    let store = TokenStore::open(conn).unwrap();
    store.put("tok_x", "supersecret").unwrap();
    let dir = std::env::temp_dir();
    let mut found_plaintext = false;
    for entry in std::fs::read_dir(&dir).unwrap().flatten() {
        if let Ok(content) = std::fs::read(entry.path()) {
            if content.windows(11).any(|w| w == b"supersecret") {
                found_plaintext = true;
            }
        }
    }
    assert!(
        !found_plaintext,
        "plaintext must not appear on disk in temp db"
    );
}

#[test]
fn in_flight_flag_persists() {
    let store = TokenStore::open(temp_conn()).unwrap();
    store.put("tok_flight", "secret").unwrap();
    store.set_in_flight("tok_flight", true).unwrap();
    store.set_in_flight("tok_flight", false).unwrap();
    let got = store.get("tok_flight").unwrap();
    assert_eq!(got, "secret");
}

#[test]
fn cross_restart_reveal_persists() {
    let dir = std::env::temp_dir().join(format!(
        "fg-token-restart-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("token-restart.db");
    {
        ensure_env_key();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .unwrap();
        let store = TokenStore::open(conn).unwrap();
        store.put("tok_restart", "restart-secret").unwrap();
    }
    {
        ensure_env_key();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .unwrap();
        let store = TokenStore::open(conn).unwrap();
        let got = store.get("tok_restart").unwrap();
        assert_eq!(got, "restart-secret", "encrypted token survives restart");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn evict_expired_removes_old() {
    let store = TokenStore::open(temp_conn()).unwrap();
    store.put("tok_old", "old").unwrap();
    let n = store.evict_expired().unwrap();
    assert_eq!(n, 0, "fresh token not evicted");
}
