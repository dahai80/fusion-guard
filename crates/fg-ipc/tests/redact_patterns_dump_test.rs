// issue #7: guard.redact.patterns.dump exposes a serializable dump of the 15
// redaction pattern definitions.
// Verifies: a patterns array is returned (15 entries), each with
// name/regex/validator tag, priority order preserved (first match wins on overlap),
// and validator tag enum none|ipv4|aws_secret|luhn|phone|id_card (issue #13 adds
// id_card). Read-only dump; does not change redaction behavior.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use fg_ipc::IpcServer;
use fg_store::AuditStore;

const TEST_KEY_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn ensure_env() -> (PathBuf, PathBuf) {
    if std::env::var("FUSION_GUARD_TOKEN_KEY").is_err() {
        std::env::set_var("FUSION_GUARD_TOKEN_KEY", TEST_KEY_HEX);
    }
    let dir = std::env::temp_dir().join(format!(
        "fg-redactdump-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("guard-redactdump.db");
    let short = uuid::Uuid::new_v4().simple().to_string();
    let sock = PathBuf::from(format!(
        "/tmp/fg-redactdump-{}-{}.sock",
        std::process::id(),
        &short[..8]
    ));
    let _ = std::fs::remove_file(&sock);
    std::env::set_var("FUSION_GUARD_SOCK", &sock);
    std::env::set_var("FUSION_GUARD_DATA_DIR", &dir);
    (db, sock)
}

async fn spawn_server(db: &std::path::Path, sock: PathBuf) -> tokio::task::JoinHandle<()> {
    let store = Arc::new(AuditStore::open(db).unwrap());
    let engine = fg_audit_engine::AuditEngine::new(store.clone()).unwrap();
    let server = IpcServer::new(engine, store);
    tokio::spawn(async move {
        if let Err(e) = server.serve(sock).await {
            tracing::error!(error = %e, "test server exited");
        }
    })
}

async fn wait_for_sock(sock: &std::path::Path) {
    for _ in 0..100 {
        if sock.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("server sock never appeared: {}", sock.display());
}

fn call(sock: &std::path::Path, method: &str) -> serde_json::Value {
    let mut stream = UnixStream::connect(sock).unwrap();
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let req = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"{}","params":{{}}}}"#,
        method
    );
    stream.write_all(req.as_bytes()).unwrap();
    stream.write_all(&[0x0A]).unwrap();
    stream.flush().unwrap();

    let mut reader = BufReader::new(stream);
    let mut buf = Vec::new();
    reader.read_until(0x0A, &mut buf).unwrap();
    while buf.last() == Some(&0x0A) {
        buf.pop();
    }
    let resp: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    resp.get("result").cloned().unwrap()
}

// All 15 patterns are exposed, fields complete, validator tag enum correct.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redact_patterns_dump_returns_all_definitions() {
    let (db, sock) = ensure_env();
    let handle = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    let res = call(&sock, "guard.redact.patterns.dump");
    let patterns = res["patterns"].as_array().unwrap();
    assert_eq!(
        patterns.len(),
        15,
        "issue #7: all 15 redaction pattern definitions must be exposed"
    );

    // Fields complete + validator tag enum valid.
    let valid_tags = ["none", "ipv4", "aws_secret", "luhn", "phone", "id_card"];
    for p in patterns {
        assert!(p["name"].is_string(), "each entry must carry a name");
        assert!(p["regex"].is_string(), "each entry must carry a regex");
        let tag = p["validator"].as_str().unwrap();
        assert!(
            valid_tags.contains(&tag),
            "validator tag must be one of the enum: {tag}"
        );
    }

    handle.abort();
    let _ = std::fs::remove_file(&sock);
}

// Priority order preserved: long credentials (private_key/jwt/api_key/conn_string/
// password) must come before the bare-number pattern (id_number).
// First match wins on overlap, preventing a short pattern from swallowing a long
// credential's substring / a bare-number pattern from swallowing a credential's
// labeled value.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redact_patterns_dump_preserves_priority_order() {
    let (db, sock) = ensure_env();
    let handle = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    let res = call(&sock, "guard.redact.patterns.dump");
    let patterns = res["patterns"].as_array().unwrap();
    let names: Vec<&str> = patterns
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();

    // Credential-labeled patterns must come before the bare-number pattern
    // (id_number is now ordered before credit_card — issue #13: the GB validation
    // must swallow all 18 characters first, preventing credit_card from consuming
    // the 17 leading digits and leaving a dangling trailing character).
    let pos_private_key = names.iter().position(|n| *n == "private_key").unwrap();
    let pos_jwt = names.iter().position(|n| *n == "jwt").unwrap();
    let pos_api_key = names.iter().position(|n| *n == "api_key").unwrap();
    let pos_conn_string = names.iter().position(|n| *n == "conn_string").unwrap();
    let pos_password = names.iter().position(|n| *n == "password").unwrap();
    let pos_id_number = names.iter().position(|n| *n == "id_number").unwrap();

    assert!(
        pos_id_number > pos_private_key,
        "id_number must come after private_key"
    );
    assert!(pos_id_number > pos_jwt, "id_number must come after jwt");
    assert!(
        pos_id_number > pos_api_key,
        "id_number must come after api_key"
    );
    assert!(
        pos_id_number > pos_conn_string,
        "id_number must come after conn_string"
    );
    assert!(
        pos_id_number > pos_password,
        "id_number must come after password"
    );

    // email must come after conn_string (pass@host must be consumed by conn_string
    // first, preventing it from being swallowed by email).
    let pos_email = names.iter().position(|n| *n == "email").unwrap();
    assert!(
        pos_email > pos_conn_string,
        "email must come after conn_string (prevents pass@host from being swallowed by email)"
    );

    handle.abort();
    let _ = std::fs::remove_file(&sock);
}

// Validator tag exact mapping: only ipv4/aws_secret/credit_card/phone/id_number
// carry algorithm validators, the rest are none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redact_patterns_dump_validator_tags_exact() {
    let (db, sock) = ensure_env();
    let handle = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    let res = call(&sock, "guard.redact.patterns.dump");
    let patterns = res["patterns"].as_array().unwrap();
    let tag_of = |name: &str| -> &str {
        patterns
            .iter()
            .find(|p| p["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("pattern {name} missing"))["validator"]
            .as_str()
            .unwrap()
    };

    assert_eq!(tag_of("ipv4"), "ipv4", "ipv4 must carry the ipv4 validator");
    assert_eq!(
        tag_of("aws_secret"),
        "aws_secret",
        "aws_secret must carry the aws_secret validator"
    );
    assert_eq!(
        tag_of("credit_card"),
        "luhn",
        "credit_card must carry the luhn validator"
    );
    assert_eq!(
        tag_of("phone"),
        "phone",
        "phone must carry the phone validator"
    );
    assert_eq!(
        tag_of("id_number"),
        "id_card",
        "id_number must carry the id_card validator (issue #13 GB 11643 validation)"
    );
    // Patterns without an algorithm validator must be tagged none.
    for n in [
        "private_key",
        "jwt",
        "oauth_bearer",
        "api_key",
        "conn_string",
        "password",
        "secret_kv",
        "env_kv",
        "netrc",
        "email",
    ] {
        assert_eq!(
            tag_of(n),
            "none",
            "{n} must be tagged none (no algorithm validator)"
        );
    }

    handle.abort();
    let _ = std::fs::remove_file(&sock);
}
