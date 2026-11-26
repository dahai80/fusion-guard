// fg-pyo3 integration tests — UDS client round trip against a real fg-ipc server
// No Python dependency (pure-Rust UdsClient wire contract tests); the PyO3 layer is covered by maturin build + Python smoke
// Isolated env: dedicated SOCK + DATA_DIR + TOKEN_KEY (daemon interaction must be isolated to avoid polluting the local guard)

use std::path::PathBuf;
use std::sync::Arc;

use fg_core::{CheckStage, GuardVerdict, RiskLevel, SafetyAction};
use fg_ipc::IpcServer;
use fg_store::AuditStore;

const TEST_KEY_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn ensure_env() -> (PathBuf, PathBuf) {
    if std::env::var("FUSION_GUARD_TOKEN_KEY").is_err() {
        std::env::set_var("FUSION_GUARD_TOKEN_KEY", TEST_KEY_HEX);
    }
    let dir = std::env::temp_dir().join(format!(
        "fg-pyo3-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("guard-pyo3.db");
    // UDS SUN_LEN limit (~104 bytes) — the socket path must be short, directly under /tmp, not in a long temp_dir subdirectory
    // Unique socket per test (no collisions between parallel tests): 8-character uuid prefix
    let short = uuid::Uuid::new_v4().simple().to_string();
    let sock = PathBuf::from(format!(
        "/tmp/fg-pyo3-{}-{}.sock",
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

// Poll 500 × 10ms = 5s (the old 100×10ms=1s hit server spawn scheduling delays >1s under
// heavy workspace concurrency → false panic on the socket never appearing). With worker_threads=2
// the server task competes with the client for scheduling; startup is slower under compile/concurrency pressure, so 5s leaves ample margin.
async fn wait_for_sock(sock: &std::path::Path) {
    for _ in 0..500 {
        if sock.exists() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("server sock never appeared: {}", sock.display());
}

// Flake guard: the socket file exists but server.serve's accept loop has not been scheduled by a worker yet
// (heavy workspace concurrency, multi_thread worker_threads=2 scheduling jitter) → the client connects successfully but
// the first request times out on read after 2s (-32010). Retry transient -32010 (connect/read/write timeout) up to 3 × 200ms
// to give the accept loop a chance to be polled. Non-transient errors (stale epoch -32003, parse -32700) are returned as-is without retry.
fn call_retry(
    client: &fg_pyo3::UdsClient,
    method: &str,
    params: serde_json::Value,
) -> serde_json::Value {
    for attempt in 0..3u8 {
        match client.call(method, params.clone()) {
            Ok(v) => return v,
            Err(e) if e.code == -32010 && attempt < 2 => {
                eprintln!(
                    "transient -32010 (attempt {}): {}, retry in 200ms",
                    attempt + 1,
                    e.message
                );
                std::thread::sleep(std::time::Duration::from_millis(200));
                continue;
            }
            Err(e) => panic!(
                "call {method} failed (no retry left): code={} {}",
                e.code, e.message
            ),
        }
    }
    unreachable!()
}

// Same as call_retry, but for calls expected to fail (e.g. stale_epoch -32003). Retries transient -32010
// (connect/read timeout); non--32010 errors return immediately (preserving real business errors like -32003 for assertions).
fn call_retry_err(
    client: &fg_pyo3::UdsClient,
    method: &str,
    params: serde_json::Value,
) -> fg_pyo3::RpcError {
    for attempt in 0..3u8 {
        match client.call(method, params.clone()) {
            Ok(_) => panic!("call {method} unexpectedly succeeded (expected error)"),
            Err(e) if e.code == -32010 && attempt < 2 => {
                eprintln!(
                    "transient -32010 (attempt {}): {}, retry in 200ms",
                    attempt + 1,
                    e.message
                );
                std::thread::sleep(std::time::Duration::from_millis(200));
                continue;
            }
            Err(e) => return e,
        }
    }
    unreachable!()
}

// multi_thread: UdsClient.call is synchronous blocking (std UnixStream); blocking a current-thread runtime
// would starve the server.serve task on the same runtime (accept never polled) → read timeout EAGAIN.
// multi_thread lets the server task run on another worker, concurrent with the blocking client.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ping_roundtrip() {
    let (db, sock) = ensure_env();
    let handle = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    let sock_for_cleanup = sock.clone();
    let client = fg_pyo3::UdsClient::new(sock);
    let res = call_retry(&client, "guard.ping", serde_json::json!({}));
    assert_eq!(res["pong"], true);
    assert!(res["rules_epoch"].as_u64().is_some());

    handle.abort();
    let _ = std::fs::remove_file(&sock_for_cleanup);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn evaluate_block_returns_verdict() {
    let (db, sock) = ensure_env();
    let handle = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    let sock_for_cleanup = sock.clone();
    let client = fg_pyo3::UdsClient::new(sock);
    let res = call_retry(
        &client,
        "guard.evaluate",
        serde_json::json!({ "action": "evaluate", "content": "rm -rf /", "caller_epoch": 0 }),
    );
    // C11/P0-G7: server serde rename_all=lowercase → "block"/"l4" (not PascalCase).
    assert_eq!(res["action"], "block");
    assert_eq!(res["risk_level"], "l4");

    handle.abort();
    let _ = std::fs::remove_file(&sock_for_cleanup);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_epoch_rejected() {
    let (db, sock) = ensure_env();
    let handle = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    let sock_for_cleanup = sock.clone();
    let client = fg_pyo3::UdsClient::new(sock);
    let err = call_retry_err(
        &client,
        "guard.evaluate",
        serde_json::json!({ "action": "evaluate", "content": "ls", "caller_epoch": 999 }),
    );
    assert_eq!(err.code, -32003);

    handle.abort();
    let _ = std::fs::remove_file(&sock_for_cleanup);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_verify_roundtrip() {
    let (db, sock) = ensure_env();
    let handle = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    let sock_for_cleanup = sock.clone();
    let client = fg_pyo3::UdsClient::new(sock);
    // Run evaluate first to trigger an audit write
    let _ = call_retry(
        &client,
        "guard.evaluate",
        serde_json::json!({ "action": "evaluate", "content": "rm -rf /x", "caller_epoch": 0 }),
    );
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let res = call_retry(&client, "guard.audit.verify", serde_json::json!({}));
    // P0-5: the response is AllChainsVerification (audit/tcc/rules/dead_letter subchains + top-level tampered).
    // The audit subchain has at least 1 row (evaluate above persisted), all chains tampered=false.
    assert!(res["audit"]["total_rows"].as_u64().unwrap() >= 1);
    assert_eq!(res["tampered"], false);
    assert_eq!(res["audit"]["tampered"], false);
    assert_eq!(res["tcc"]["tampered"], false);
    assert_eq!(res["rules"]["tampered"], false);
    assert_eq!(res["dead_letter"]["tampered"], false);

    handle.abort();
    let _ = std::fs::remove_file(&sock_for_cleanup);
}

// P2-4 (audit §3.6): UdsClient connection pool — persistent connection reuse + transparent reconnect.
// The server conn_loop already loops over multiple requests per connection (read→dispatch→write, disconnects only on EOF);
// the client UdsClient holds a Mutex<Option<UnixStream>> reused stream; on IO error (server restart/deadline disconnect)
// → drop the old stream, reconnect, retry once, invisible to the caller. This test verifies two points:
//   1) the same client's repeated calls reuse the connection, all succeeding (reuse does not corrupt the wire).
//   2) after a server restart, the persistent stream is dead → the first call_once fails (read EOF) → clear the stream, reconnect → the second call succeeds (transparent self-healing).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p24_persistent_conn_reuse_and_reconnect() {
    let (db, sock) = ensure_env();

    // Server A
    let handle_a = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    let client = fg_pyo3::UdsClient::new(sock.clone());

    // (1) Same client, repeated calls reusing the connection — 5 pings all ok, proving reuse does not corrupt the wire.
    for i in 0..5u8 {
        let res = call_retry(&client, "guard.ping", serde_json::json!({}));
        assert_eq!(res["pong"], true, "reuse call #{i} must succeed");
        assert!(
            res["rules_epoch"].as_u64().is_some(),
            "reuse call #{i} must carry an epoch"
        );
    }

    // (2) Restart the server: abort A, start a new B (same sock, serve rebinds).
    //     The client's persistent stream is connected to A's listener; A abort → peer EOF → the stream is dead.
    //     The next call_once fails on read → clear the stream → reconnect and retry once → connects to B successfully (transparent self-healing).
    handle_a.abort();
    // A's abort does not delete the sock file; B's serve will remove_file + rebind. Before B appears the old file may still exist,
    // so wait_for_sock returns immediately on the old file → connect to the old (closed) endpoint fails -32010 → call_retry retries until B binds.
    let handle_b = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    // After the restart ping still works — proving the dead stream was detected + cleared + reconnected, with the server restart invisible to the caller.
    // call_retry's internal transient -32010 retries cover the restart race (connect to the old endpoint failing before B binds).
    let res = call_retry(&client, "guard.ping", serde_json::json!({}));
    assert_eq!(
        res["pong"], true,
        "must reconnect transparently after server restart (P2-4)"
    );

    handle_b.abort();
    let _ = std::fs::remove_file(&sock);
}

// Issue #36: NativeGuardClient could not authenticate against a shared-secret daemon — the client never sent params["secret"].
// Fix: UdsClient holds Option<String> shared_secret; call() injects params["secret"] into non-ping requests.
// A mock UDS server (std UnixListener) asserts per request whether the secret is present on the wire — ping does not inject (the server
// is open to any peer), non-ping injects; a secret-less client does not inject (behavior unchanged when the dev daemon has no secret).
fn spawn_mock_server(
    sock: std::path::PathBuf,
    n_requests: usize,
) -> std::thread::JoinHandle<Vec<bool>> {
    std::thread::spawn(move || {
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        // Signal as soon as bind completes (client side polls the sock file, avoiding a connect-before-bind race).
        let ready = sock.with_extension("ready");
        std::fs::write(&ready, b"ok").unwrap();
        let mut saw_secret: Vec<bool> = Vec::new();
        let (mut stream, _) = listener.accept().unwrap();
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
        let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
        for _ in 0..n_requests {
            let mut line = Vec::new();
            use std::io::BufRead;
            if reader.read_until(0x0Au8, &mut line).is_err() {
                break;
            }
            line.pop(); // framing \n
            let req: serde_json::Value = serde_json::from_slice(&line).unwrap();
            saw_secret.push(req["params"]["secret"].is_string());
            let resp = serde_json::json!({
                "jsonrpc": "2.0",
                "id": req["id"],
                "result": { "pong": true },
            });
            let mut bytes = serde_json::to_vec(&resp).unwrap();
            bytes.push(0x0Au8);
            use std::io::Write;
            let _ = stream.write_all(&bytes);
        }
        saw_secret
    })
}

// Poll-wait for the mock server's bind-complete signal (sock.with_extension("ready") file) to avoid races.
fn wait_mock_ready(sock: &std::path::Path) {
    let ready = sock.with_extension("ready");
    for _ in 0..500 {
        if ready.exists() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("mock server never became ready: {}", ready.display());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn secret_injected_on_non_ping_only() {
    let short = uuid::Uuid::new_v4().simple().to_string();
    let sock = std::path::PathBuf::from(format!(
        "/tmp/fg-pyo3-{}-{}.sock",
        std::process::id(),
        &short[..8]
    ));
    let _ = std::fs::remove_file(&sock);

    // Two requests: evaluate (inject) → ping (no inject). Arrive in order on the same persistent connection.
    let mock = spawn_mock_server(sock.clone(), 2);
    wait_mock_ready(&sock);

    let client = fg_pyo3::UdsClient::new_with_secret(sock.clone(), Some("s3cret".into()));
    let res = client
        .call("guard.evaluate", serde_json::json!({ "content": "ls" }))
        .expect("evaluate with secret");
    assert_eq!(res["pong"], true);
    let res = client
        .call("guard.ping", serde_json::json!({}))
        .expect("ping");
    assert_eq!(res["pong"], true);

    let saw = mock.join().unwrap();
    assert_eq!(
        saw,
        vec![true, false],
        "non-ping requests must carry params[\"secret\"], ping must not carry it"
    );
    let _ = std::fs::remove_file(&sock);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_secret_param_when_client_unset() {
    let short = uuid::Uuid::new_v4().simple().to_string();
    let sock = std::path::PathBuf::from(format!(
        "/tmp/fg-pyo3-{}-{}.sock",
        std::process::id(),
        &short[..8]
    ));
    let _ = std::fs::remove_file(&sock);

    let mock = spawn_mock_server(sock.clone(), 1);
    wait_mock_ready(&sock);

    let client = fg_pyo3::UdsClient::new(sock.clone());
    let res = client
        .call("guard.evaluate", serde_json::json!({ "content": "ls" }))
        .expect("evaluate without secret");
    assert_eq!(res["pong"], true);

    let saw = mock.join().unwrap();
    assert_eq!(
        saw,
        vec![false],
        "secret-less client does not inject (dev behavior unchanged)"
    );
    let _ = std::fs::remove_file(&sock);
}

// Prevent unused import warnings (verdict helper kept for future extension)
#[allow(dead_code)]
fn _verdict() -> GuardVerdict {
    GuardVerdict {
        action: SafetyAction::Allow,
        risk_level: RiskLevel::L1,
        reason: "x".into(),
        stage: CheckStage::Regex,
        requires_approval: false,
        redacted_content: None,
        seatbelt_required: false,
        action_id: None,
        verdict_epoch: 1,
        verdict_ttl_secs: 30,
        inferred_category: "clean".into(),
        category_hint: None,
    }
}
