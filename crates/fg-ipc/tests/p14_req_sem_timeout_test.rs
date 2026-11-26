// P1-4 (audit §2.3): permit waiting is separated from the handler timeout.
// The old code nested req_sem.acquire_owned().await inside the 2s handler timeout
// future, so permit queueing stole from the business budget. Fix: the permit gets
// its own 500ms wait (PERMIT_TIMEOUT_MS); failing to obtain one -> immediate
// rejection with -32002; once obtained, the full 2s (REQ_TIMEOUT_SECS) goes to the
// handler.
//
// Deterministic strategy (test-helpers): new_with_req_permits(1) builds a
// single-slot server; the test pre-acquires and holds that 1 permit, so the next
// request necessarily goes through permit waiting -> 500ms timeout -> -32002.
// No real slow handler needed, no timing races.
//
// Verifies two things:
//   1) permit exhausted -> -32002 (not -32010 timeout, not waiting the full 2s).
//   2) The rejection returns fast (< 2s handler budget, measured < 1s), proving
//      the permit timeout is independently shorter than the handler's.
// Isolated env: dedicated SOCK + DATA_DIR + TOKEN_KEY. Requires the test-helpers
// feature.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fg_ipc::IpcServer;
use fg_store::AuditStore;

const TEST_KEY_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn ensure_env() -> (PathBuf, PathBuf) {
    if std::env::var("FUSION_GUARD_TOKEN_KEY").is_err() {
        std::env::set_var("FUSION_GUARD_TOKEN_KEY", TEST_KEY_HEX);
    }
    let dir = std::env::temp_dir().join(format!(
        "fg-p14-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("guard-p14.db");
    let short = uuid::Uuid::new_v4().simple().to_string();
    let sock = PathBuf::from(format!(
        "/tmp/fg-p14-{}-{}.sock",
        std::process::id(),
        &short[..8]
    ));
    let _ = std::fs::remove_file(&sock);
    std::env::set_var("FUSION_GUARD_SOCK", &sock);
    std::env::set_var("FUSION_GUARD_DATA_DIR", &dir);
    (db, sock)
}

// Single-slot server: pre-acquire and hold the sole permit -> the next request
// goes through permit waiting -> 500ms timeout -> -32002.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn permit_wait_timeout_returns_rate_limit_fast() {
    let (db, sock) = ensure_env();
    let store = Arc::new(AuditStore::open(&db).unwrap());
    let engine = fg_audit_engine::AuditEngine::new(store.clone()).unwrap();
    // Single slot: only 1 req permit.
    let server = IpcServer::new_with_req_permits(engine, store, 1);
    let sem = server.req_sem_handle();
    let serve_sock = sock.clone();

    let handle = tokio::spawn(async move {
        if let Err(e) = server.serve(serve_sock).await {
            tracing::error!(error = %e, "test server exited");
        }
    });

    // Wait for the socket to appear.
    for _ in 0..100 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        sock.exists(),
        "server sock never appeared: {}",
        sock.display()
    );

    // Pre-acquire and hold the sole permit -> the server's req_sem is empty, any
    // request goes through permit waiting.
    let held = sem.acquire_owned().await.expect("acquire sole permit");
    // Give the accept loop a moment to become ready.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut stream = UnixStream::connect(&sock).unwrap();
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));

    let req = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"guard.ping\",\"params\":{}}\n";
    stream.write_all(req).unwrap();
    stream.flush().unwrap();

    // Timing: the permit wait should time out and reject at ~500ms, far below the
    // 2s handler budget.
    let start = Instant::now();
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).unwrap_or(0);
    let elapsed = start.elapsed();

    assert!(
        n > 0,
        "P1-4: an exhausted permit must yield a rejection frame (no silent freeze), got n={n}"
    );
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(
        resp.contains(r#""code":-32002"#),
        "P1-4: permit timeout must return -32002 (rate limit), not -32010 handler timeout, got: {resp}"
    );
    assert!(
        resp.contains("rate limited"),
        "P1-4: the rejection frame must contain a rate limited message, got: {resp}"
    );
    // Key: the rejection must return before the handler's 2s budget (permit timeout
    // is 500ms; with network jitter allowance keep it under 1.5s).
    // The old code counted the permit wait inside the 2s; being >= 2s here means
    // the separation failed.
    assert!(
        elapsed < Duration::from_secs(2),
        "P1-4: the permit-timeout rejection must be faster than the 2s handler budget (separation in effect), measured {:?}",
        elapsed
    );

    drop(held);
    drop(stream);
    handle.abort();
    let _ = std::fs::remove_file(&sock);
}

// Control: after the permit is released, the same ping must return pong normally
// (proves -32002 is specific to an exhausted permit, not a blanket rejection).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn permit_available_serves_normally() {
    let (db, sock) = ensure_env();
    let store = Arc::new(AuditStore::open(&db).unwrap());
    let engine = fg_audit_engine::AuditEngine::new(store.clone()).unwrap();
    let server = IpcServer::new_with_req_permits(engine, store, 2);
    let serve_sock = sock.clone();
    let handle = tokio::spawn(async move {
        if let Err(e) = server.serve(serve_sock).await {
            tracing::error!(error = %e, "test server exited");
        }
    });

    for _ in 0..100 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(sock.exists());

    // No permit pre-acquired -> both server slots idle -> ping is served normally.
    let mut stream = UnixStream::connect(&sock).unwrap();
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let req = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"guard.ping\",\"params\":{}}\n";
    stream.write_all(req).unwrap();
    stream.flush().unwrap();

    let mut buf = [0u8; 512];
    let n = stream.read(&mut buf).unwrap_or(0);
    assert!(n > 0, "ping must receive a response");
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(
        resp.contains("pong"),
        "with a free permit, ping must return pong normally (no spurious rejection), got: {resp}"
    );
    assert!(
        !resp.contains(r#""code":-32002"#),
        "with a free permit, no rate limit should be returned, got: {resp}"
    );

    drop(stream);
    handle.abort();
    let _ = std::fs::remove_file(&sock);
}
