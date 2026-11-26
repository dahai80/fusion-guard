// P1-7 (audit §P1-7): independent rate limiting for slow tasks (slow_sem), so
// large-table verify / federated network calls cannot fill the blocking pool and
// starve the interception path.
//
// For slow methods (guard.audit.verify / guard.cluster.*) the 2s timeout cannot
// cancel an in-flight spawn_blocking task, so slow requests can fill the blocking
// thread pool (max_blocking_threads=64) -> starve the interception path
// (guard.evaluate). Fix: slow methods additionally acquire a slow_sem permit
// (independent 500ms timeout, <= fast req_sem slot count), held until the task
// truly completes, hard-limiting concurrent slow tasks and preserving fast
// req_sem slots for interception.
//
// Verifies three points (deterministic, no real slow tasks needed):
//   1) slow_sem full -> slow method (guard.audit.verify) returns -32002 (rate
//      limit), not -32010 timeout.
//   2) The slow-method rejection is faster than the 2s handler budget (slow
//      permit timeout of 500ms is independent).
//   3) Fast methods (guard.ping) are unaffected by slow_sem — with slow_sem full,
//      ping still returns pong normally (the two limiters are independent).
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
        "fg-p17-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("guard-p17.db");
    let short = uuid::Uuid::new_v4().simple().to_string();
    let sock = PathBuf::from(format!(
        "/tmp/fg-p17-{}-{}.sock",
        std::process::id(),
        &short[..8]
    ));
    let _ = std::fs::remove_file(&sock);
    std::env::set_var("FUSION_GUARD_SOCK", &sock);
    std::env::set_var("FUSION_GUARD_DATA_DIR", &dir);
    (db, sock)
}

// Single slow-slot server: pre-acquire and hold the sole slow permit -> the next
// slow method goes through slow_sem waiting -> 500ms timeout -> -32002.
// req_sem keeps its default 16 (empty), ensuring only the slow path is limited and
// avoiding confusion with fast req_sem contention.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_sem_full_rejects_slow_method_fast() {
    let (db, sock) = ensure_env();
    let store = Arc::new(AuditStore::open(&db).unwrap());
    let engine = fg_audit_engine::AuditEngine::new(store.clone()).unwrap();
    // Single slow slot; req_sem default 16 (empty, not limited).
    let server = IpcServer::new_with_slow_permits(engine, store, 1);
    let slow_sem = server.slow_sem_handle();
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
    assert!(
        sock.exists(),
        "server sock never appeared: {}",
        sock.display()
    );

    // Pre-acquire and hold the sole slow permit -> the server's slow_sem is empty,
    // slow methods go through slow_sem waiting.
    let held = slow_sem
        .acquire_owned()
        .await
        .expect("acquire sole slow permit");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut stream = UnixStream::connect(&sock).unwrap();
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));

    // guard.audit.verify is a slow method (is_slow=true) -> acquires slow_sem
    // first -> full, waits 500ms -> -32002.
    let req = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"guard.audit.verify\",\"params\":{}}\n";
    stream.write_all(req).unwrap();
    stream.flush().unwrap();

    let start = Instant::now();
    let mut buf = [0u8; 512];
    let n = stream.read(&mut buf).unwrap_or(0);
    let elapsed = start.elapsed();

    assert!(
        n > 0,
        "P1-7: a full slow_sem must yield a rejection frame (no silent freeze), got n={n}"
    );
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(
        resp.contains(r#""code":-32002"#),
        "P1-7: slow permit timeout must return -32002 (rate limit), not -32010 timeout, got: {resp}"
    );
    // The slow-method rejection must be faster than the 2s handler budget (slow
    // permit timeout of 500ms is independent; keep margin under 1.5s).
    assert!(
        elapsed < Duration::from_secs(2),
        "P1-7: the slow permit timeout rejection must be faster than the 2s handler budget (independent), measured {:?}",
        elapsed
    );

    drop(held);
    drop(stream);
    handle.abort();
    let _ = std::fs::remove_file(&sock);
    if let Ok(data_dir) = std::env::var("FUSION_GUARD_DATA_DIR") {
        let _ = std::fs::remove_dir_all(&data_dir);
    }
}

// Control: with slow_sem full, fast methods (guard.ping) are unaffected and still
// return pong normally.
// Proves the two limiters are independent — slow_sem only constrains slow methods;
// with fast req_sem empty, fast methods are served normally.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_sem_full_does_not_block_fast_method() {
    let (db, sock) = ensure_env();
    let store = Arc::new(AuditStore::open(&db).unwrap());
    let engine = fg_audit_engine::AuditEngine::new(store.clone()).unwrap();
    let server = IpcServer::new_with_slow_permits(engine, store, 1);
    let slow_sem = server.slow_sem_handle();
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

    // Pre-acquire and hold the sole slow permit -> slow_sem full. But ping is a
    // fast method (is_slow=false), going through req_sem (empty).
    let _held = slow_sem
        .acquire_owned()
        .await
        .expect("acquire sole slow permit");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut stream = UnixStream::connect(&sock).unwrap();
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let req = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"guard.ping\",\"params\":{}}\n";
    stream.write_all(req).unwrap();
    stream.flush().unwrap();

    let mut buf = [0u8; 512];
    let n = stream.read(&mut buf).unwrap_or(0);
    assert!(n > 0, "P1-7: ping must receive a response");
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(
        resp.contains("pong"),
        "P1-7: with slow_sem full, the fast method ping must still return pong normally (independent limiters), got: {resp}"
    );
    assert!(
        !resp.contains(r#""code":-32002"#),
        "P1-7: fast methods must not be rate limited by a full slow_sem, got: {resp}"
    );

    drop(stream);
    handle.abort();
    let _ = std::fs::remove_file(&sock);
    if let Ok(data_dir) = std::env::var("FUSION_GUARD_DATA_DIR") {
        let _ = std::fs::remove_dir_all(&data_dir);
    }
}

// Control: with slow_sem empty, slow methods are served normally (after the permit
// is released, verify returns a result, not -32002).
// Proves -32002 is specific to a full slow_sem, not a blanket rejection of slow
// methods.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_sem_available_serves_slow_method() {
    let (db, sock) = ensure_env();
    let store = Arc::new(AuditStore::open(&db).unwrap());
    let engine = fg_audit_engine::AuditEngine::new(store.clone()).unwrap();
    let server = IpcServer::new_with_slow_permits(engine, store, 2);
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

    // No slow permit pre-acquired -> slow_sem empty -> the slow method verify is
    // served normally (verify on an empty store returns quickly).
    let mut stream = UnixStream::connect(&sock).unwrap();
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let req = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"guard.audit.verify\",\"params\":{}}\n";
    stream.write_all(req).unwrap();
    stream.flush().unwrap();

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).unwrap_or(0);
    assert!(n > 0, "P1-7: verify must receive a response");
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(
        resp.contains("\"result\"") || resp.contains("tampered"),
        "P1-7: with slow_sem empty, verify must return a normal result (including the tampered field), not a rate limit, got: {resp}"
    );
    assert!(
        !resp.contains(r#""code":-32002"#),
        "P1-7: with slow_sem empty, verify must not be rate limited, got: {resp}"
    );

    drop(stream);
    handle.abort();
    let _ = std::fs::remove_file(&sock);
    if let Ok(data_dir) = std::env::var("FUSION_GUARD_DATA_DIR") {
        let _ = std::fs::remove_dir_all(&data_dir);
    }
}
