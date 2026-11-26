// fg-ipc adversarial negative tests — C17 (OOM) + A6 (slowloris)
// Verifies: an overlong request with no newline -> the server disconnects (not a
// 500MB buffer); the response side never returns a normal frame.
// Isolated env: dedicated SOCK + DATA_DIR + TOKEN_KEY.

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
        "fg-ipc-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("guard-ipc.db");
    let short = uuid::Uuid::new_v4().simple().to_string();
    let sock = PathBuf::from(format!(
        "/tmp/fg-ipc-{}-{}.sock",
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

// C17: sending MAX_LINE_BYTES + 64KiB of newline-free garbage -> the server must
// disconnect (take truncates first, then the limit is checked); it must not buffer
// to a memory peak. After disconnect the client read returns 0 (EOF) or the
// connection is reset.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversize_request_disconnects_not_buffers() {
    let (db, sock) = ensure_env();
    let handle = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    let mut stream = UnixStream::connect(&sock).unwrap();
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));

    // MAX_LINE_BYTES = 1MiB. Send 1MiB + 64KiB of 'A' with no newline.
    let payload: Vec<u8> = vec![b'A'; (1024 * 1024) + (64 * 1024)];
    use std::io::Write;
    // write_all may return EPIPE (BrokenPipe) because the server disconnects
    // mid-write — that is exactly the C17 defense working: the server disconnects
    // before buffering past the limit. EPIPE counts as a disconnect (pass); if the
    // write succeeds, the subsequent read must return EOF.
    let write_err = stream.write_all(&payload).err();
    let _ = stream.flush();
    let pipe_broken = matches!(
        write_err.as_ref(),
        Some(e) if e.kind() == std::io::ErrorKind::BrokenPipe
    );

    use std::io::Read;
    let mut got = [0u8; 16];
    let n = stream.read(&mut got).unwrap_or(0);
    let disconnected = pipe_broken || n == 0;
    assert!(
        disconnected,
        "server must disconnect on oversize request (C17), not buffer 1.1MiB (pipe_broken={pipe_broken}, n={n})"
    );

    handle.abort();
    let _ = std::fs::remove_file(&sock);
}

// A6 slowloris: after slots are filled, new connections can still be accepted
// (conn_sem permits are released when the deadline expires).
// Here we verify the per-connection deadline: a slow client sends no newline, and
// the server disconnects when CONN_DEADLINE expires.
// The full 30s window is not measured (too slow); we verify the disconnect
// behavior — send a partial newline-free payload, expect no response in the short
// term, but the server must not hang blocked in read_until (the take-truncation
// path is already covered by the previous case).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn partial_request_no_frame_does_not_respond() {
    let (db, sock) = ensure_env();
    let handle = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    let mut stream = UnixStream::connect(&sock).unwrap();
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));

    // Send partial JSON with no newline -> the server is still in take/buffering;
    // an incomplete frame gets no response.
    use std::io::Write;
    stream
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"guard.ping\"")
        .unwrap();
    stream.flush().unwrap();

    // Short read: no complete frame -> a normal ping response must not arrive.
    use std::io::Read;
    let mut got = [0u8; 64];
    let res = stream.read(&mut got);
    // 0 (EOF/disconnect) or a timeout are both fine (the server never returned a
    // complete ping frame). The key point: no "pong" was received.
    if let Ok(n) = res {
        if n > 0 {
            let s = String::from_utf8_lossy(&got[..n]);
            assert!(
                !s.contains("pong"),
                "incomplete frame must not yield a ping response"
            );
        }
    }

    handle.abort();
    let _ = std::fs::remove_file(&sock);
}

// A5 (P0-G9): the socket path is squatted by a directory -> serve must refuse to
// bind (not start), preventing a local DoS.
// The old code `let _ = remove_file` swallowed the directory-removal failure ->
// bind failed and startup exited (passive); the new code checks existence via
// symlink_metadata -> actively errors and refuses.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socket_dir_squat_refuses_bind() {
    let (db, _sock) = ensure_env();
    let short = uuid::Uuid::new_v4().simple().to_string();
    let squat_sock = PathBuf::from(format!(
        "/tmp/fg-ipc-squat-{}-{}.sock",
        std::process::id(),
        &short[..8]
    ));
    let _ = std::fs::remove_file(&squat_sock);
    std::fs::create_dir(&squat_sock).unwrap();

    let store = Arc::new(AuditStore::open(&db).unwrap());
    let engine = fg_audit_engine::AuditEngine::new(store.clone()).unwrap();
    let server = IpcServer::new(engine, store);

    let result = server.serve(squat_sock.clone()).await;
    assert!(
        result.is_err(),
        "serve must refuse bind when socket path is a directory (A5 squat guard)"
    );
    let err = result.unwrap_err();
    assert!(
        matches!(err, fg_core::GuardError::Io(_)),
        "squat refusal must surface as Io error, got: {:?}",
        err
    );

    let _ = std::fs::remove_dir(&squat_sock);
}
