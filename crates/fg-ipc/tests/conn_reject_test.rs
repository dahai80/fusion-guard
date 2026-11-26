// P0-9 (audit §2.2): verify accept is decoupled from conn_sem. After the 64
// connection slots are filled, the 65th connection must immediately receive a
// rejection frame (no blocked/frozen accept). The old code acquire_owned().await
// blocked the whole accept loop, leaving the 65th connection silently stalled in
// the kernel backlog. try_acquire rejects when full + disconnects, accept continues.

use std::io::Read;
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
        "fg-conn-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("guard-conn.db");
    let short = uuid::Uuid::new_v4().simple().to_string();
    let sock = PathBuf::from(format!(
        "/tmp/fg-conn-{}-{}.sock",
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

// MAX_CONNECTIONS=64. Open 64 idle connections to fill the slots (no frames sent,
// each holds a conn_sem permit until its deadline).
// The 65th connection must immediately receive a rejection frame (non-blocking,
// non-empty response) — P0-9 decoupling in effect.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sixty_fifth_conn_rejected_not_frozen() {
    let (db, sock) = ensure_env();
    let handle = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    // Fill the 64 slots: open idle connections, send no frames -> each holds one conn_sem permit.
    let mut idle: Vec<UnixStream> = Vec::with_capacity(64);
    for _ in 0..64 {
        let s = UnixStream::connect(&sock).unwrap();
        let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
        idle.push(s);
    }
    // Give the accept loop some time to process the 64 connections (one task spawned each).
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 65th connection: try_acquire full -> rejection frame + disconnect.
    let mut conn65 = UnixStream::connect(&sock).unwrap();
    let _ = conn65.set_read_timeout(Some(Duration::from_secs(5)));

    let mut buf = [0u8; 256];
    let n = conn65.read(&mut buf).unwrap_or(0);
    assert!(
        n > 0,
        "P0-9: the 65th connection must receive a rejection frame (no silent freeze), got n={n}"
    );
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(
        resp.contains(r#""code":-32010"#),
        "rejection frame must contain -32010, got: {resp}"
    );
    assert!(
        resp.contains("connection limit"),
        "rejection frame must contain a connection limit message, got: {resp}"
    );

    // Cleanup: dropping idle connections releases slots; abort the handle.
    drop(idle);
    drop(conn65);
    handle.abort();
    let _ = std::fs::remove_file(&sock);
}
