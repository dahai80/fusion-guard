// P0-9 (audit §2.2): accept 与 conn_sem 解耦验证。占满 64 连接槽后, 第 65 连接须
// 立即收到拒绝帧 (非阻塞 accept 卡死)。旧码 acquire_owned().await 阻塞整个 accept
// 循环, 第 65 连接静默停滞在内核 backlog。try_acquire 满即拒 + 断连, accept 继续。

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

// MAX_CONNECTIONS=64。开 64 个空闲连接占满槽 (不发帧, 占 conn_sem 至 deadline)。
// 第 65 连接必须立即收到拒绝帧 (非阻塞, 非空响应) — P0-9 解耦生效。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sixty_fifth_conn_rejected_not_frozen() {
    let (db, sock) = ensure_env();
    let handle = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    // 占满 64 槽: 开 idle 连接, 不发帧 → 各占 conn_sem 一个 permit。
    let mut idle: Vec<UnixStream> = Vec::with_capacity(64);
    for _ in 0..64 {
        let s = UnixStream::connect(&sock).unwrap();
        let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
        idle.push(s);
    }
    // 给 accept 循环一点时间处理 64 个连接 (每个 spawn 一个 task)。
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 第 65 连接: try_acquire 满 → 拒绝帧 + 断连。
    let mut conn65 = UnixStream::connect(&sock).unwrap();
    let _ = conn65.set_read_timeout(Some(Duration::from_secs(5)));

    let mut buf = [0u8; 256];
    let n = conn65.read(&mut buf).unwrap_or(0);
    assert!(
        n > 0,
        "P0-9: 第 65 连接须收到拒绝帧 (非静默卡死), got n={n}"
    );
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(
        resp.contains(r#""code":-32010"#),
        "拒绝帧须含 -32010, got: {resp}"
    );
    assert!(
        resp.contains("connection limit"),
        "拒绝帧须含 connection limit 消息, got: {resp}"
    );

    // 清理: idle 连接 drop 释放槽; handle abort。
    drop(idle);
    drop(conn65);
    handle.abort();
    let _ = std::fs::remove_file(&sock);
}
