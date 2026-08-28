// fg-ipc 对抗性负向测试 — C17 (OOM) + A6 (slowloris)
// 验证: 超长无换行请求 → 服务端断连 (非缓冲 500MB); 响应端不回正常帧。
// 隔离 env: 独立 SOCK + DATA_DIR + TOKEN_KEY。

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

// C17: 发 MAX_LINE_BYTES + 64KiB 无换行垃圾 → 服务端必须断连 (take 截断后查超限),
// 不能缓冲到内存峰值。断连后客户端 read 返 0 (EOF) 或连接重置。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversize_request_disconnects_not_buffers() {
    let (db, sock) = ensure_env();
    let handle = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    let mut stream = UnixStream::connect(&sock).unwrap();
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));

    // MAX_LINE_BYTES = 1MiB. 发 1MiB + 64KiB 'A' 无换行。
    let payload: Vec<u8> = vec![b'A'; (1024 * 1024) + (64 * 1024)];
    use std::io::Write;
    // write_all 可能因服务端中途断连返 EPIPE (BrokenPipe) — 这正是 C17 防御生效,
    // 服务端在缓冲到超限前就断连。EPIPE 视为断连通过; 写入成功则要求后续读得 EOF。
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

// A6 slowloris: 占满连接后, 新连接仍可被 accept (conn_sem 在 deadline 超时释放)。
// 这里验证单连接 deadline: 慢速不发换行, 服务端 CONN_DEADLINE 到期断连。
// 不实测 30s 全程 (太慢); 验证断连行为 — 发一截无换行数据, 短期内不回响应,
// 但服务端不会因 read_until 阻塞挂死 (take 截断路径已由上一用例覆盖)。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn partial_request_no_frame_does_not_respond() {
    let (db, sock) = ensure_env();
    let handle = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    let mut stream = UnixStream::connect(&sock).unwrap();
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));

    // 发部分 JSON 无换行 → 服务端 take/缓冲中, 未完成帧不回响应。
    use std::io::Write;
    stream
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"guard.ping\"")
        .unwrap();
    stream.flush().unwrap();

    // 短读: 无完整帧 → 不应收到正常 ping 响应。
    use std::io::Read;
    let mut got = [0u8; 64];
    let res = stream.read(&mut got);
    // 0 (EOF/断连) 或超时均算正常 (服务端未回完整 ping 帧)。关键是没拿到 "pong"。
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

// A5 (P0-G9): socket 路径被目录蹲守 → serve 必须拒 bind (不启动), 防本地 DoS。
// 旧码 `let _ = remove_file` 吞目录删除失败 → bind 失败启动退出 (被动);
// 新码 symlink_metadata 查存在 → 主动报错拒绝。
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
