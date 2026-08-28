// P1-4 (audit §2.3): permit 等待与 handler 超时分离。
// 旧码 req_sem.acquire_owned().await 嵌在 2s handler timeout future 内 → permit 排队
// 偷占业务预算。修复: permit 单独 500ms 等待 (PERMIT_TIMEOUT_MS), 拿不到 → -32002 即拒;
// 拿到后 2s (REQ_TIMEOUT_SECS) 全程给 handler。
//
// 确定性策略 (test-helpers): new_with_req_permits(1) 建单槽服务端, 预取并持有那 1 个 permit,
// 后续请求必然走 permit 等待 → 500ms 超时 → -32002。无需真实慢 handler, 无时序竞态。
//
// 验证两点:
//   1) permit 等满 → -32002 (非 -32010 timeout, 非 2s 等满)。
//   2) 拒绝快速返回 (< 2s handler 预算, 实测 < 1s), 证 permit 超时独立短于 handler。
// 隔离 env: 独立 SOCK + DATA_DIR + TOKEN_KEY。需 test-helpers feature。

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

// 单槽服务端: 预取并持有唯一 permit → 下一个请求走 permit 等待 → 500ms 超时 → -32002。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn permit_wait_timeout_returns_rate_limit_fast() {
    let (db, sock) = ensure_env();
    let store = Arc::new(AuditStore::open(&db).unwrap());
    let engine = fg_audit_engine::AuditEngine::new(store.clone()).unwrap();
    // 单槽: 只 1 个 req permit。
    let server = IpcServer::new_with_req_permits(engine, store, 1);
    let sem = server.req_sem_handle();
    let serve_sock = sock.clone();

    let handle = tokio::spawn(async move {
        if let Err(e) = server.serve(serve_sock).await {
            tracing::error!(error = %e, "test server exited");
        }
    });

    // 等套接字出现。
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

    // 预取并持有唯一 permit → 服务端 req_sem 空, 任何请求走 permit 等待。
    let held = sem.acquire_owned().await.expect("acquire sole permit");
    // 给 accept 循环一点时间就绪。
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut stream = UnixStream::connect(&sock).unwrap();
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));

    let req = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"guard.ping\",\"params\":{}}\n";
    stream.write_all(req).unwrap();
    stream.flush().unwrap();

    // 计时: permit 等待应 ~500ms 超时拒, 远 < 2s handler 预算。
    let start = Instant::now();
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).unwrap_or(0);
    let elapsed = start.elapsed();

    assert!(n > 0, "P1-4: permit 满须收到拒绝帧 (非静默卡死), got n={n}");
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(
        resp.contains(r#""code":-32002"#),
        "P1-4: permit 超时须返 -32002 (rate limit), 非 -32010 handler timeout, got: {resp}"
    );
    assert!(
        resp.contains("rate limited"),
        "P1-4: 拒绝帧须含 rate limited 消息, got: {resp}"
    );
    // 关键: 拒绝须在 handler 2s 预算之前返回 (permit 超时 500ms, 含网络抖动留余量 < 1.5s)。
    // 旧码会把 permit 等待算进 2s, 这里若 ≥ 2s 说明分离失效。
    assert!(
        elapsed < Duration::from_secs(2),
        "P1-4: permit 超时拒绝须快于 2s handler 预算 (分离生效), 实测 {:?}",
        elapsed
    );

    drop(held);
    drop(stream);
    handle.abort();
    let _ = std::fs::remove_file(&sock);
}

// 对照: 释放 permit 后同一 ping 须正常返 pong (证 -32002 是 permit 满专属, 非误拒全部)。
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

    // 不预取 permit → 服务端两槽空闲 → ping 正常服务。
    let mut stream = UnixStream::connect(&sock).unwrap();
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let req = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"guard.ping\",\"params\":{}}\n";
    stream.write_all(req).unwrap();
    stream.flush().unwrap();

    let mut buf = [0u8; 512];
    let n = stream.read(&mut buf).unwrap_or(0);
    assert!(n > 0, "ping 须有响应");
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(
        resp.contains("pong"),
        "permit 空闲时 ping 须正常返 pong (非误拒), got: {resp}"
    );
    assert!(
        !resp.contains(r#""code":-32002"#),
        "permit 空闲时不应返 rate limit, got: {resp}"
    );

    drop(stream);
    handle.abort();
    let _ = std::fs::remove_file(&sock);
}
