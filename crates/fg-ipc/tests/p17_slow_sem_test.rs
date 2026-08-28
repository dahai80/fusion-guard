// P1-7 (audit §P1-7): 慢任务独立限流 (slow_sem), 防大表 verify/联邦网络调用占满 blocking 池饿死拦截。
//
// 慢方法 (guard.audit.verify / guard.cluster.*) 2s 超时无法取消正在执行的 spawn_blocking 阻塞任务,
// 慢请求可占满 blocking 线程池 (max_blocking_threads=64) → 饿死拦截路径 (guard.evaluate)。
// 修复: 慢方法额外取 slow_sem permit (独立 500ms 超时, ≤ fast req_sem 槽数), 持到任务真完成,
// 硬限并发慢任务数, 保 fast req_sem 槽给拦截。
//
// 验证三点 (确定性, 无需真实慢任务):
//   1) slow_sem 满 → 慢方法 (guard.audit.verify) 返 -32002 (rate limit), 非 -32010 timeout。
//   2) 慢方法拒绝快于 2s handler 预算 (slow permit 超时 500ms 独立)。
//   3) 快方法 (guard.ping) 不受 slow_sem 影响 —— slow_sem 满时 ping 仍正常返 pong (两限流独立)。
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

// 单 slow 槽服务端: 预取并持有唯一 slow permit → 下一个慢方法走 slow_sem 等待 → 500ms 超时 → -32002。
// req_sem 保持默认 16 (空), 确保只 slow 路径受限, 不与 fast req_sem 竞争混淆。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_sem_full_rejects_slow_method_fast() {
    let (db, sock) = ensure_env();
    let store = Arc::new(AuditStore::open(&db).unwrap());
    let engine = fg_audit_engine::AuditEngine::new(store.clone()).unwrap();
    // 单 slow 槽; req_sem 默认 16 (空, 不受限)。
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

    // 预取并持有唯一 slow permit → 服务端 slow_sem 空, 慢方法走 slow_sem 等待。
    let held = slow_sem
        .acquire_owned()
        .await
        .expect("acquire sole slow permit");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut stream = UnixStream::connect(&sock).unwrap();
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));

    // guard.audit.verify 是慢方法 (is_slow=true) → 先取 slow_sem → 满等待 500ms → -32002。
    let req = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"guard.audit.verify\",\"params\":{}}\n";
    stream.write_all(req).unwrap();
    stream.flush().unwrap();

    let start = Instant::now();
    let mut buf = [0u8; 512];
    let n = stream.read(&mut buf).unwrap_or(0);
    let elapsed = start.elapsed();

    assert!(
        n > 0,
        "P1-7: slow_sem 满须收到拒绝帧 (非静默卡死), got n={n}"
    );
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(
        resp.contains(r#""code":-32002"#),
        "P1-7: slow permit 超时须返 -32002 (rate limit), 非 -32010 timeout, got: {resp}"
    );
    // 慢方法拒绝须快于 2s handler 预算 (slow permit 超时 500ms 独立, 留余量 < 1.5s)。
    assert!(
        elapsed < Duration::from_secs(2),
        "P1-7: slow permit 超时拒绝须快于 2s handler 预算 (独立生效), 实测 {:?}",
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

// 对照: slow_sem 满 时快方法 (guard.ping) 不受影响, 仍正常返 pong。
// 证两限流独立 —— slow_sem 只约束慢方法, fast req_sem 空则快方法正常服务。
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

    // 预取并持有唯一 slow permit → slow_sem 满。但 ping 是快方法 (is_slow=false), 走 req_sem (空)。
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
    assert!(n > 0, "P1-7: ping 须有响应");
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(
        resp.contains("pong"),
        "P1-7: slow_sem 满时快方法 ping 须正常返 pong (两限流独立), got: {resp}"
    );
    assert!(
        !resp.contains(r#""code":-32002"#),
        "P1-7: 快方法不应受 slow_sem 满影响返 rate limit, got: {resp}"
    );

    drop(stream);
    handle.abort();
    let _ = std::fs::remove_file(&sock);
    if let Ok(data_dir) = std::env::var("FUSION_GUARD_DATA_DIR") {
        let _ = std::fs::remove_dir_all(&data_dir);
    }
}

// 对照: slow_sem 空时慢方法正常服务 (释放 permit 后 verify 返 result, 非 -32002)。
// 证 -32002 是 slow_sem 满专属, 非误拒所有慢方法。
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

    // 不预取 slow permit → slow_sem 空 → 慢方法 verify 正常服务 (空库 verify 快返)。
    let mut stream = UnixStream::connect(&sock).unwrap();
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let req = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"guard.audit.verify\",\"params\":{}}\n";
    stream.write_all(req).unwrap();
    stream.flush().unwrap();

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).unwrap_or(0);
    assert!(n > 0, "P1-7: verify 须有响应");
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(
        resp.contains("\"result\"") || resp.contains("tampered"),
        "P1-7: slow_sem 空时 verify 须正常返 result (含 tampered 字段), 非 rate limit, got: {resp}"
    );
    assert!(
        !resp.contains(r#""code":-32002"#),
        "P1-7: slow_sem 空时 verify 不应返 rate limit, got: {resp}"
    );

    drop(stream);
    handle.abort();
    let _ = std::fs::remove_file(&sock);
    if let Ok(data_dir) = std::env::var("FUSION_GUARD_DATA_DIR") {
        let _ = std::fs::remove_dir_all(&data_dir);
    }
}
