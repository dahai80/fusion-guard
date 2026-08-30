// fg-pyo3 集成测试 — UDS 客户端对真实 fg-ipc server 往返
// 不依赖 Python (纯 Rust 测 UdsClient wire contract); PyO3 层由 maturin build + Python smoke 覆盖
// 隔离 env: 独立 SOCK + DATA_DIR + TOKEN_KEY (测守护进程交互必须隔离, 防污染本机 guard)

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
    // UDS SUN_LEN 限制 (~104 字节) — socket 须短路径, 放 /tmp 直下, 非长 temp_dir 子目录
    // 每测试唯一 socket (并行测试不冲突): 8 字符 uuid 前缀
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

// 轮询 500 次 × 10ms = 5s (原 100×10ms=1s 在 workspace 高并发负载下 server spawn
// 调度延迟 >1s → 测得 socket 未出现假 panic)。worker_threads=2 下 server task 与 client
// 竞争调度, 编译/并发压力时启动更慢, 5s 给足余量。
async fn wait_for_sock(sock: &std::path::Path) {
    for _ in 0..500 {
        if sock.exists() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("server sock never appeared: {}", sock.display());
}

// flake 兜底: socket 文件已出现但 server.serve 的 accept 循环尚未被 worker 调度
// (workspace 高并发负载, multi_thread worker_threads=2 调度抖动) → 客户端 connect 成功但
// 首请求 read 2s 超时 (-32010)。重试瞬态 -32010 (connect/read/write 超时) 3 次 × 200ms
// 给 accept 循环被 poll 的机会。非瞬态错 (stale epoch -32003, parse -32700) 不重试原样返。
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

// 同 call_retry, 但用于期望失败的调用 (如 stale_epoch -32003)。重试瞬态 -32010
// (connect/read 超时), 非 -32010 错立即返 (保留真实业务错如 -32003 供断言)。
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

// multi_thread: UdsClient.call 是同步阻塞 (std UnixStream), 阻塞 current-thread runtime
// 会导致同 runtime 上的 server.serve 任务饿死 (accept 永不被 poll) → read 超时 EAGAIN。
// multi_thread 让 server 任务在另一 worker 上跑, 与阻塞客户端并发。
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
    // C11/P0-G7: 服务端 serde rename_all=lowercase → "block"/"l4" (非 PascalCase)。
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
    // 先 evaluate 触发审计落盘
    let _ = call_retry(
        &client,
        "guard.evaluate",
        serde_json::json!({ "action": "evaluate", "content": "rm -rf /x", "caller_epoch": 0 }),
    );
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let res = call_retry(&client, "guard.audit.verify", serde_json::json!({}));
    // P0-5: 响应是 AllChainsVerification (audit/tcc/rules/dead_letter 子链 + 顶层 tampered)。
    // audit 子链至少 1 行 (上面 evaluate 落盘), 全链 tampered=false。
    assert!(res["audit"]["total_rows"].as_u64().unwrap() >= 1);
    assert_eq!(res["tampered"], false);
    assert_eq!(res["audit"]["tampered"], false);
    assert_eq!(res["tcc"]["tampered"], false);
    assert_eq!(res["rules"]["tampered"], false);
    assert_eq!(res["dead_letter"]["tampered"], false);

    handle.abort();
    let _ = std::fs::remove_file(&sock_for_cleanup);
}

// P2-4 (audit §3.6): UdsClient 连接池 —— 持久连接复用 + 透明重连。
// 服务端 conn_loop 已循环处理单连接多请求 (read→dispatch→write, EOF 才断),
// 客户端 UdsClient 持 Mutex<Option<UnixStream>> 复用流; IO 错 (服务端重启/deadline 断)
// → drop 旧流重连一次重试, 调用方不感知。此测验证两点:
//   1) 同一 client 多次 call 复用连接, 全成功 (不因复用损坏 wire)。
//   2) 服务端重启后, 持久流已死 → 首次 call_once 失败 (read EOF) → 清流重连 → 第二次成功 (透明自愈)。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p24_persistent_conn_reuse_and_reconnect() {
    let (db, sock) = ensure_env();

    // 服务端 A
    let handle_a = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    let client = fg_pyo3::UdsClient::new(sock.clone());

    // (1) 同 client 多次 call 复用连接 —— ping 5 次全 ok, 证明复用不损坏 wire。
    for i in 0..5u8 {
        let res = call_retry(&client, "guard.ping", serde_json::json!({}));
        assert_eq!(res["pong"], true, "reuse call #{i} 须成功");
        assert!(
            res["rules_epoch"].as_u64().is_some(),
            "reuse call #{i} 须带 epoch"
        );
    }

    // (2) 重启服务端: abort A, 起新 B (同 sock, serve 重绑)。
    //     client 持久流连的是 A 的 listener, A abort → 对端 EOF → 流已死。
    //     下次 call_once 读失败 → 清流 → 重连一次重试 → 连 B 成功 (透明自愈)。
    handle_a.abort();
    // A abort 不删 sock 文件; B 的 serve 会 remove_file+重绑。等 B 出现前旧文件可能在,
    // wait_for_sock 见旧文件立即返 → connect 旧 (已关) 失败 -32010 → call_retry 重试到 B 绑定。
    let handle_b = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    // 重启后 ping 仍 ok —— 证明死流被检测+清空+重连, 调用方不感知服务端重启。
    // call_retry 内重试瞬态 -32010 兜底重启竞态 (B 绑定前 connect 旧失败)。
    let res = call_retry(&client, "guard.ping", serde_json::json!({}));
    assert_eq!(res["pong"], true, "服务端重启后须透明重连成功 (P2-4)");

    handle_b.abort();
    let _ = std::fs::remove_file(&sock);
}

// 防止未使用 import 警告 (verdict helper 保留供未来扩展用)
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
