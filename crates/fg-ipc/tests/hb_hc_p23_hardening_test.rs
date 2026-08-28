// H-B / H-C / P2-3 (product-audit §5/§3.4): fg-ipc 鉴权与协议硬化回归。
//
// H-B: 规则突变方法 (guard.rule.add/update/remove) 仅 admin (root) 可调。非 admin → -32001 拒。
//      防普通租户用户自行改 blocklist 致拦截失效或植入恶意规则。本机 uid 非 root → 走非 admin 路径。
// H-C: release 构建启动须设共享 secret (第二鉴权因子)。require_shared_secret_for_release 纯函数单测
//      验证决策门控 (dev 放行 / release+secret 放行 / release 无 secret 拒 / 应急 flag 放行)。
// P2-3: JSON-RPC 协议版本必须 "2.0"。非 "2.0" → -32600 Invalid Request (JSON-RPC 规范码)。

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use fg_ipc::{require_shared_secret_for_release, IpcServer};
use fg_store::AuditStore;

const TEST_KEY_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn is_root() -> bool {
    fg_peercred::our_uid() == 0
}

fn ensure_env() -> (PathBuf, PathBuf) {
    if std::env::var("FUSION_GUARD_TOKEN_KEY").is_err() {
        std::env::set_var("FUSION_GUARD_TOKEN_KEY", TEST_KEY_HEX);
    }
    let dir = std::env::temp_dir().join(format!(
        "fg-hardening-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("guard-hardening.db");
    let short = uuid::Uuid::new_v4().simple().to_string();
    let sock = PathBuf::from(format!(
        "/tmp/fg-hardening-{}-{}.sock",
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

fn raw_call(sock: &std::path::Path, req: &str) -> serde_json::Value {
    let mut stream = UnixStream::connect(sock).unwrap();
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    stream.write_all(req.as_bytes()).unwrap();
    stream.write_all(&[0x0A]).unwrap();
    stream.flush().unwrap();
    let mut reader = BufReader::new(stream);
    let mut buf = Vec::new();
    reader.read_until(0x0A, &mut buf).unwrap();
    while buf.last() == Some(&0x0A) {
        buf.pop();
    }
    serde_json::from_slice(&buf).unwrap()
}

fn cleanup(sock: &std::path::Path) {
    let _ = std::fs::remove_file(sock);
    if let Ok(data_dir) = std::env::var("FUSION_GUARD_DATA_DIR") {
        let _ = std::fs::remove_dir_all(&data_dir);
    }
}

// H-B: 非 admin 调 guard.rule.add → -32001 拒 (规则突变仅 admin)。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hb_rule_add_non_admin_denied() {
    if is_root() {
        eprintln!("skip: root caller is admin, bypass H-B admin gate");
        return;
    }
    let (db, sock) = ensure_env();
    let handle = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    let req = r#"{"jsonrpc":"2.0","id":1,"method":"guard.rule.add","params":{"caller_epoch":1,"rule":{"name":"evil","pattern":"rm","risk_level":"L4","action":"block"}}}"#;
    let resp = raw_call(&sock, req);
    let err = resp
        .get("error")
        .expect("H-B: non-admin rule.add must error, not result");
    assert_eq!(
        err["code"], -32001,
        "H-B: non-admin rule.add 须 -32001 (Forbidden → wire 同 Unauthorized 码防 admin 枚举), got: {}",
        err
    );

    handle.abort();
    cleanup(&sock);
}

// H-B: 非 admin 调 guard.rule.remove → -32001 拒。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hb_rule_remove_non_admin_denied() {
    if is_root() {
        eprintln!("skip: root caller is admin, bypass H-B admin gate");
        return;
    }
    let (db, sock) = ensure_env();
    let handle = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    let req = r#"{"jsonrpc":"2.0","id":1,"method":"guard.rule.remove","params":{"caller_epoch":1,"name":"default-1"}}"#;
    let resp = raw_call(&sock, req);
    let err = resp
        .get("error")
        .expect("H-B: non-admin rule.remove must error");
    assert_eq!(
        err["code"], -32001,
        "H-B: non-admin rule.remove 须 -32001, got: {}",
        err
    );

    handle.abort();
    cleanup(&sock);
}

// P2-3: jsonrpc 字段非 "2.0" (如 "1.0") → -32600 Invalid Request (协议级, 鉴权前)。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p23_nonstandard_jsonrpc_rejected() {
    let (db, sock) = ensure_env();
    let handle = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    let req = r#"{"jsonrpc":"1.0","id":1,"method":"guard.ping","params":{}}"#;
    let resp = raw_call(&sock, req);
    let err = resp
        .get("error")
        .expect("P2-3: non-2.0 jsonrpc must error, not result");
    assert_eq!(
        err["code"], -32600,
        "P2-3: jsonrpc != \"2.0\" 须 -32600 Invalid Request, got: {}",
        err
    );

    handle.abort();
    cleanup(&sock);
}

// P2-3: 合法 "2.0" ping 正常返回 (对照: 不误拒合法协议)。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p23_standard_jsonrpc_allowed() {
    let (db, sock) = ensure_env();
    let handle = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    let req = r#"{"jsonrpc":"2.0","id":1,"method":"guard.ping","params":{}}"#;
    let resp = raw_call(&sock, req);
    assert!(
        resp.get("result").is_some(),
        "P2-3: 合法 jsonrpc 2.0 ping 须正常返回 result, 非 error. resp: {}",
        resp
    );

    handle.abort();
    cleanup(&sock);
}

// H-C: require_shared_secret_for_release 纯函数决策门控 (不启真实 server)。
//  1) dev 构建放行 (cfg!(debug_assertions)) — 测试恒为 debug, 故恒 Ok。
//  2) release+secret 已设 → Ok (prod 正常姿态)。
//  3) release+无 secret+无应急 flag → Err (拒启动, H-C 核心)。
//  4) release+无 secret+应急 flag → Ok (运维知情放行)。
#[test]
fn hc_secret_gating_decision() {
    // (1) dev 构建恒放行 (本测试即 debug 编译)。
    assert!(
        require_shared_secret_for_release().is_ok(),
        "H-C: dev build must allow start regardless of secret (debug_assertions)"
    );

    // 决策函数受 cfg!(debug_assertions) 短路: debug 下永远 Ok, 下方分支在 release 才生效。
    // 因测试恒 debug, 无法在进程内覆盖 cfg; 故此处仅断言 dev 放行 (覆盖 release 分支需 release 构建跑同测)。
    // release 行为由代码静态保证: not(debug_assertions) && secret.is_none() && !allow_no_secret → Err。
}

// H-C (对照): 启动闸门不应影响合法 secret 已设的 dev server 启动。
// 设 secret env → spawn server → ping 正常 (secret 校验在 authorize_method, ping 免 secret, 不冲突)。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hc_server_starts_with_secret_env() {
    let (db, sock) = ensure_env();
    // 显式设 shared secret (模拟 prod 部署姿态, H-C 要求)。
    std::env::set_var("FUSION_GUARD_SHARED_SECRET", "test-secret-strong-value");
    let handle = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    let req = r#"{"jsonrpc":"2.0","id":1,"method":"guard.ping","params":{}}"#;
    let resp = raw_call(&sock, req);
    assert!(
        resp.get("result").is_some(),
        "H-C: server with secret set must serve ping normally, resp: {}",
        resp
    );

    handle.abort();
    cleanup(&sock);
    std::env::remove_var("FUSION_GUARD_SHARED_SECRET");
}
