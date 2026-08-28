// P0-1 (audit §1.1): peercred→tenant 绑定验证。wire tenant_id 自声明漏洞修复 —
// 非 admin caller 传未授权 tenant_id 到 evaluate/redact/reveal/confirm/audit.list/
// audit.verify → -32001 拒。同 uid 守护进程仅授权 DEFAULT_TENANT (IpcServer::new bootstrap)。
// admin (uid=0) 跳过 (root 全租户)。本机测试 uid != 0 → 走非 admin 路径。

use std::io::{BufRead, BufReader, Write};
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
        "fg-tenant-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("guard-tenant.db");
    let short = uuid::Uuid::new_v4().simple().to_string();
    let sock = PathBuf::from(format!(
        "/tmp/fg-tenant-{}-{}.sock",
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

fn is_root() -> bool {
    // 用 fg-peercred 安全 our_uid (crate 本身 unsafe_code=allow), 避免测试触发 workspace deny。
    fg_peercred::our_uid() == 0
}

// 非 admin caller: evaluate 传未授权 tenant_id "evil-corp" → -32001。
// 守护进程 IpcServer::new 已绑 daemon_uid → DEFAULT_TENANT。本机 uid 非 root 仅授权 DEFAULT。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn evaluate_cross_tenant_denied() {
    if is_root() {
        eprintln!("skip: root caller is admin, bypass tenant gate (P0-1)");
        return;
    }
    let (db, sock) = ensure_env();
    let handle = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    let req = r#"{"jsonrpc":"2.0","id":1,"method":"guard.evaluate","params":{"content":"echo hi","tenant_id":"evil-corp","caller_epoch":0}}"#;
    let resp = raw_call(&sock, req);
    let err = resp
        .get("error")
        .expect("cross-tenant must error, not result");
    assert_eq!(
        err["code"], -32001,
        "P0-1: 未授权 tenant 须 -32001, got: {}",
        err
    );

    handle.abort();
    let _ = std::fs::remove_file(&sock);
}

// 非 admin caller: evaluate 传授权 DEFAULT_TENANT → 正常 result (非拒)。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn evaluate_authorized_tenant_allowed() {
    let (db, sock) = ensure_env();
    let handle = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    let tenant = if is_root() {
        "evil-corp"
    } else {
        fg_store::DEFAULT_TENANT
    };
    let req = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"guard.evaluate","params":{{"content":"echo hi","tenant_id":"{}","caller_epoch":0}}}}"#,
        tenant
    );
    let resp = raw_call(&sock, &req);
    assert!(
        resp.get("result").is_some(),
        "P0-1: 授权 tenant 须正常返回 result, 非 error. resp: {}",
        resp
    );

    handle.abort();
    let _ = std::fs::remove_file(&sock);
}

// 非 admin: audit.list 传未授权 tenant_id → -32001 (斩跨租户枚举外泄链)。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_list_cross_tenant_denied() {
    if is_root() {
        eprintln!("skip: root caller is admin, bypass tenant gate (P0-1)");
        return;
    }
    let (db, sock) = ensure_env();
    let handle = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    let req = r#"{"jsonrpc":"2.0","id":1,"method":"guard.audit.list","params":{"tenant_id":"evil-corp"}}"#;
    let resp = raw_call(&sock, req);
    let err = resp
        .get("error")
        .expect("cross-tenant audit.list must error");
    assert_eq!(
        err["code"], -32001,
        "P0-1: audit.list 未授权 tenant 须 -32001, got: {}",
        err
    );

    handle.abort();
    let _ = std::fs::remove_file(&sock);
}

// 非 admin: audit.verify 传未授权 tenant_id → -32001 (斩跨租户行数外泄)。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_verify_cross_tenant_denied() {
    if is_root() {
        eprintln!("skip: root caller is admin, bypass tenant gate (P0-1)");
        return;
    }
    let (db, sock) = ensure_env();
    let handle = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    let req = r#"{"jsonrpc":"2.0","id":1,"method":"guard.audit.verify","params":{"tenant_id":"evil-corp"}}"#;
    let resp = raw_call(&sock, req);
    let err = resp
        .get("error")
        .expect("cross-tenant audit.verify must error");
    assert_eq!(
        err["code"], -32001,
        "P0-1: audit.verify 未授权 tenant 须 -32001, got: {}",
        err
    );

    handle.abort();
    let _ = std::fs::remove_file(&sock);
}

// 非 admin: audit.verify 不传 tenant_id → scope 默认取授权集中首个 (DEFAULT_TENANT),
// 正常返回 (非拒)。total_rows=0 空库。验证默认作用域不崩。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_verify_default_scope_allowed() {
    let (db, sock) = ensure_env();
    let handle = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    let req = r#"{"jsonrpc":"2.0","id":1,"method":"guard.audit.verify","params":{}}"#;
    let resp = raw_call(&sock, req);
    assert!(
        resp.get("result").is_some(),
        "P0-1: 不传 tenant_id 须用授权默认 scope 正常返回, 非 error. resp: {}",
        resp
    );

    handle.abort();
    let _ = std::fs::remove_file(&sock);
}
