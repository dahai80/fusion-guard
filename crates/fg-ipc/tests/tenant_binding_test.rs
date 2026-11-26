// P0-1 (audit §1.1): peercred->tenant binding verification. Fixes the wire
// tenant_id self-declaration vulnerability —
// a non-admin caller passing an unauthorized tenant_id to
// evaluate/redact/reveal/confirm/audit.list/audit.verify is rejected with -32001.
// A same-uid daemon only authorizes DEFAULT_TENANT (IpcServer::new bootstrap).
// admin (uid=0) is skipped (root spans all tenants). Local test uid != 0 -> takes
// the non-admin path.

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
    // Use fg-peercred's safe our_uid (the crate itself is unsafe_code=allow) so the
    // test does not trip the workspace deny.
    fg_peercred::our_uid() == 0
}

// Non-admin caller: evaluate with unauthorized tenant_id "evil-corp" -> -32001.
// The daemon's IpcServer::new already bound daemon_uid -> DEFAULT_TENANT. Local uid
// is not root, so only DEFAULT is authorized.
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
        "P0-1: an unauthorized tenant must get -32001, got: {}",
        err
    );

    handle.abort();
    let _ = std::fs::remove_file(&sock);
}

// Non-admin caller: evaluate with the authorized DEFAULT_TENANT -> normal result (not rejected).
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
        "P0-1: an authorized tenant must return a normal result, not an error. resp: {}",
        resp
    );

    handle.abort();
    let _ = std::fs::remove_file(&sock);
}

// Non-admin: audit.list with unauthorized tenant_id -> -32001 (cuts the cross-tenant enumeration exfiltration chain).
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
        "P0-1: audit.list with an unauthorized tenant must get -32001, got: {}",
        err
    );

    handle.abort();
    let _ = std::fs::remove_file(&sock);
}

// Non-admin: audit.verify with unauthorized tenant_id -> -32001 (cuts cross-tenant row-count exfiltration).
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
        "P0-1: audit.verify with an unauthorized tenant must get -32001, got: {}",
        err
    );

    handle.abort();
    let _ = std::fs::remove_file(&sock);
}

// Non-admin: audit.verify without tenant_id -> scope defaults to the first entry of
// the authorized set (DEFAULT_TENANT), returning normally (not rejected).
// total_rows=0 on an empty store. Verifies the default scope does not crash.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_verify_default_scope_allowed() {
    let (db, sock) = ensure_env();
    let handle = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    let req = r#"{"jsonrpc":"2.0","id":1,"method":"guard.audit.verify","params":{}}"#;
    let resp = raw_call(&sock, req);
    assert!(
        resp.get("result").is_some(),
        "P0-1: omitting tenant_id must use the authorized default scope and return normally, not an error. resp: {}",
        resp
    );

    handle.abort();
    let _ = std::fs::remove_file(&sock);
}
