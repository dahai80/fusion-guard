// P0-7 (audit §2.8): ES 监控接入验证。无 entitlement → IPC 必须如实回 degraded
// (非假装 Active), 让运维知 ES 未生效、退回 TCC (PRD Q#3)。验证 dead-code 不复存在。

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
        "fg-es-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("guard-es.db");
    let short = uuid::Uuid::new_v4().simple().to_string();
    let sock = PathBuf::from(format!(
        "/tmp/fg-es-{}-{}.sock",
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

fn call(sock: &std::path::Path, method: &str) -> serde_json::Value {
    let mut stream = UnixStream::connect(sock).unwrap();
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let req = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"{}","params":{{}}}}"#,
        method
    );
    stream.write_all(req.as_bytes()).unwrap();
    stream.write_all(&[0x0A]).unwrap();
    stream.flush().unwrap();

    let mut reader = BufReader::new(stream);
    let mut buf = Vec::new();
    reader.read_until(0x0A, &mut buf).unwrap();
    while buf.last() == Some(&0x0A) {
        buf.pop();
    }
    let resp: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    resp.get("result").cloned().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn es_status_reports_honest_degraded() {
    let (db, sock) = ensure_env();
    let handle = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    let status = call(&sock, "guard.es.status");
    // 无 entitlement → degraded (非 Active 假装可用)。
    assert_eq!(
        status["state"], "degraded",
        "P0-7: ES 无 entitlement 须诚实报 degraded, 非假装 Active"
    );
    assert_eq!(status["entitlement"], false, "entitlement 须 false");
    assert!(
        status["source"].as_str().unwrap().contains("stub"),
        "source 须标 stub (来源可追溯): {}",
        status["source"]
    );
    assert_eq!(
        status["subscribed"].as_array().unwrap().len(),
        0,
        "degraded 模式无订阅事件"
    );

    handle.abort();
    let _ = std::fs::remove_file(&sock);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn es_events_empty_under_degraded() {
    let (db, sock) = ensure_env();
    let handle = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    let res = call(&sock, "guard.es.events");
    let events = res["events"].as_array().unwrap();
    assert!(
        events.is_empty(),
        "P0-7: degraded 模式事件流须空, 不伪造事件"
    );

    handle.abort();
    let _ = std::fs::remove_file(&sock);
}
