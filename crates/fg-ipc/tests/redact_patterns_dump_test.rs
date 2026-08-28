// issue #7: guard.redact.patterns.dump 暴露 15 redaction pattern 定义的可序列化 dump。
// 验证: 返回 patterns 数组 (15 条), 每条带 name/regex/validator tag, 优先序保留 (先到先拒重叠),
// validator tag 枚举 none|ipv4|aws_secret|luhn|phone。只读 dump, 不改 redaction 行为。

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
        "fg-redactdump-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("guard-redactdump.db");
    let short = uuid::Uuid::new_v4().simple().to_string();
    let sock = PathBuf::from(format!(
        "/tmp/fg-redactdump-{}-{}.sock",
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

// 15 条 pattern 全暴露, 字段完整, validator tag 枚举正确。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redact_patterns_dump_returns_all_definitions() {
    let (db, sock) = ensure_env();
    let handle = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    let res = call(&sock, "guard.redact.patterns.dump");
    let patterns = res["patterns"].as_array().unwrap();
    assert_eq!(
        patterns.len(),
        15,
        "issue #7: 须暴露全部 15 条 redaction pattern 定义"
    );

    // 字段完整 + validator tag 枚举合法。
    let valid_tags = ["none", "ipv4", "aws_secret", "luhn", "phone"];
    for p in patterns {
        assert!(p["name"].is_string(), "每条须带 name");
        assert!(p["regex"].is_string(), "每条须带 regex");
        let tag = p["validator"].as_str().unwrap();
        assert!(valid_tags.contains(&tag), "validator tag 须枚举之一: {tag}");
    }

    handle.abort();
    let _ = std::fs::remove_file(&sock);
}

// 优先序保留: 长凭据 (private_key/jwt/api_key/conn_string/password) 须先于裸数字 (id_number)。
// 先到先拒重叠, 防短模式吞长凭据子串 / 裸数字吞凭据标签值。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redact_patterns_dump_preserves_priority_order() {
    let (db, sock) = ensure_env();
    let handle = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    let res = call(&sock, "guard.redact.patterns.dump");
    let patterns = res["patterns"].as_array().unwrap();
    let names: Vec<&str> = patterns
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();

    // 凭据标签模式须先于裸数字模式 (id_number 最后)。
    let pos_private_key = names.iter().position(|n| *n == "private_key").unwrap();
    let pos_jwt = names.iter().position(|n| *n == "jwt").unwrap();
    let pos_api_key = names.iter().position(|n| *n == "api_key").unwrap();
    let pos_conn_string = names.iter().position(|n| *n == "conn_string").unwrap();
    let pos_password = names.iter().position(|n| *n == "password").unwrap();
    let pos_id_number = names.iter().position(|n| *n == "id_number").unwrap();

    assert!(
        pos_id_number > pos_private_key,
        "id_number 须排 private_key 之后"
    );
    assert!(pos_id_number > pos_jwt, "id_number 须排 jwt 之后");
    assert!(pos_id_number > pos_api_key, "id_number 须排 api_key 之后");
    assert!(
        pos_id_number > pos_conn_string,
        "id_number 须排 conn_string 之后"
    );
    assert!(pos_id_number > pos_password, "id_number 须排 password 之后");

    // email 须排 conn_string 之后 (pass@host 须让 conn_string 先吃, 防被 email 吞)。
    let pos_email = names.iter().position(|n| *n == "email").unwrap();
    assert!(
        pos_email > pos_conn_string,
        "email 须排 conn_string 之后 (防 pass@host 被 email 吞)"
    );

    handle.abort();
    let _ = std::fs::remove_file(&sock);
}

// validator 标签精确映射: 仅 ipv4/aws_secret/credit_card/phone 带算法 validator, 余 none。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redact_patterns_dump_validator_tags_exact() {
    let (db, sock) = ensure_env();
    let handle = spawn_server(&db, sock.clone()).await;
    wait_for_sock(&sock).await;

    let res = call(&sock, "guard.redact.patterns.dump");
    let patterns = res["patterns"].as_array().unwrap();
    let tag_of = |name: &str| -> &str {
        patterns
            .iter()
            .find(|p| p["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("pattern {name} missing"))["validator"]
            .as_str()
            .unwrap()
    };

    assert_eq!(tag_of("ipv4"), "ipv4", "ipv4 须带 ipv4 validator");
    assert_eq!(
        tag_of("aws_secret"),
        "aws_secret",
        "aws_secret 须带 aws_secret validator"
    );
    assert_eq!(
        tag_of("credit_card"),
        "luhn",
        "credit_card 须带 luhn validator"
    );
    assert_eq!(tag_of("phone"), "phone", "phone 须带 phone validator");
    // 无算法 validator 的模式须标 none。
    for n in [
        "private_key",
        "jwt",
        "oauth_bearer",
        "api_key",
        "conn_string",
        "password",
        "secret_kv",
        "env_kv",
        "netrc",
        "email",
        "id_number",
    ] {
        assert_eq!(tag_of(n), "none", "{n} 须标 none (无算法 validator)");
    }

    handle.abort();
    let _ = std::fs::remove_file(&sock);
}
