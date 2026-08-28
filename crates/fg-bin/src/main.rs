use clap::{Parser, Subcommand};
use fg_audit_engine::AuditEngine;
use fg_ipc::{IpcServer, DEFAULT_SOCK};
use fg_store::AuditStore;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "fusion-guard",
    version,
    about = "Fusion zero-trust guard daemon"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    Start {
        #[arg(long, env = "FUSION_GUARD_SOCK", default_value = DEFAULT_SOCK)]
        sock: PathBuf,
        // P2-1 (audit §2.6): 显式放行 env key (release 用)。默认 false —— prod 强制 Keychain。
        // 置位 = set FUSION_GUARD_ALLOW_ENV_KEY=1 (fg-store token_store 读), 告警级 warn。
        #[arg(long, default_value_t = false)]
        insecure_env_key: bool,
    },
    Ping {
        #[arg(long, env = "FUSION_GUARD_SOCK", default_value = DEFAULT_SOCK)]
        sock: PathBuf,
    },
}

fn init_tracing() {
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let dir = log_dir();
    let _ = std::fs::create_dir_all(&dir);
    let log_file = dir.join("fusion-guard.log");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_file)
        .unwrap_or_else(|e| {
            eprintln!("open log file failed: {e}, fallback stderr");
            std::fs::File::create("/dev/null").unwrap()
        });
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::sync::Mutex::new(file))
        .try_init();
    tracing::info!(log_file = %log_file.display(), "tracing initialized");
}

fn log_dir() -> PathBuf {
    if let Ok(d) = std::env::var("FUSION_GUARD_LOG_DIR") {
        return PathBuf::from(d);
    }
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    home.join(".fusion-guard").join("logs")
}

fn data_dir() -> PathBuf {
    if let Ok(d) = std::env::var("FUSION_GUARD_DATA_DIR") {
        return PathBuf::from(d);
    }
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    home.join(".fusion-guard")
}

fn main() -> anyhow::Result<()> {
    init_tracing();
    // soak/商用: 显式 runtime 限 blocking 线程池 + 栈大小。
    // 默认 max_blocking_threads=512 × 2MB 栈 = 潜在 1GB, 高并发 evaluate 全走 spawn_blocking
    // (SQLite Mutex + 链 hash 阻塞) 时池涨满占大量 RSS。64 线程 × 256KB 栈 = 16MB, 足够
    // 16 req_sem 并发 (实际并发 handler ≤ MAX_CONCURRENT_REQS=16), 512 纯浪费。
    // worker_threads=CPU 核数保持 (异步 IO); blocking 池独立给 spawn_blocking。
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(64)
        .thread_stack_size(256 * 1024)
        .build()?;
    rt.block_on(async_main())
}

async fn async_main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Some(Cmd::Start {
            sock,
            insecure_env_key,
        }) => run_server(sock, insecure_env_key).await,
        Some(Cmd::Ping { sock }) => run_ping(sock).await,
        None => run_server(PathBuf::from(DEFAULT_SOCK), false).await,
    }
}

async fn run_server(sock: PathBuf, insecure_env_key: bool) -> anyhow::Result<()> {
    tracing::info!(sock = %sock.display(), "fusion-guard daemon starting");
    // P2-1: CLI flag → env (token_store load_or_create_key 读)。flag 显式 = operator 知情放行。
    if insecure_env_key {
        std::env::set_var("FUSION_GUARD_ALLOW_ENV_KEY", "1");
        tracing::warn!(
            "--insecure-env-key set (P2-1): master key may load from env in release build"
        );
    }
    let db_path = data_dir().join("guard.db");
    let audit = Arc::new(AuditStore::open(&db_path)?);
    // soak/商用: 周期 retention 监控覆盖 drain 低风险路径 (drain 只插不触 rotation)。
    // 5s 间隔 —— 高频 L1 流量下 DB 涨快, 60s 太慢 (突发已超 rotation 阈值)。
    audit.spawn_retention_monitor(5);
    let engine = AuditEngine::new(audit.clone())?;
    let server = IpcServer::new(engine, audit);

    let server_task = tokio::spawn(async move {
        if let Err(e) = server.serve(sock).await {
            tracing::error!(error = %e, "server exited with error");
        }
    });

    tokio::signal::ctrl_c().await?;
    tracing::info!("SIGINT received, shutting down");
    server_task.abort();
    Ok(())
}

async fn run_ping(sock: PathBuf) -> anyhow::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let stream = UnixStream::connect(&sock).await?;
    let (rd, mut wr) = stream.into_split();
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "guard.ping",
        "params": {}
    });
    let mut bytes = serde_json::to_vec(&req)?;
    bytes.push(b'\n');
    wr.write_all(&bytes).await?;

    let mut reader = tokio::io::BufReader::new(rd);
    let mut resp = Vec::new();
    reader.read_until(b'\n', &mut resp).await?;
    let val: serde_json::Value = serde_json::from_slice(&resp)?;
    println!("{}", serde_json::to_string_pretty(&val)?);
    Ok(())
}
