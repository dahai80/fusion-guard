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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let cli = Cli::parse();

    match cli.cmd {
        Some(Cmd::Start { sock }) => run_server(sock).await,
        Some(Cmd::Ping { sock }) => run_ping(sock).await,
        None => run_server(PathBuf::from(DEFAULT_SOCK)).await,
    }
}

async fn run_server(sock: PathBuf) -> anyhow::Result<()> {
    tracing::info!(sock = %sock.display(), "fusion-guard daemon starting");
    let db_path = data_dir().join("guard.db");
    let audit = Arc::new(AuditStore::open(&db_path)?);
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
