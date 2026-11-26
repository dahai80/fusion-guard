use clap::{Parser, Subcommand};
use fg_audit_engine::AuditEngine;
use fg_ipc::{require_shared_secret_for_release, IpcServer, DEFAULT_SOCK};
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
        // P2-1 (audit §2.6): explicit escape hatch for the env key (release builds). Default false — prod requires Keychain.
        // When set, enables FUSION_GUARD_ALLOW_ENV_KEY=1 (read by fg-store token_store), logged at warn level.
        #[arg(long, default_value_t = false)]
        insecure_env_key: bool,
        // H-C secret side: explicit escape hatch for the env shared secret (release builds). Default false — prod requires Keychain.
        // When set, enables FUSION_GUARD_ALLOW_INSECURE_SECRET=1 (read by the fg-ipc authorizer + gate), logged at
        // warn level.
        // An env secret is readable by any same-UID process, not recommended; prod uses Keychain
        // (security add-generic-password).
        #[arg(long, default_value_t = false)]
        insecure_secret_env: bool,
    },
    Ping {
        #[arg(long, env = "FUSION_GUARD_SOCK", default_value = DEFAULT_SOCK)]
        sock: PathBuf,
    },
}

// P1-2 (audit §P1-2): rolling log files (tracing-appender rolling, split daily).
// The old code used OpenOptions append on a single fusion-guard.log that grew without bound; long runs (launchd
// resident) could fill the disk. Switched to rolling: daily rotation fusion-guard.log.YYYY-MM-DD, keep N files
// (max_log_files), oldest files deleted automatically.
// Returns a WorkerGuard that must stay alive until process exit (drop flushes buffered writes); main binds it to a
// non-underscore variable to keep it alive.
fn init_tracing() -> tracing_appender::non_blocking::WorkerGuard {
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let dir = log_dir();
    let _ = std::fs::create_dir_all(&dir);
    // P1-2: rolling split daily, keep 7 files (one week of logs). Filename prefix fusion-guard, suffix .log.
    // rotation=Daily → a new fusion-guard.YYYY-MM-DD.log each day; max_log_files=N deletes the oldest beyond N.
    let file_appender = tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("fusion-guard")
        .filename_suffix("log")
        .max_log_files(7)
        .build(&dir);
    let (writer, guard) = match file_appender {
        Ok(appender) => tracing_appender::non_blocking(appender),
        Err(e) => {
            // Rolling appender build failure (unwritable dir etc.) falls back to stderr; log init must not crash
            // the daemon.
            eprintln!("rolling log appender build failed: {e}, fallback stderr");
            let (w, g) = tracing_appender::non_blocking(std::io::stderr());
            (w, g)
        }
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer)
        .try_init();
    tracing::info!(log_dir = %dir.display(), "tracing initialized (P1-2 rolling daily, keep 7)");
    guard
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
    // P1-2: the guard must stay alive until process exit (drop flushes buffered writes + prevents early rotation).
    // Keep the variable non-underscore prefixed.
    let _log_guard = init_tracing();
    // soak/commercial: explicit runtime caps the blocking thread pool + stack size.
    // Default max_blocking_threads=512 × 2MB stacks = potentially 1GB; under high-concurrency evaluate everything
    // goes through spawn_blocking (SQLite Mutex + chain hash blocking) and the pool can fill up consuming large RSS.
    // 64 threads × 256KB stacks = 16MB, enough for the 16 req_sem concurrency (actual concurrent handlers ≤
    // MAX_CONCURRENT_REQS=16); 512 is pure waste.
    // worker_threads=CPU core count kept (async IO); the blocking pool is reserved for spawn_blocking.
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
            insecure_secret_env,
        }) => run_server(sock, insecure_env_key, insecure_secret_env).await,
        Some(Cmd::Ping { sock }) => run_ping(sock).await,
        None => run_server(PathBuf::from(DEFAULT_SOCK), false, false).await,
    }
}

async fn run_server(
    sock: PathBuf,
    insecure_env_key: bool,
    insecure_secret_env: bool,
) -> anyhow::Result<()> {
    tracing::info!(sock = %sock.display(), "fusion-guard daemon starting");
    // P2-1: CLI flag → env (read by token_store load_or_create_key). An explicit flag means the operator knowingly allows it.
    if insecure_env_key {
        std::env::set_var("FUSION_GUARD_ALLOW_ENV_KEY", "1");
        tracing::warn!(
            "--insecure-env-key set (P2-1): master key may load from env in release build"
        );
    }
    // H-C secret side: CLI flag → env (read by the fg-ipc authorizer + require_shared_secret_for_release).
    // An explicit flag means the operator knowingly allows the env shared secret (same-UID readable, not
    // recommended); prod uses Keychain.
    if insecure_secret_env {
        std::env::set_var("FUSION_GUARD_ALLOW_INSECURE_SECRET", "1");
        tracing::warn!(
            "--insecure-secret-env set (H-C): shared secret may load from env in release build — \
             same-UID visible, prod should use Keychain (security add-generic-password -s fusion-guard -a shared-secret)"
        );
    }
    // H-C (product-audit §5): release builds must have a shared secret set (second auth factor beyond peercred).
    // dev skips; release without one → refuse to start (prevents the peercred-only fallback being fully callable by
    // a compromised same-uid process).
    // Emergency: FUSION_GUARD_ALLOW_NO_SECRET=1 allows it (operator-informed, not for prod).
    require_shared_secret_for_release().map_err(|e| anyhow::anyhow!(e))?;
    let db_path = data_dir().join("guard.db");
    let audit = Arc::new(AuditStore::open(&db_path)?);
    // soak/commercial: periodic retention monitor covers the drain low-risk path (drain only inserts, never rotates).
    // 5s interval — under high-frequency L1 traffic the DB grows fast; 60s is too slow (bursts already exceed the
    // rotation threshold).
    audit.spawn_retention_monitor(5);
    let engine = AuditEngine::new(audit.clone())?;
    let server = IpcServer::new(engine, audit);

    let server_task = tokio::spawn(async move {
        if let Err(e) = server.serve(sock).await {
            tracing::error!(error = %e, "server exited with error");
        }
    });

    // P1-1 (audit §P1-1): graceful shutdown. The old code only handled tokio::signal::ctrl_c() (SIGINT); SIGTERM
    // from launchd/start.sh killed the process via the default action (no SIGTERM handler → the process exits but
    // the audit drain thread's in-flight L1/L2 batch may not be flushed; synchronous=NORMAL does not fsync every
    // commit). Added a SIGTERM handler:
    // SIGINT/SIGTERM → stop accept (abort server_task) → drain grace lets in-flight low-risk batches persist
    // → exit (AuditStore drop closes the SQLite connections = WAL checkpoint).
    // High-risk rows already fsync every commit (synchronous=FULL), no loss; the low-risk drain gets a short grace window.
    shutdown_signal().await;
    tracing::info!("shutdown signal received, stopping accept loop (P1-1 graceful)");
    server_task.abort();
    // P1-1 drain grace: gives the drain thread a window to persist in-flight low-risk batches (sync_channel batch
    // insert). 500ms is enough for a single batch (drain inserts as it receives, or small batches) without slowing
    // shutdown much; a long drain stall does not block exit.
    tracing::info!("drain grace window (500ms) — flushing in-flight low-risk audit batch (P1-1)");
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    tracing::info!("fusion-guard daemon stopped (audit connections drop → WAL checkpoint)");
    Ok(())
}

// P1-1: wait for SIGINT or SIGTERM, return on whichever arrives first (triggers graceful shutdown).
// tokio::signal::ctrl_c() only covers SIGINT; SIGTERM needs the unix signal adapter. launchd/kill -TERM lands here.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sig = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        sig.recv().await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("received SIGINT"),
        _ = terminate => tracing::info!("received SIGTERM"),
    }
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
