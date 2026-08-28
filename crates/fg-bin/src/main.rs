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

// P1-2 (audit §P1-2): 滚动日志文件 (tracing-appender rolling, 按日切分)。
// 旧码 OpenOptions append 单文件 fusion-guard.log 无限增长, 长跑 (launchd 常驻) 撑满磁盘。
// 改 rolling: 按日轮转 fusion-guard.log.YYYY-MM-DD, 保留 N 份 (max_log_files), 旧文件自动删。
// 返回 WorkerGuard 须存活到进程退出 (drop 时 flush 缓冲), main 持有非 _ 前缀变量保活。
fn init_tracing() -> tracing_appender::non_blocking::WorkerGuard {
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let dir = log_dir();
    let _ = std::fs::create_dir_all(&dir);
    // P1-2: rolling 按日切分, 保留 7 份 (一周日志)。文件名前缀 fusion-guard, 后缀 .log。
    // rotation=Daily → 每日新文件 fusion-guard.YYYY-MM-DD.log; max_log_files=N 删最旧超 N 份。
    let file_appender = tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("fusion-guard")
        .filename_suffix("log")
        .max_log_files(7)
        .build(&dir);
    let (writer, guard) = match file_appender {
        Ok(appender) => tracing_appender::non_blocking(appender),
        Err(e) => {
            // 滚动构建失败 (目录不可写等) 回退 stderr, 不让日志初始化崩溃守护进程。
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
    // P1-2: guard 须存活到进程退出 (drop flush 缓冲 + 阻止提前轮换)。变量非 _ 前缀保活。
    let _log_guard = init_tracing();
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
    // H-C (product-audit §5): release 构建必须设共享 secret (第二鉴权因子, 超越 peercred)。
    // dev 跳过; release 未设 → 拒启动 (防仅 peercred 兜底被同 uid 被攻陷进程全权调用)。
    // 应急: FUSION_GUARD_ALLOW_NO_SECRET=1 放行 (运维知情, 非 prod)。
    require_shared_secret_for_release().map_err(|e| anyhow::anyhow!(e))?;
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

    // P1-1 (audit §P1-1): 优雅关闭。旧码仅 tokio::signal::ctrl_c() (SIGINT), launchd/start.sh
    // 发 SIGTERM 被默认动作直接杀 (SIGTERM 无 handler → 进程退出但 audit drain 线程的 L1/L2
    // 在途批次可能未 flush, synchronous=NORMAL 非每提交 fsync)。补 SIGTERM handler:
    // 收 SIGINT/SIGTERM → 停 accept (abort server_task) → drain grace 让在途低风险批次落库
    // → 退出 (AuditStore drop 触发 SQLite 连接关闭 = WAL checkpoint)。
    // 高风险行 synchronous=FULL 每提交已 fsync, 无丢失; 低风险 drain 短 grace 兜底。
    shutdown_signal().await;
    tracing::info!("shutdown signal received, stopping accept loop (P1-1 graceful)");
    server_task.abort();
    // P1-1 drain grace: 给 drain 线程在途低风险批次落库窗口 (sync_channel batch insert)。
    // 500ms 足够单批次 (drain 收一条即插, 或小批), 不显著拖慢停止; 长 drain 卡顿不阻塞退出。
    tracing::info!("drain grace window (500ms) — flushing in-flight low-risk audit batch (P1-1)");
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    tracing::info!("fusion-guard daemon stopped (audit connections drop → WAL checkpoint)");
    Ok(())
}

// P1-1: 等待 SIGINT 或 SIGTERM, 任一到即返回 (触发优雅关闭)。
// tokio::signal::ctrl_c() 仅 SIGINT; SIGTERM 需 unix signal adapter。launchd/kill -TERM 走此。
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
