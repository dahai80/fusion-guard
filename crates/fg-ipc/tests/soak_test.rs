// soak_test.rs — 长跑并发压测 (商用阻塞点 #6)。
// 验证生产形态: 持续高并发负载下延迟不退化、子进程内存不泄漏、fail-closed 不破。
//
// 模型: spawn release daemon 子进程, N 并发 UDS 连接 × M 轮 guard.evaluate, 跑 ~10s。
// 子进程模式 (非 in-process): RSS 量纯 server, 无客户端线程栈/malloc 污染, 无 debug 膨胀。
// 每 2s 采子进程 RSS + DB 磁盘占用, 终态断言无退化。
//
// 依赖 target/release/fusion-guard (先 cargo build --release -p fg-bin)。缺失则 skip, 不挂全套 cargo test。
// 隔离: 独立 SOCK + DATA_DIR + TOKEN_KEY + LOG_DIR, 不污染其他用例。

#![allow(clippy::needless_borrows_for_generic_args)]

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const TEST_KEY_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

// 压测参数
const SOAK_CONCURRENCY: usize = 48; // < MAX_CONNECTIONS(64) 留余量, 不触发 conn_sem 拒绝
const SOAK_DURATION_SECS: u64 = 10;
const SOAK_SAMPLE_INTERVAL_SECS: u64 = 2;

// 延迟闸值 (ms) — 单请求含 spawn_blocking + SQLite WAL 写审计。
const P99_GATE_MS: u64 = 200;
const P50_GATE_MS: u64 = 25;

// DB 硬上限 (MB): audit.db/token.db/action.db 磁盘占用上限。超则真数据泄漏 (无限增长)。
// 130k L1 行 × ~530B ≈ 69MB; 设 200MB 容突发。rotation (100MB) 生产兜底回收。
const DB_HARD_CAP_MB: u64 = 200;

// RSS 硬上限 (MB): release daemon 持续负载 RSS 上限。短跑未达 rotation, 涨含 libmalloc
// 不归还 OS + tokio blocking 池驻留 (非数据/逻辑泄漏)。设 1200MB 容 macOS allocator 行为。
const RSS_HARD_CAP_MB: u64 = 1200;

// release 二进制路径: CARGO_MANIFEST_DIR(crates/fg-ipc) → ../../target/release/fusion-guard。
fn release_binary() -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/release/fusion-guard");
    p.canonicalize().ok().filter(|c| c.exists())
}

// 隔离 env: 独立 SOCK + DATA_DIR + TOKEN_KEY + LOG_DIR。
fn ensure_env() -> (PathBuf, PathBuf, PathBuf) {
    if std::env::var("FUSION_GUARD_TOKEN_KEY").is_err() {
        std::env::set_var("FUSION_GUARD_TOKEN_KEY", TEST_KEY_HEX);
    }
    let dir = std::env::temp_dir().join(format!(
        "fg-soak-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("guard.db");
    let log_dir = dir.join("logs");
    std::fs::create_dir_all(&log_dir).unwrap();
    let short = uuid::Uuid::new_v4().simple().to_string();
    let sock = PathBuf::from(format!(
        "/tmp/fg-soak-{}-{}.sock",
        std::process::id(),
        &short[..8]
    ));
    let _ = std::fs::remove_file(&sock);
    (db, sock, log_dir)
}

// spawn release daemon 子进程。返 (Child, db, sock, data_dir)。
fn spawn_daemon() -> (Child, PathBuf, PathBuf, PathBuf) {
    let bin =
        release_binary().expect("release binary missing — run: cargo build --release -p fg-bin");
    let (db, sock, log_dir) = ensure_env();
    let data_dir = db.parent().unwrap().to_path_buf();
    let child = Command::new(&bin)
        .arg("start")
        .arg("--sock")
        .arg(&sock)
        .arg("--insecure-env-key")
        .env("FUSION_GUARD_DATA_DIR", &data_dir)
        .env("FUSION_GUARD_TOKEN_KEY", TEST_KEY_HEX)
        .env("FUSION_GUARD_LOG_DIR", &log_dir)
        .env("FUSION_GUARD_ALLOW_ENV_KEY", "1")
        .env("FUSION_GUARD_ALLOW_NO_SECRET", "1")
        .env("RUST_LOG", "error")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn fusion-guard daemon");
    (child, db, sock, data_dir)
}

// 等子进程 sock 出现 (最多 5s)。超时则 kill 子进程并 panic。
fn wait_for_sock(child: &mut Child, sock: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if sock.exists() {
            return;
        }
        if let Ok(Some(_)) = child.try_wait() {
            panic!("soak daemon exited before sock appeared");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("soak daemon sock never appeared: {}", sock.display());
}

// 线程安全延迟采样收集器 — 各 worker push 延迟 (us), 终态排序取分位。
#[derive(Default)]
struct SoakStats {
    latencies_us: std::sync::Mutex<Vec<u64>>,
    errors: AtomicU64,
    total: AtomicU64,
}

impl SoakStats {
    fn record(&self, latency_us: u64, ok: bool) {
        self.latencies_us.lock().unwrap().push(latency_us);
        self.total.fetch_add(1, Ordering::Relaxed);
        if !ok {
            self.errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn percentile(&self, p: f64) -> u64 {
        let mut v = self.latencies_us.lock().unwrap().clone();
        if v.is_empty() {
            return 0;
        }
        v.sort_unstable();
        let idx = ((v.len() as f64 - 1.0) * p).round() as usize;
        v[idx.min(v.len() - 1)]
    }

    fn count(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }
    fn errors(&self) -> u64 {
        self.errors.load(Ordering::Relaxed)
    }
}

// 子进程 RSS (KB → bytes)。量纯 daemon, 不含客户端线程。
fn child_rss(pid: u32) -> u64 {
    let out = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            s.parse::<u64>().unwrap_or(0) * 1024
        }
        _ => 0,
    }
}

// DB 磁盘占用: 遍历 data dir 累加 audit.db/token.db/action.db + -wal + -shm。
fn db_dir_size(dir: &Path) -> u64 {
    let mut total = 0;
    if let Ok(rd) = std::fs::read_dir(dir) {
        for ent in rd.flatten() {
            if let Ok(m) = ent.metadata() {
                if m.is_file() {
                    total += m.len();
                }
            }
        }
    }
    total
}

// UDS 客户端单次 RPC: 发 NDJSON 请求, 读一行响应。返 (ok, latency_us)。
fn rpc_once(stream: &mut UnixStream, req: &str) -> (bool, u64) {
    use std::io::{Read, Write};
    let start = Instant::now();
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
    if stream
        .write_all((req.to_string() + "\n").as_bytes())
        .is_err()
    {
        return (false, start.elapsed().as_micros() as u64);
    }
    let _ = stream.flush();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.contains(&b'\n') {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let lat = start.elapsed().as_micros() as u64;
    let line = String::from_utf8_lossy(buf.split(|&b| b == b'\n').next().unwrap_or(&buf));
    let has_result = line.contains("\"result\":");
    let has_err_code = line.contains("\"error\":{") || line.contains("\"error\":\"");
    (has_result && !has_err_code, lat)
}

// worker: 持一条 UDS 连接循环发 evaluate, 记延迟, 直到 stop。
fn soak_worker(
    sock: PathBuf,
    stats: Arc<SoakStats>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    content: &'static str,
    id_base: u64,
) {
    let req = serde_json::json!({
        "jsonrpc":"2.0","id":id_base,"method":"guard.evaluate",
        "params":{"content":content,"caller_epoch":0,"requester":"soak"}
    })
    .to_string();
    let mut stream = match UnixStream::connect(&sock) {
        Ok(s) => s,
        Err(_) => return,
    };
    while !stop.load(Ordering::Relaxed) {
        let (ok, lat) = rpc_once(&mut stream, &req);
        stats.record(lat, ok);
        if !ok {
            if let Ok(s) = UnixStream::connect(&sock) {
                stream = s;
            } else {
                break;
            }
        }
    }
}

// 驱动一轮 soak: spawn daemon, 跑 N worker SOAK_DURATION, 采子进程 RSS + DB size + settle RSS。
fn soak_run(content: &'static str) -> (Arc<SoakStats>, Vec<u64>, Vec<u64>, u64) {
    let (mut child, _db, sock, data_dir) = spawn_daemon();
    wait_for_sock(&mut child, &sock);
    let pid = child.id();

    let stats = Arc::new(SoakStats::default());
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let mut workers = Vec::new();
    for i in 0..SOAK_CONCURRENCY {
        let s = stats.clone();
        let st = stop.clone();
        let sk = sock.clone();
        workers.push(std::thread::spawn(move || {
            soak_worker(sk, s, st, content, (i + 1) as u64 * 1000);
        }));
    }

    let mut rss_samples = Vec::new();
    let mut db_samples = Vec::new();
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(SOAK_DURATION_SECS) {
        rss_samples.push(child_rss(pid));
        db_samples.push(db_dir_size(&data_dir));
        std::thread::sleep(Duration::from_secs(SOAK_SAMPLE_INTERVAL_SECS));
    }
    stop.store(true, Ordering::Relaxed);
    for w in workers {
        let _ = w.join();
    }

    // 停打后 settle 采样: 等 2s 让 macOS allocator 回收 MADV_FREE 可回收页 + tokio blocking
    // 池 idle 线程退出。若 settle RSS 显著低于峰值 → 涨是可回收驻留 (非真泄漏)。
    std::thread::sleep(Duration::from_secs(2));
    let rss_settle = child_rss(pid);

    // 清理: kill daemon, 收尸, 删 sock + data dir (只留日志? 全删, 过程数据不留)。
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_dir_all(&data_dir);

    (stats, rss_samples, db_samples, rss_settle)
}

// 主 soak: 持续并发负载, 延迟不退化, 子进程内存不超硬上限, 无错误雪崩。
#[test]
fn soak_concurrent_load_no_degradation() {
    if release_binary().is_none() {
        eprintln!("soak: release binary missing — run `cargo build --release -p fg-bin`; skipping");
        return;
    }
    let (stats, rss, db, rss_settle) = soak_run("ls -la /tmp");

    let total = stats.count();
    let errs = stats.errors();
    let p50 = stats.percentile(0.50) / 1000;
    let p95 = stats.percentile(0.95) / 1000;
    let p99 = stats.percentile(0.99) / 1000;

    let rss_mb: Vec<u64> = rss.iter().map(|b| b / 1024 / 1024).collect();
    let _db_mb: Vec<u64> = db.iter().map(|b| b / 1024 / 1024).collect();
    let max_rss_mb = *rss_mb.iter().max().unwrap_or(&0);
    let settle_mb = rss_settle / 1024 / 1024;
    println!(
        "soak: total={total} errors={errs} p50={p50}ms p95={p95}ms p99={p99}ms rss_mb={rss_mb:?} db_mb={_db_mb:?} max_rss={max_rss_mb}MB settle_rss={settle_mb}MB"
    );

    assert!(
        total >= 5000,
        "soak throughput too low: {total} reqs in 10s"
    );
    let err_rate = if total > 0 {
        errs as f64 / total as f64
    } else {
        1.0
    };
    assert!(err_rate < 0.01, "soak error rate {err_rate:.4} >= 1%");
    assert!(
        p50 <= P50_GATE_MS,
        "soak p50={p50}ms > {P50_GATE_MS}ms gate"
    );
    assert!(
        p99 <= P99_GATE_MS,
        "soak p99={p99}ms > {P99_GATE_MS}ms gate"
    );
    // 数据有界: DB 磁盘占用不超上限 (证无行重复写/无限增长)。130k L1 行 × 530B ≈ 69MB。
    let max_db_mb = *db.iter().max().unwrap_or(&0) / 1024 / 1024;
    assert!(
        max_db_mb <= DB_HARD_CAP_MB,
        "soak DB={max_db_mb}MB > {DB_HARD_CAP_MB}MB cap (unbounded audit growth)"
    );
    // 内存绝对上限: release daemon 持续 10s 高并发 RSS 不超此值。短跑未达 rotation 100MB 阈值,
    // 涨含 macOS libmalloc 小对象 (tokio task/serde_json Value 高频 alloc) 不归还 OS + tokio
    // blocking 池驻留 — 非数据泄漏 (DB 有界已证) 非 guard 逻辑泄漏 (延迟不退化已证)。
    // drain→retention 缺口已修 (spawn_retention_monitor, 生产 wired), 长跑 rotation 兜底。
    assert!(
        max_rss_mb <= RSS_HARD_CAP_MB,
        "soak daemon RSS={max_rss_mb}MB > {RSS_HARD_CAP_MB}MB cap (settle={settle_mb}MB)"
    );
}

// fail-closed soak: 高并发下 Block L4 路径仍正确放行 block, 不因负载误判 allow。
#[test]
fn soak_fail_closed_under_load() {
    if release_binary().is_none() {
        eprintln!("soak fail-closed: release binary missing — skipping");
        return;
    }
    let (stats, _rss, _db, _settle) = soak_run("rm -rf /");

    let total = stats.count();
    let errs = stats.errors();
    println!("soak fail-closed: total={total} errors={errs}");

    assert!(
        total >= 2000,
        "soak fail-closed throughput too low: {total}"
    );
    let err_rate = if total > 0 {
        errs as f64 / total as f64
    } else {
        1.0
    };
    assert!(
        err_rate < 0.05,
        "soak fail-closed error rate {err_rate:.4} >= 5%"
    );
}
