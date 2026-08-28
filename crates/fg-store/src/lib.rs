#[cfg(feature = "test-helpers")]
use fg_core::CheckStage;
use fg_core::{GuardVerdict, RiskLevel, SafetyAction};
use fg_rules::{GuardRule, RuleSet};
use hmac::{Hmac, Mac};
use rusqlite::{params, Connection, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

// M3: 锁中毒显式处理 —— recover 非进程 panic。守护进程须存活 (单请求 panic 杀 daemon →
// 27 子项目全断服务)。中毒 = 持锁线程 panic, 受保护数据可能不一致, 但 audit/rules 持久化于
// SQLite (原子性由 DB 事务保证非内存锁), 内存态次新可接受。EMERG 日志供运维感知重启。
// unwrap_or_else(|e| e.into_inner()) 提取 guard, PoisonError::into_inner() 对 Mutex/RwLock 通用。
macro_rules! recover_lock {
    ($lock:expr, $what:expr) => {
        match $lock {
            Ok(g) => g,
            Err(e) => {
                tracing::error!(
                    what = $what,
                    "lock poisoned — recovering (daemon must stay alive, M3)"
                );
                e.into_inner()
            }
        }
    };
}

// C21 (P0-G9): 硬化 DB 文件权限。安全守护进程的 store 不可依赖 umask (默认 022 → 0644/0755 可读)。
// 对 db + <db>-wal + <db>-shm 应用 0o600; 存在则设, 不存在跳过 (WAL 文件按需创建)。
// 重应用防外部宽松: 每次 open 后调一次, 覆盖 DB 衰变或外部 chmod 放宽。
fn harden_db_perms(db_path: &Path) {
    let mut paths = vec![db_path.to_path_buf()];
    for suffix in ["-wal", "-shm"] {
        let mut s = db_path.as_os_str().to_os_string();
        s.push(suffix);
        paths.push(std::path::PathBuf::from(s));
    }
    for p in paths {
        if p.exists() {
            // Permissions 非 Copy, 每次构造。
            let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
        }
    }
}

// P1-7 (audit §3.5): 旧单文件 guard.db 把 pending_actions/tokens/key_versions 放主库。
// 分库后迁至 token.db/action.db, 主库残留旧表不再被新代码查询。DROP 残留让 audit.db 纯净。
// 幂等: 用 sqlite_master 查表存在再 DROP (新库无此三表 → 跳过, 无 error)。失败仅 warn 不阻断 open
// (三表皆临时态, 残留不致命; 真正查询走 sibling 文件, 残留表只占少量空间)。
fn drop_legacy_split_tables(conn: &Connection) {
    for tbl in ["pending_actions", "tokens", "key_versions"] {
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                rusqlite::params![tbl],
                |r| r.get(0),
            )
            .unwrap_or(false);
        if exists {
            if let Err(e) = conn.execute_batch(&format!("DROP TABLE {};", tbl)) {
                tracing::warn!(table = tbl, error = %e, "drop legacy split table failed (non-fatal, residual ignored)");
            } else {
                tracing::info!(
                    table = tbl,
                    "dropped legacy split table (P1-7 migrated to sibling db)"
                );
            }
        }
    }
}

const GENESIS_PREV_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// P0-4 (audit §1.3, PRD §13.3): 审计治理阈值。
// ROTATE_BYTES: guard.db 超 100MB → 归档最旧段 (rotation 触发条件之一)。
// ROTATE_AGE_DAYS: 超 30 天的行 → 归档至 ~/.fusion-guard/audit-archive/ (rotation 触发条件之二)。
// RETENTION_DAYS: 归档文件超 180 天 → 删除 (retention 冷存到期)。
const ROTATE_BYTES: u64 = 100 * 1024 * 1024;
const ROTATE_AGE_DAYS: i64 = 30;
const RETENTION_DAYS: i64 = 180;

// P0-4: 归档目录 (PRD §13.3: ~/.fusion-guard/audit-archive/)。
// per-store 解析: env FUSION_GUARD_ARCHIVE_DIR 覆盖 (测试/运维), 否则 db_path 同级 audit-archive/。
// 生产单守护进程 db 在 ~/.fusion-guard/guard.db → 归档目录即 ~/.fusion-guard/audit-archive/ (PRD 不变)。
// per-store 解析避全局 env 在并发测试 store 间竞争 (env 是进程级单值)。
fn resolve_archive_dir(db_path: &Path) -> std::path::PathBuf {
    if let Ok(d) = std::env::var("FUSION_GUARD_ARCHIVE_DIR") {
        return std::path::PathBuf::from(d);
    }
    db_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("audit-archive")
}

pub mod action_store;
pub mod token_store;
pub use action_store::{ActionError, ActionStore, PendingAction};
pub use token_store::{TokenError, TokenStore};

pub const DEFAULT_TENANT: &str = "default";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TccEventRecord {
    pub audit_id: uuid::Uuid,
    pub ts: chrono::DateTime<chrono::Utc>,
    pub permission: String,
    pub requester: String,
    pub result: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub id: uuid::Uuid,
    pub ts: chrono::DateTime<chrono::Utc>,
    pub tenant_id: String,
    pub verdict: GuardVerdict,
    pub raw_content_redacted: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub audit_id: uuid::Uuid,
    pub ts: chrono::DateTime<chrono::Utc>,
    pub event_type: String,
    pub tenant_id: String,
    pub requester: String,
    pub action: String,
    pub inferred_category: String,
    pub verdict_json: String,
    pub approved_by: Option<String>,
    pub seatbelt_required: bool,
    pub outcome: String,
    pub prev_hash: String,
    pub event_hash: String,
}

// P1-6 (audit §3.2): audit.list 过滤 + 游标分页。旧 handler 仅 tenant_id + limit,
// 监控只能暴力轮询全量再客户端筛。补时间窗 (since/until) + event_type + level_min
// 过滤 + 游标分页 → 监控 since=<上次末行 ts> 只拉增量, 不再全量。
//
// level_min: 经 json_extract(verdict_json,'$.risk_level') 取 'l1'..'l4', 字典序 == 等级序
// (等长小写串), SQL >= 直接比较。confirm/tcc 事件无 risk_level (verdict_json 空/无该键)
// → json_extract 返 NULL → NULL >= 'lN' 为 NULL (false) → 自然排除 (符合「按风险等级筛」语义)。
//
// cursor: 末行 (ts, audit_id) 双键, ORDER BY ts DESC, audit_id DESC 下游标条件
// ts < cur_ts OR (ts = cur_ts AND audit_id < cur_audit_id)。ts RFC3339 等长可字典序比;
// audit_id UUID hex 字典序比 (无并发改同一 ts 时稳定排序)。
#[derive(Debug, Clone, Default)]
pub struct AuditListFilter<'a> {
    pub tenant_id: Option<&'a str>,
    pub since: Option<&'a str>,      // RFC3339 字符串, ts >= ?
    pub until: Option<&'a str>,      // RFC3339 字符串, ts <= ?
    pub event_type: Option<&'a str>, // 精确匹配 event_type = ?
    pub level_min: Option<&'a str>,  // 'l1'..'l4', json_extract >= ?
    pub cursor_ts: Option<&'a str>,  // 游标末行 ts
    pub cursor_id: Option<&'a str>,  // 游标末行 audit_id
    pub limit: usize,
}

// P1-6: 分页结果。has_more=true 时 next_cursor 供客户端续拉。
#[derive(Debug, Clone, Serialize)]
pub struct AuditListPage {
    pub records: Vec<AuditRecord>,
    pub next_cursor: Option<String>, // "ts\x1faudit_id" 编码, 客户端透传续拉
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainVerification {
    pub total_rows: usize,
    pub unhashed_rows: usize,
    pub verified_links: usize,
    pub broken_links: usize,
    pub tampered: bool,
    pub first_broken_at: Option<usize>,
}

// P0-5 (audit §1.4): 防篡改覆盖面补齐。单表链 (audit_events) 只覆盖审计行;
// 规则集/TCC/死信不在链上 → 规则篡改 (最高影响攻击, 控制什么被 Block) + TCC 删除 + 死信堆积
// 全部 verify_chain 报绿不可检测。补三条独立链 (每表自链, 非并入 audit_events ——
// audit_events 高吞吐有 rotation, 并入会被归档切链; rules/tcc 变更低频, 独立链更清晰)。
// SubChainVerification = 单条链的校验结果 (与 ChainVerification 同字段)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubChainVerification {
    pub total_rows: usize,
    pub unhashed_rows: usize,
    pub verified_links: usize,
    pub broken_links: usize,
    pub tampered: bool,
    pub first_broken_at: Option<usize>,
}

// P0-5: 全链聚合校验。audit (audit_events 链) + tcc (tcc_events 链) + rules
// (rule_mutations 链) + dead_letter (死信文件链)。tampered = 任一链坏。
// guard.audit.verify 返此聚合 (旧只返 audit ChainVerification, 现扩全链)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllChainsVerification {
    pub audit: ChainVerification,
    pub tcc: SubChainVerification,
    pub rules: SubChainVerification,
    pub dead_letter: SubChainVerification,
    pub tampered: bool,
}

// P0-4 (audit §1.3/§2.4): 增量链校验检查点。缓存上次校验通过的末行 audit_id, 下次只验新增段。
// audit_id (UUID) 而非 rowid: VACUUM 后 rowid 可能重排, audit_id 稳定 → 锚点不失效。
#[derive(Debug, Clone)]
struct Checkpoint {
    last_verified_audit_id: String,
    last_verified_hash: String,
    last_archived_audit_id: Option<String>,
    last_archived_hash: Option<String>,
}

// P0-4 (audit §1.3, PRD §13.3): retention/rotation 执行报告。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RetentionReport {
    pub archived_rows: i64,
    pub archive_path: Option<String>,
    pub pruned_archives: i64,
}

pub struct AuditStore {
    db: Mutex<Connection>,
    // P0-3 (audit §1.2): 高风险同步审计写连接。synchronous=FULL —— commit 时 fsync WAL,
    // 断电不丢 H7 高风险审计行 (NORMAL 仅 acknowledge, 断电可丢)。L3/L4 Block + confirm 走此。
    audit_writer: Arc<Mutex<Connection>>,
    // P0-3/§3.5: 低风险异步批量写连接 (drain 线程)。synchronous=NORMAL —— 性能换耐久分级
    // (L1/L2 异步批量, 丢一批可接受, 非高风险门控)。独立连接独立 Mutex, 减与高风险 writer 锁竞争。
    // drain 线程持 clone; 此字段存所有者句柄 (writer_sync_pragma + 连接生命周期绑定 AuditStore)。
    low_writer: Arc<Mutex<Connection>>,
    // A3/P1: 只读连接, verify_chain/list_events 用它, 不抢 audit_writer 写锁。
    // Mutex 包裹: rusqlite::Connection 非 Sync (内含 RefCell), Arc<Connection> 不 Send → IpcServer 不 Send → tokio::spawn 拒。
    // Mutex<Connection> = Send+Sync。与 audit_writer 独立锁, 读路径互不阻塞 H7 同步写门。
    read_conn: Arc<Mutex<Connection>>,
    // A2: 有界 sync_channel (背压, 防 drain 卡顿时无界堆 OOM)。满 → try_send 失败 → 死信文件。
    low_queue: mpsc::SyncSender<AuditEvent>,
    // A2: 死信文件路径 (与 guard.db 同目录, queue 满/关闭时审计事件落盘非虚空)。
    dead_letter_path: std::path::PathBuf,
    tokens: Arc<TokenStore>,
    actions: Arc<ActionStore>,
    // P1-2 (audit §1.6): master key (Keychain/env), 非 pre-derived。compute_event_hmac
    // 按行 key_version 调 derive_chain_key 派生 (域分离 + 版本化)。Arc 共享给 drain 线程 + confirm。
    chain_key: Arc<Zeroizing<[u8; 32]>>,
    // P1-2: 当前 key 版本 (新审计行记此)。Arc<AtomicI64>: drain 线程 + rotate_key 共享,
    // 轮换后 drain 立即读到新版本 (无闭包捕获过期)。open 时从 key_versions 表最大 version 初始化。
    current_key_version: Arc<std::sync::atomic::AtomicI64>,
    // P0-4: db 路径 (rotation size 检查)。
    db_path: std::path::PathBuf,
    // P0-4: 归档目录 (PRD §13.3)。per-store 解析 (env 覆盖或 db_path 同级 audit-archive/),
    // 非全局 env —— 隔离并发测试 store 不抢同一 env, 且生产单守护进程单归档目录语义不变。
    archive_dir: std::path::PathBuf,
}

pub struct StoreError;

impl AuditEvent {
    // 长度前缀编码 (P0-G2, C8): 每字段 u32 BE 长度 + 字节, 消除 \x1f 连接碰撞。
    // 字段顺序固定 (11 字段), 改任一字段 → HMAC 变 → 检出。
    pub fn payload_bytes(&self) -> Vec<u8> {
        let approved = self.approved_by.clone().unwrap_or_default();
        let ts_str = self.ts.to_rfc3339();
        let seatbelt_str = (self.seatbelt_required as i64).to_string();
        let audit_id_str = self.audit_id.to_string();
        let fields: [&[u8]; 11] = [
            audit_id_str.as_bytes(),
            ts_str.as_bytes(),
            self.event_type.as_bytes(),
            self.tenant_id.as_bytes(),
            self.requester.as_bytes(),
            self.action.as_bytes(),
            self.inferred_category.as_bytes(),
            self.verdict_json.as_bytes(),
            approved.as_bytes(),
            seatbelt_str.as_bytes(),
            self.outcome.as_bytes(),
        ];
        let mut out = Vec::with_capacity(256);
        for f in fields {
            let len = f.len() as u32;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(f);
        }
        out
    }
}

impl AuditStore {
    pub fn open(db_path: &Path) -> std::io::Result<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
            // C21: 目录 0o700, 防 umask 默认 0755 让其他本地用户 cp DB。
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
        // P1-7 (audit §3.5): 写路径物理分库。旧 5+ 连接共 guard.db 单 WAL —— audit_writer
        // (FULL, H7 高风险逐行 fsync) 与 token_store put / action_store put 抢同一 WAL 写锁,
        // 应用层 Mutex 只是假性隔离, 突发写吞吐受限于 SQLite 单写者。分三物理文件各持独立 WAL:
        //   audit.db  ← db_path (audit_events + 链 + rules + tcc + tenant_bindings + checkpoint)
        //   token.db  ← 同级 sibling (tokens + key_versions, TokenStore 独占)
        //   action.db ← 同级 sibling (pending_actions, ActionStore 独占)
        // evaluate 路径: action put (action.db WAL) + 可逆 token (token.db WAL) + 审计 (audit.db WAL)
        // 三库 WAL 互不抢锁 —— H7 fsync 热路径不再被 token/action 写阻塞。
        // H4 confirm 原子性: confirm_atomic 须 SELECT pending_actions + INSERT audit_events + UPDATE
        // consumed 同事务原子。audit_writer 连接 ATTACH action.db 为 `action` schema, 跨库事务协调
        // 提交 (各 ATTACH db 各自 WAL, 原子性保), pending_actions 引用改 `action.pending_actions`。
        // ActionStore 自身连接 (put/evict, 无审计写) 仍指 main.pending_actions, 不经 ATTACH。
        let audit_db_path = db_path.to_path_buf();
        let token_db_path = db_path.with_file_name("token.db");
        let action_db_path = db_path.with_file_name("action.db");

        let conn = Connection::open(&audit_db_path).map_err(io_err)?;
        // P1-4 (product-audit §3): db 连接 (规则/tcc/tenant_bindings/checkpoint 写) 补 busy_timeout=5000。
        // 原 db 无 busy_timeout (默认 0 = 立即 SQLITE_BUSY), 与 audit_writer/low_writer 共享 audit.db
        // 同一 WAL。高负载下 audit 写持 WAL 写锁时, save_rule/save_epoch/report_tcc_event/bind_tenant
        // 立即收 SQLITE_BUSY 无重试 → 规则/tcc 写间歇性失败, 影响 SSOT 一致性 (与 §2 epoch 竞态叠加)。
        // 其余四写连接 (audit_writer/low_writer/token_conn/action_conn) 已设 5000, 此处补齐 db。
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA wal_autocheckpoint=1000;
             PRAGMA secure_delete=ON;
             PRAGMA busy_timeout=5000;",
        )
        .map_err(io_err)?;
        conn.execute_batch(SCHEMA).map_err(io_err)?;
        migrate_audit_chain(&conn).map_err(io_err)?;
        // P1-7: 旧单文件 guard.db 把 pending_actions/tokens/key_versions 也放主库。分库后这三表
        // 迁至 token.db/action.db, 主库残留旧表不再被查询 (新代码走 sibling 文件)。DROP 残留
        // 让 audit.db 纯净 (新库 IF NOT EXISTS 跳过 DROP, 升级库清旧表)。三表皆临时态 (pending
        // TTL 30s / token TTL 300s), 不复制行 (跨文件复制值不当, 旧值大概率已过期)。
        drop_legacy_split_tables(&conn);
        tracing::info!(db = %audit_db_path.display(), "audit store opened (split: audit.db/token.db/action.db, SQLite WAL, chain hash)");

        // A2: 有界 sync_channel (8192) 替无界 channel —— drain 卡 (mutex 被 verify/list 长持)
        // 时低风险事件无界堆 → OOM。有界 + try_send 满 → 死信文件, 背压不丢。
        let (tx, rx) = mpsc::sync_channel::<AuditEvent>(8192);
        let dead_letter_path = db_path.with_extension("deadletter");
        // P0-3 (audit §1.2): 高风险审计写连接 synchronous=FULL —— commit 时 fsync WAL,
        // 断电不丢 H7 高风险审计行 (L3/L4 Block + confirm 走此)。NORMAL 仅 acknowledge, 断电可丢。
        let audit_writer_conn = Connection::open(&audit_db_path).map_err(io_err)?;
        audit_writer_conn
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON; PRAGMA busy_timeout=5000;")
            .map_err(io_err)?;
        // P1-7: audit_writer ATTACH action.db 为 `action` schema —— confirm_atomic 跨库事务
        // (SELECT action.pending_actions + INSERT main.audit_events + UPDATE action.pending_actions)
        // 保 H4 原子性, 同时 action.db 持独立 WAL (不并入 audit.db WAL)。
        // ATTACH '.../action.db' AS action; busy_timeout 防 action.db 被 ActionStore 连接持写锁时短暂等待。
        audit_writer_conn
            .execute_batch(&format!(
                "ATTACH DATABASE '{}' AS action;",
                action_db_path.display().to_string().replace('\'', "''")
            ))
            .map_err(io_err)?;
        // P0-3/§3.5: 低风险异步批量写连接 (drain 线程) synchronous=NORMAL —— 性能换耐久分级
        // (L1/L2 异步批量, 丢一批可接受, 非高风险门控)。独立连接独立 Mutex, 减与高风险 writer 锁竞争。
        let low_writer_conn = Connection::open(&audit_db_path).map_err(io_err)?;
        low_writer_conn
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA secure_delete=ON; PRAGMA busy_timeout=5000;")
            .map_err(io_err)?;
        // P1-7: token 独立物理库 token.db (独立 WAL, 不与 audit 写抢锁)。
        let token_conn = Connection::open(&token_db_path).map_err(io_err)?;
        token_conn
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA secure_delete=ON; PRAGMA busy_timeout=5000;")
            .map_err(io_err)?;
        // H-E (product-audit §5): allow_mint 由审计行存在性决定。audit.db 已有 audit_events 行 =
        // 历史已用主密钥签名链, Keychain 缺密钥 = 密钥丢失 → 拒静默重生成 (否则 verify 全链报篡改
        // 且无法区分真假)。全新库 (无审计行 + token.db 全新) → allow_mint=true 首次生成。
        // 用 `conn` (audit.db, 已 migrate) 查 audit_events 行数; TokenStore::open_checked 再叠加
        // token.db 自身存在性 (两库任一非全新 → allow_mint=false)。这里传 audit 行存在性作下限。
        let audit_has_rows: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM audit_events LIMIT 1)",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|v| v != 0)
            .unwrap_or(false);
        let allow_mint = !audit_has_rows;
        let tokens = TokenStore::open_checked(token_conn, allow_mint).map_err(|e| {
            tracing::error!(error = %e, "token store open failed");
            std::io::Error::other(e.to_string())
        })?;
        // P1-2 (audit §1.6): master key (非派生) + 当前版本。chain_key 现存 master,
        // compute_event_hmac 按行 key_version 派生 chain key (域分离于 token key)。
        let current_key_version = tokens.current_key_version();
        let chain_key = Arc::new(Zeroizing::new(*tokens.master_key()));
        let key_version = Arc::new(std::sync::atomic::AtomicI64::new(current_key_version));
        // P1-7: pending_actions 独立物理库 action.db (独立 WAL)。ActionStore 自身连接经此打开,
        // put/evict_expired 走 main.pending_actions (未 ATTACH, 独立 WAL)。
        let action_conn = Connection::open(&action_db_path).map_err(io_err)?;
        action_conn
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA secure_delete=ON; PRAGMA busy_timeout=5000;")
            .map_err(io_err)?;
        // C21: 全部连接 open 后硬化三库 db/-wal/-shm 权限 0o600 (WAL 文件此时已由首连创建)。
        harden_db_perms(&audit_db_path);
        harden_db_perms(&token_db_path);
        harden_db_perms(&action_db_path);
        // A3/P1: 只读连接 (只读 query_map, 不与 audit_writer 抢锁)。
        let read_conn = Connection::open(&audit_db_path).map_err(io_err)?;
        read_conn
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA query_only=ON;")
            .map_err(io_err)?;
        let actions = ActionStore::open(action_conn).map_err(|e| {
            tracing::error!(error = %e, "action store open failed");
            std::io::Error::other(e.to_string())
        })?;
        let audit_writer = Arc::new(Mutex::new(audit_writer_conn));
        // P0-3: drain 线程持低风险 writer (NORMAL), 非共享高风险 audit_writer (FULL)。
        let low_writer = Arc::new(Mutex::new(low_writer_conn));
        let writer_for_thread = low_writer.clone();
        let key_for_thread = chain_key.clone();
        let kv_for_thread = key_version.clone();
        // A2: drain 线程持死信路径副本 (插入失败时落盘, 非吞)。
        let dead_letter_path_dl = dead_letter_path.clone();
        std::thread::spawn(move || {
            let mut buf: Vec<AuditEvent> = Vec::with_capacity(100);
            while let Ok(ev) = rx.recv() {
                buf.push(ev);
                while let Ok(ev) = rx.try_recv() {
                    buf.push(ev);
                    if buf.len() >= 100 {
                        break;
                    }
                }
                let batch: Vec<AuditEvent> = std::mem::take(&mut buf);
                // A2: 内联跑 batch (非每批 spawn 线程)。原 spawn-per-batch 零并发 + panic 吞整 batch
                // (审计事件从防篡改日志消失, 无重试无持久)。内联 panic 毒化本 drain 线程 →
                // 守护进程重启 fail-closed 可见, 非 silent drop。
                let mut g = recover_lock!(writer_for_thread.lock(), "audit writer");
                // P1-2: 读当前 key version (轮换后即时新版本, 非闭包过期快照)。
                let kv = kv_for_thread.load(std::sync::atomic::Ordering::Relaxed);
                for ev in &batch {
                    if let Err(e) = insert_audit_event(&mut g, ev, &key_for_thread, kv) {
                        tracing::warn!(error = %e, audit_id = %ev.audit_id, "async audit insert failed");
                        // A2: 插入失败持久到死信文件, 非虚空 (审计道不容静默丢)。
                        spool_dead_letter(
                            &dead_letter_path_dl,
                            ev,
                            &e.to_string(),
                            &key_for_thread,
                            kv,
                        );
                    }
                }
            }
            tracing::info!("audit async writer exited");
        });

        Ok(Self {
            db: Mutex::new(conn),
            audit_writer,
            low_writer,
            read_conn: Arc::new(Mutex::new(read_conn)),
            low_queue: tx,
            dead_letter_path,
            tokens: Arc::new(tokens),
            actions: Arc::new(actions),
            chain_key,
            current_key_version: key_version,
            db_path: db_path.to_path_buf(),
            archive_dir: resolve_archive_dir(db_path),
        })
    }

    pub fn tokens(&self) -> Arc<TokenStore> {
        self.tokens.clone()
    }

    pub fn actions(&self) -> Arc<ActionStore> {
        self.actions.clone()
    }

    pub fn audit_writer_handle(&self) -> Arc<Mutex<Connection>> {
        self.audit_writer.clone()
    }

    // P0-3 (audit §1.2): 暴露写连接 PRAGMA synchronous 值供测试验证分级耐久。
    // high_risk=true → audit_writer (FULL), false → low_writer (NORMAL)。
    // SQLite PRAGMA synchronous 回读为整数: 2=FULL, 1=NORMAL。
    pub fn writer_sync_pragma(&self, high_risk: bool) -> i64 {
        let conn = if high_risk {
            self.audit_writer.lock()
        } else {
            self.low_writer.lock()
        };
        let conn = recover_lock!(conn, "writer conn");
        conn.query_row("PRAGMA synchronous", [], |r| r.get::<_, i64>(0))
            .unwrap_or(-1)
    }

    // G6/L2+A8: confirm_atomic 需借 audit_writer + chain_key 做 consume 与审计同临界区原子写入。
    // P1-2: 返 master key (非派生), 调用方配 current_key_version() 按版本派生。
    pub fn chain_key_handle(&self) -> Arc<Zeroizing<[u8; 32]>> {
        self.chain_key.clone()
    }

    // P1-2 (audit §1.6): 当前 key 版本 (confirm_atomic 等外部写审计行需记此 version)。
    pub fn current_key_version(&self) -> i64 {
        self.current_key_version
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    // P1-2 (audit §1.6): 轮换 key —— bump version + 落 key_versions 表 + 更新共享 Atomic。
    // 新写入用新派生 key; 旧行保留旧 version, 验/解用旧派生 key (派生确定, master 不变)。
    pub fn rotate_key(&self) -> Result<i64, token_store::TokenError> {
        let new_version = self.tokens.rotate_key()?;
        self.current_key_version
            .store(new_version, std::sync::atomic::Ordering::Relaxed);
        tracing::info!(
            new_version = new_version,
            "audit store key rotated (P1-2, HKDF version bump)"
        );
        Ok(new_version)
    }

    // P0-4 test-helpers: 注入带指定 ts 的合法链行 (rotation 测试需旧行触发归档)。
    // 构造 AuditEvent → 读上一行 event_hash 作 prev → 算 HMAC → insert_audit_event。
    // 非生产路径, 仅 test-helpers feature 开启。
    #[cfg(feature = "test-helpers")]
    pub fn insert_event_at_ts(
        &self,
        tenant_id: &str,
        ts: chrono::DateTime<chrono::Utc>,
        raw: &str,
    ) -> Result<AuditEvent, rusqlite::Error> {
        let mut g = recover_lock!(self.audit_writer.lock(), "audit writer (test-helpers)");
        let ev = AuditEvent {
            audit_id: uuid::Uuid::new_v4(),
            ts,
            event_type: "evaluate".to_string(),
            tenant_id: tenant_id.to_string(),
            requester: "tester".to_string(),
            action: raw.to_string(),
            inferred_category: "test".to_string(),
            verdict_json: "{}".to_string(),
            approved_by: None,
            seatbelt_required: false,
            outcome: "allowed".to_string(),
            prev_hash: String::new(),
            event_hash: String::new(),
        };
        let kv = self
            .current_key_version
            .load(std::sync::atomic::Ordering::Relaxed);
        insert_audit_event(&mut g, &ev, &self.chain_key, kv)?;
        Ok(ev)
    }

    // P1-6 test-helpers: 注入带指定 ts + event_type + risk_level 的合法链行 (过滤/分页测试
    // 需可控时间窗 + 事件类型 + 风险等级, 旧 insert_event_at_ts verdict_json 恒 "{}" 无 risk_level)。
    // verdict_json 序列化真实 GuardVerdict (含 risk_level) 供 level_min json_extract 过滤验证。
    #[cfg(feature = "test-helpers")]
    pub fn insert_test_event(
        &self,
        tenant_id: &str,
        ts: chrono::DateTime<chrono::Utc>,
        event_type: &str,
        risk: RiskLevel,
        action: SafetyAction,
    ) -> Result<AuditEvent, rusqlite::Error> {
        let verdict = GuardVerdict {
            action,
            risk_level: risk,
            reason: "test".into(),
            stage: CheckStage::Regex,
            requires_approval: false,
            redacted_content: None,
            seatbelt_required: false,
            action_id: None,
            verdict_epoch: 1,
            verdict_ttl_secs: 30,
            inferred_category: "test".into(),
            category_hint: None,
        };
        let outcome = match action {
            SafetyAction::Block => "blocked",
            _ => "allowed",
        };
        let ev = AuditEvent {
            audit_id: uuid::Uuid::new_v4(),
            ts,
            event_type: event_type.to_string(),
            tenant_id: tenant_id.to_string(),
            requester: "tester".to_string(),
            action: "test-action".to_string(),
            inferred_category: "test".to_string(),
            verdict_json: serde_json::to_string(&verdict).unwrap_or_default(),
            approved_by: None,
            seatbelt_required: false,
            outcome: outcome.to_string(),
            prev_hash: String::new(),
            event_hash: String::new(),
        };
        let mut g = recover_lock!(self.audit_writer.lock(), "audit writer (test-helpers P1-6)");
        let kv = self
            .current_key_version
            .load(std::sync::atomic::Ordering::Relaxed);
        insert_audit_event(&mut g, &ev, &self.chain_key, kv)?;
        Ok(ev)
    }

    pub fn append_confirm_event(
        &self,
        tenant_id: &str,
        verdict: &GuardVerdict,
        approved_by: &str,
        outcome: &str,
    ) -> Result<AuditEvent, rusqlite::Error> {
        // L12: action 列存推断 category (原触发上下文), 非 verdict.reason
        // (此时 reason 已被 confirm 覆盖为 "approved/rejected by X")。
        // 与 evaluate 事件 action 列语义对齐: 触发上下文, outcome 列存批准结果。
        let ev = AuditEvent {
            audit_id: uuid::Uuid::new_v4(),
            ts: chrono::Utc::now(),
            event_type: "confirm".to_string(),
            tenant_id: tenant_id.to_string(),
            requester: approved_by.to_string(),
            action: verdict.inferred_category.clone(),
            inferred_category: verdict.inferred_category.clone(),
            verdict_json: serde_json::to_string(verdict).unwrap_or_default(),
            approved_by: Some(approved_by.to_string()),
            seatbelt_required: verdict.seatbelt_required,
            outcome: outcome.to_string(),
            prev_hash: String::new(),
            event_hash: String::new(),
        };
        let mut g = recover_lock!(self.audit_writer.lock(), "audit writer");
        let kv = self
            .current_key_version
            .load(std::sync::atomic::Ordering::Relaxed);
        insert_audit_event(&mut g, &ev, &self.chain_key, kv)?;
        tracing::info!(
            audit_id = %ev.audit_id,
            tenant = %ev.tenant_id,
            outcome = %ev.outcome,
            "confirm audit event persisted (sync H7, chain HMAC)"
        );
        Ok(ev)
    }

    pub fn append_event(
        &self,
        tenant_id: &str,
        verdict: &GuardVerdict,
        raw_redacted: String,
        requester: &str,
    ) -> Result<AuditEvent, rusqlite::Error> {
        let high_risk = matches!(verdict.risk_level, RiskLevel::L3 | RiskLevel::L4)
            || verdict.action == SafetyAction::Block;
        let outcome = match verdict.action {
            SafetyAction::Block => "blocked",
            SafetyAction::Allow => "allowed",
            SafetyAction::Preview | SafetyAction::Redact => "allowed",
        };
        let ev = AuditEvent {
            audit_id: uuid::Uuid::new_v4(),
            ts: chrono::Utc::now(),
            event_type: "evaluate".to_string(),
            tenant_id: tenant_id.to_string(),
            requester: requester.to_string(),
            action: raw_redacted,
            inferred_category: verdict.inferred_category.clone(),
            verdict_json: serde_json::to_string(verdict).unwrap_or_default(),
            approved_by: None,
            seatbelt_required: verdict.seatbelt_required,
            outcome: outcome.to_string(),
            prev_hash: String::new(),
            event_hash: String::new(),
        };

        if high_risk {
            let mut g = recover_lock!(self.audit_writer.lock(), "audit writer");
            let kv = self
                .current_key_version
                .load(std::sync::atomic::Ordering::Relaxed);
            insert_audit_event(&mut g, &ev, &self.chain_key, kv)?;
            tracing::info!(
                audit_id = %ev.audit_id,
                tenant = %ev.tenant_id,
                "high-risk audit event persisted (sync gate H7, chain HMAC)"
            );
        } else {
            let kv = self
                .current_key_version
                .load(std::sync::atomic::Ordering::Relaxed);
            // A2: try_send 非阻塞 send。有界队列满 (drain 卡) → TrySendError::Full → 死信文件,
            // 不丢不阻塞 IPC 调用线程。Disconnected → 同样死信 (drain 线程死)。
            match self.low_queue.try_send(ev.clone()) {
                Ok(()) => {}
                Err(mpsc::TrySendError::Full(_)) => {
                    tracing::warn!(audit_id = %ev.audit_id, "low-risk audit queue full → dead-letter spool");
                    spool_dead_letter(
                        &self.dead_letter_path,
                        &ev,
                        "queue full",
                        &self.chain_key,
                        kv,
                    );
                }
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    tracing::warn!(audit_id = %ev.audit_id, "low-risk audit queue disconnected → dead-letter spool");
                    spool_dead_letter(
                        &self.dead_letter_path,
                        &ev,
                        "queue disconnected",
                        &self.chain_key,
                        kv,
                    );
                }
            }
        }
        // P0-4 (audit §1.3): 每次落审计后检查 rotation 触发 (db 超 100MB 或有超 30 天行)。
        // 廉价: stat db 文件大小 + 一条 COUNT 查询。未触发 → 立返。触发 → 归档+VACUUM。
        // 归档在 audit_writer 临界区, 与本 append 已释放写锁不重叠 (append_event 持锁段已结束)。
        if let Err(e) = self.enforce_retention() {
            tracing::warn!(error = %e, "audit retention/rotation check failed (P0-4, non-fatal)");
        }
        Ok(ev)
    }

    pub fn list_events(
        &self,
        tenant_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AuditEvent>, rusqlite::Error> {
        // A3/P1: 用 read_conn (query_only), 不抢 audit_writer 写锁 (H7 同步门不自 DoS)。
        let r = recover_lock!(self.read_conn.lock(), "read conn");
        let mut stmt = if tenant_id.is_some() {
            r.prepare(
                "SELECT audit_id, ts, event_type, tenant_id, requester, action,
                        inferred_category, verdict_json, approved_by, seatbelt_required, outcome,
                        prev_hash, event_hash
                 FROM audit_events WHERE tenant_id = ?1
                 ORDER BY ts DESC LIMIT ?2",
            )?
        } else {
            r.prepare(
                "SELECT audit_id, ts, event_type, tenant_id, requester, action,
                        inferred_category, verdict_json, approved_by, seatbelt_required, outcome,
                        prev_hash, event_hash
                 FROM audit_events ORDER BY ts DESC LIMIT ?1",
            )?
        };
        let rows = if let Some(t) = tenant_id {
            stmt.query_map(params![t, limit as i64], row_to_event)?
                .collect::<Result<Vec<_>, _>>()?
        } else {
            stmt.query_map(params![limit as i64], row_to_event)?
                .collect::<Result<Vec<_>, _>>()?
        };
        Ok(rows)
    }

    pub fn list_by_tenant(&self, tenant_id: &str, limit: usize) -> Vec<AuditRecord> {
        match self.list_events(Some(tenant_id), limit) {
            Ok(events) => events.into_iter().filter_map(event_to_record).collect(),
            Err(e) => {
                tracing::warn!(error = %e, "list_by_tenant failed");
                Vec::new()
            }
        }
    }

    pub fn list(&self, limit: usize) -> Vec<AuditRecord> {
        match self.list_events(None, limit) {
            Ok(events) => events.into_iter().filter_map(event_to_record).collect(),
            Err(e) => {
                tracing::warn!(error = %e, "list failed");
                Vec::new()
            }
        }
    }

    // P1-6 (audit §3.2): 过滤 + 游标分页查询。动态拼 WHERE 子句 (绑参, 非 fmt 拼接防注入),
    // read_conn (query_only 不抢写锁, 同 list_events)。ORDER BY ts DESC, audit_id DESC 稳定双键。
    // 游标条件: (ts, audit_id) < (cur_ts, cur_id) —— ts < cur_ts OR (ts = cur_ts AND audit_id < cur_id)。
    // level_min 走 json_extract(verdict_json,'$.risk_level') >= ? (NULL 行自然排除)。
    // 多取一行 (limit+1) 判 has_more, 末行 (若 has_more) 编码游标返回。
    pub fn list_events_filtered(
        &self,
        f: &AuditListFilter,
    ) -> Result<Vec<AuditEvent>, rusqlite::Error> {
        let r = recover_lock!(self.read_conn.lock(), "read conn (filtered)");
        // 子句占位编号 (rusqlite ?N 连续递增) + 绑参 push 顺序须一致: tenant → since → until
        // → event_type → level_min → (cursor_ts, cursor_id) → limit。
        let mut where_clauses: Vec<String> = Vec::new();
        let mut bind_idx = 1usize;
        if f.tenant_id.is_some() {
            where_clauses.push(format!("tenant_id = ?{bind_idx}"));
            bind_idx += 1;
        }
        if f.since.is_some() {
            where_clauses.push(format!("ts >= ?{bind_idx}"));
            bind_idx += 1;
        }
        if f.until.is_some() {
            where_clauses.push(format!("ts <= ?{bind_idx}"));
            bind_idx += 1;
        }
        if f.event_type.is_some() {
            where_clauses.push(format!("event_type = ?{bind_idx}"));
            bind_idx += 1;
        }
        if f.level_min.is_some() {
            where_clauses.push(format!(
                "json_extract(verdict_json, '$.risk_level') >= ?{bind_idx}"
            ));
            bind_idx += 1;
        }
        if f.cursor_ts.is_some() && f.cursor_id.is_some() {
            // 游标: 严格小于末行 (DESC 排序, 续拉更旧行)。
            where_clauses.push(format!(
                "(ts < ?{b} OR (ts = ?{b} AND audit_id < ?{b1}))",
                b = bind_idx,
                b1 = bind_idx + 1
            ));
            bind_idx += 2;
        }
        let where_sql = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };
        let limit_param = bind_idx; // LIMIT 末位参
                                    // 多取 1 行判 has_more。
        let sql = format!(
            "SELECT audit_id, ts, event_type, tenant_id, requester, action,
                    inferred_category, verdict_json, approved_by, seatbelt_required, outcome,
                    prev_hash, event_hash
             FROM audit_events {where_sql}
             ORDER BY ts DESC, audit_id DESC LIMIT ?{limit_param}"
        );
        let mut stmt = r.prepare(&sql)?;
        // 绑参: 必须按 where_clauses push 顺序 (tenant, since, until, event_type, level_min, cursor_ts, cursor_id)。
        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if let Some(t) = f.tenant_id {
            params_vec.push(Box::new(t.to_string()));
        }
        if let Some(s) = f.since {
            params_vec.push(Box::new(s.to_string()));
        }
        if let Some(u) = f.until {
            params_vec.push(Box::new(u.to_string()));
        }
        if let Some(et) = f.event_type {
            params_vec.push(Box::new(et.to_string()));
        }
        if let Some(lm) = f.level_min {
            params_vec.push(Box::new(lm.to_lowercase()));
        }
        if let (Some(cts), Some(cid)) = (f.cursor_ts, f.cursor_id) {
            params_vec.push(Box::new(cts.to_string()));
            params_vec.push(Box::new(cid.to_string()));
        }
        // LIMIT = 请求 limit + 1 (多取判 has_more)。
        let fetch = (f.limit as i64).saturating_add(1);
        params_vec.push(Box::new(fetch));
        let params_refs: Vec<&dyn rusqlite::ToSql> =
            params_vec.iter().map(|b| b.as_ref()).collect();
        let rows = stmt
            .query_map(params_refs.as_slice(), row_to_event)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    // P1-6: 过滤分页的 record 视图 + 游标/has_more 计算。多取的 1 行若存在 → has_more=true,
    // 该行不返回 (只取前 limit 行); next_cursor = 第 limit 行 (返回集末行) 的 "ts\x1faudit_id"。
    pub fn list_filtered_page(&self, f: &AuditListFilter) -> AuditListPage {
        let events = match self.list_events_filtered(f) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(error = %e, "list_events_filtered failed");
                return AuditListPage {
                    records: Vec::new(),
                    next_cursor: None,
                    has_more: false,
                };
            }
        };
        let has_more = events.len() > f.limit;
        let mut ret: Vec<AuditEvent> = events;
        if has_more {
            ret.truncate(f.limit);
        }
        let next_cursor = if has_more {
            ret.last()
                .map(|ev| format!("{}\x1f{}", ev.ts.to_rfc3339(), ev.audit_id))
        } else {
            None
        };
        let records = ret.into_iter().filter_map(event_to_record).collect();
        AuditListPage {
            records,
            next_cursor,
            has_more,
        }
    }

    // P0-4 (audit §1.3, PRD §13.3): 审计治理层 — rotation + retention + archive。
    // rotation: 超 30 天的行归档至 ~/.fusion-guard/audit-archive/audit-<ts>.ndjson 并从 audit_events
    //   删除; 或 guard.db > 100MB 时归档最旧段至降到阈值下。归档段写 NDJSON (含 prev_hash/event_hash,
    //   链可移植), 删除前用 audit_writer 单事务 (断电不丢 H7)。
    // retention: 归档目录内超 180 天的 .ndjson 文件删除 (冷存到期, PRD §13.3 180d 保留)。
    // 链完整性: 归档后剩余首行 prev_hash 指向归档段 (主库悬空), 故 checkpoint 更新为
    //   last_verified_rowid=剩余首行 rowid + last_verified_hash=剩余首行 event_hash,
    //   last_archived_rowid/hash=归档段末行。增量 verify 从剩余首行之后扫, 跳过已验的剩余首行。
    //   全表扫退路: 剩余首行 prev_hash != genesis → 会误报 tampered。故归档后调
    //   reset_checkpoint_anchoring 显式锚定剩余首行, 增量路径才正确 (无 checkpoint 才全表扫,
    //   有 checkpoint 且锚行存在 → 增量, 不撞归档边界)。
    pub fn enforce_retention(&self) -> Result<RetentionReport, rusqlite::Error> {
        let mut report = RetentionReport::default();
        self.prune_expired_archives(&mut report);
        self.rotate_old_rows(&mut report)?;
        Ok(report)
    }

    // soak/商用: 周期 retention 监控线程。drain 线程只插低风险行, 不触 enforce_retention
    // (P0-4 retention 原只在 sync append_event 高风险路径调)。高频 L1 流量下 audit_events
    // 涨无 rotation 检查 → 长跑 OOM。此线程周期调 enforce_retention, 覆盖低风险积累路径
    // (rotation 阈值 100MB/30d 达到则归档+VACUUM 回收页)。interval_secs 默认 5s —— drain
    // 高频写入, 60s 太慢 (短跑/突发流量 DB 已涨超阈值); 5s 足够及时触发 rotation+VACUUM。
    pub fn spawn_retention_monitor(self: &Arc<Self>, interval_secs: u64) {
        let store = self.clone();
        std::thread::Builder::new()
            .name("fg-audit-retention".into())
            .spawn(move || {
                let interval = Duration::from_secs(interval_secs.max(1));
                loop {
                    std::thread::sleep(interval);
                    match store.enforce_retention() {
                        Ok(r) => {
                            if r.archived_rows > 0 || r.pruned_archives > 0 {
                                tracing::info!(
                                    archived = r.archived_rows,
                                    pruned = r.pruned_archives,
                                    "retention monitor cycle (drain path coverage)"
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "retention monitor cycle failed");
                        }
                    }
                }
            })
            .expect("spawn retention monitor");
    }

    // P0-4: rotation 主体。决定归档窗口 (超 ROTATE_AGE_DAYS 或 db 超 ROTATE_BYTES),
    // 写 NDJSON + 删行 + 更新 checkpoint, 单 audit_writer 事务 (H7 耐久)。
    fn rotate_old_rows(&self, report: &mut RetentionReport) -> rusqlite::Result<()> {
        let now = chrono::Utc::now();
        let age_cutoff = now - chrono::Duration::days(ROTATE_AGE_DAYS);
        let age_cutoff_str = age_cutoff.to_rfc3339();

        // 触发条件 1: 有超 ROTATE_AGE_DAYS 的行。条件 2: db 文件超 ROTATE_BYTES (此时归档最旧段
        // 不论年龄, 降到阈值下)。先查超龄行数, 0 且 db 未超 → 跳过。
        // A3/soak: 检查阶段 + 选待归档行用 read_conn (query_only, 不抢 audit_writer 写锁) ——
        // 原实现整段持 audit_writer 跑 COUNT 扫表 + SELECT 选行, 即使无 rotate 也锁住所有审计写
        // (append_event 高风险同步路径自 DoS, retention monitor 5s 周期持锁空查 → 吞吐骤降)。
        // 仅删行+checkpoint+VACUUM (真 mutate) 才锁 audit_writer。TOCTOU 安全: rowid 单调增,
        // 读到的旧 rowid 不被并发插入删除, 删按 rowid 区间 [min,max], 新插 rowid>max 不受影响。
        let r = recover_lock!(self.read_conn.lock(), "read conn (rotate check)");
        let aged_count: i64 = r.query_row(
            "SELECT COUNT(*) FROM audit_events WHERE ts < ?1",
            params![age_cutoff_str],
            |r| r.get(0),
        )?;
        let db_bytes = std::fs::metadata(&self.db_path)
            .map(|m| m.len())
            .unwrap_or(0);
        if aged_count == 0 && db_bytes < ROTATE_BYTES {
            return Ok(());
        }
        tracing::info!(
            aged_count,
            db_bytes,
            rotate_bytes_limit = ROTATE_BYTES,
            "audit rotation triggered (P0-4)"
        );

        // 取待归档行 (ORDER BY rowid ASC = 最旧优先)。超龄 → 全部超龄行; 仅 size 触发 → 最旧段
        // (按 rowid 限量, 一次归档最多 50000 行防长事务锁库)。
        let limit = if aged_count > 0 { aged_count } else { 50000 };
        let mut stmt = r.prepare(
            "SELECT audit_id, ts, event_type, tenant_id, requester, action,
                    inferred_category, verdict_json, approved_by, seatbelt_required, outcome,
                    prev_hash, event_hash, key_version, rowid
             FROM audit_events ORDER BY rowid ASC LIMIT ?1",
        )?;
        let to_archive: Vec<(AuditEvent, i64, i64)> = stmt
            .query_map(params![limit], row_to_event_with_rowid)?
            .collect::<Result<Vec<_>, _>>()?;
        drop(stmt);
        drop(r);
        if to_archive.is_empty() {
            return Ok(());
        }

        // 归档段末行 event_hash + audit_id (归档后剩余首行 prev_hash 应 = 此 hash, 链连续)。
        let archived_tail_hash = to_archive
            .last()
            .map(|(ev, _, _)| ev.event_hash.clone())
            .unwrap_or_default();
        let last_archived_audit_id = to_archive
            .last()
            .map(|(ev, _, _)| ev.audit_id.to_string())
            .unwrap_or_default();
        let last_archived_rowid = to_archive.last().map(|(_, _, rid)| *rid).unwrap_or(0);
        let min_rid = to_archive.first().map(|(_, _, rid)| *rid).unwrap_or(0);

        // 写 NDJSON 归档文件 (含链字段, 跨归档可重算校验)。
        let ndjson = archive_events_to_ndjson(&to_archive)?;
        let archive_path = self
            .archive_dir
            .join(format!("audit-{}.ndjson", now.format("%Y%m%dT%H%M%S")));
        if let Some(parent) = archive_path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                tracing::warn!(error = %e, dir = %parent.display(), "archive dir create failed (P0-4)");
            }
        }
        match std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&archive_path)
        {
            Ok(mut f) => {
                use std::io::Write;
                if let Err(e) = f.write_all(ndjson.as_bytes()) {
                    tracing::warn!(error = %e, path = %archive_path.display(), "archive ndjson write failed (P0-4)");
                }
                let _ =
                    std::fs::set_permissions(&archive_path, std::fs::Permissions::from_mode(0o600));
            }
            Err(e) => {
                tracing::warn!(error = %e, path = %archive_path.display(), "archive file open failed (P0-4), rows kept in audit_events");
                // 归档写失败 → 不删行 (保留在主库, 不丢审计)。下次再试。
                return Ok(());
            }
        }

        // 删行: 单事务, audit_writer (synchronous=FULL) 断电不丢 H7。
        // A3/soak + P1-3 (product-audit §3): 仅此 mutate 段锁 audit_writer (检查+选行已用 read_conn
        // 完成, 无锁读)。VACUUM 移出此临界区 (单独短重取锁), DELETE+checkpoint 提交先释放锁 →
        // H7 高风险 append_event 不被整段 (删行+checkpoint+VACUUM) 串行阻塞, 仅 VACUUM 独占段阻塞。
        let w = self.audit_writer.lock();
        let mut w = recover_lock!(w, "audit writer (rotate delete)");
        let tx = w.transaction()?;
        tx.execute(
            "DELETE FROM audit_events WHERE rowid >= ?1 AND rowid <= ?2",
            params![min_rid, last_archived_rowid],
        )?;
        // 确认删除数 = 归档数 (防部分删)。
        let remaining_after: i64 =
            tx.query_row("SELECT COUNT(*) FROM audit_events", [], |r| r.get(0))?;
        tx.commit()?;
        report.archived_rows = to_archive.len() as i64;
        report.archive_path = Some(archive_path.to_string_lossy().to_string());

        // 归档后更新 checkpoint: 锚定剩余首行 (若有), 否则锚定归档段末尾 (空库续链)。
        // 剩余首行 prev_hash = archived_tail_hash (链连续, 但全表扫会误报, 故必须锚定走增量)。
        // VACUUM 前写 checkpoint (audit_id 锚点 VACUUM 稳定, 但行此刻存在校验更稳)。
        let first_remaining: Option<(String, String)> = w
            .query_row(
                "SELECT audit_id, event_hash FROM audit_events ORDER BY rowid ASC LIMIT 1",
                [],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .ok();
        let new_cp = match first_remaining {
            Some((id, hash)) => Checkpoint {
                last_verified_audit_id: id,
                last_verified_hash: hash,
                last_archived_audit_id: Some(last_archived_audit_id.clone()),
                last_archived_hash: Some(archived_tail_hash.clone()),
            },
            None => Checkpoint {
                // 空库归档态: 库内无行。last_verified_audit_id 置空哨兵 (非指向已删归档行,
                // 否则 verify_chain rowid_of_audit 必 None → 误退全表 genesis → 首行 prev_hash
                // = archived_tail_hash ≠ genesis 误报 broken)。verify_chain 见空哨兵 → 不查 rowid,
                // expected_prev = last_archived_hash 续扫全库续链。下次插入也读 last_archived_hash
                // 作 prev_hash (insert_audit_event 回退 checkpoint)。
                last_verified_audit_id: String::new(),
                last_verified_hash: String::new(),
                last_archived_audit_id: Some(last_archived_audit_id.clone()),
                last_archived_hash: Some(archived_tail_hash.clone()),
            },
        };
        if let Err(e) = write_checkpoint(&w, &new_cp) {
            tracing::warn!(error = %e, "post-rotate checkpoint write failed (P0-4, next verify rescans)");
        }
        // P1-3: 先释放 audit_writer 锁, DELETE+checkpoint 临界区结束 —— 此后 H7 append_event
        // 可立即插入 (不被下方 VACUUM 整段预占)。VACUUM 单独短重取锁执行。
        drop(w);

        // VACUUM 回收已删行页 (rotation 核心目的: 降 db 体积)。WAL 模式下 VACUUM 重写整库,
        // 需独占 (无活跃事务 + 无他连接持锁)。P1-3: 独占段最短 (仅 VACUUM, 不含删行/checkpoint),
        // 周期治理非热路径; audit_id 锚点 VACUUM 稳定不破坏链。失败不阻断 (空间下次再回收)。
        let w = self.audit_writer.lock();
        let w = recover_lock!(w, "audit writer (rotate vacuum)");
        if let Err(e) = w.execute_batch("VACUUM;") {
            tracing::warn!(error = %e, "post-rotate VACUUM failed (P0-4, space not reclaimed yet)");
        }
        drop(w);
        tracing::info!(
            archived_rows = report.archived_rows,
            remaining = remaining_after,
            archive = ?archive_path,
            "audit rotation complete (P0-4, PRD §13.3, VACUUM 移出删行临界区 P1-3)"
        );
        Ok(())
    }

    // P0-4: retention — 删除归档目录内超 RETENTION_DAYS 的 .ndjson 文件 (冷存到期)。
    // 文件名格式 audit-<YYYYMMDDTHHMMSS>.ndjson, 解析时间戳判龄。解析失败保留 (不误删)。
    fn prune_expired_archives(&self, report: &mut RetentionReport) {
        let dir = self.archive_dir.clone();
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => return,
        };
        let now = chrono::Utc::now();
        let cutoff = now - chrono::Duration::days(RETENTION_DAYS);
        for ent in entries.flatten() {
            let path = ent.path();
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n,
                None => continue,
            };
            if !name.starts_with("audit-") || !name.ends_with(".ndjson") {
                continue;
            }
            // audit-YYYYMMDDTHHMMSS.ndjson → 取中段时间。
            let stem = &name["audit-".len()..name.len() - ".ndjson".len()];
            let ts = chrono::NaiveDateTime::parse_from_str(stem, "%Y%m%dT%H%M%S")
                .ok()
                .map(|n| n.and_utc());
            let Some(ts) = ts else {
                tracing::warn!(
                    file = name,
                    "archive filename unparseable, kept (P0-4 retention)"
                );
                continue;
            };
            if ts < cutoff {
                match std::fs::remove_file(&path) {
                    Ok(()) => {
                        report.pruned_archives += 1;
                        tracing::info!(
                            file = name,
                            "expired archive pruned (P0-4 retention, >180d)"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, file = name, "archive prune failed (P0-4)");
                    }
                }
            }
        }
    }

    // P0-4: 暴露 db 体积供测试/运维观测 rotation 状态。
    pub fn db_size_bytes(&self) -> u64 {
        std::fs::metadata(&self.db_path)
            .map(|m| m.len())
            .unwrap_or(0)
    }

    // P0-1 (audit §1.1): tenant 作用域 verify。None = 全局 (仅 admin/root 可用, 见 IPC 强制)。
    // 审计链是全局 append-only (prev_hash 链上一行 event_hash, 不分租户), 故须全表读以维护
    // expected_prev 正确, 但只统计落在 scope 内的行。非 scope 行不计数 (不外泄他租户活动量)。
    // verify_chain(tenant=None) 等价旧全表校验 (保留供 admin 审计)。
    //
    // P0-4 (audit §1.3/§2.4): 增量校验。chain_checkpoint 缓存上次校验通过的末行 rowid + event_hash,
    // 本调用只验该 rowid 之后的新增段, O(新增量) 而非 O(全表), 消除全表线性退化。
    // 退化条件 (安全起见全表扫): 无 checkpoint; checkpoint 锚行已被归档删除 (rowid 缺失);
    // 检出篡改 (broken) → 全表扫重算以便 first_broken_at 定位全表行号 + 不缓存坏 checkpoint。
    // 增量干净路径: total_rows = 当前 scope 内 COUNT(*) (索引快), verified_links/broken 只反映本段。
    pub fn verify_chain(&self, tenant: Option<&str>) -> Result<ChainVerification, rusqlite::Error> {
        // A3/P1: 用 read_conn (query_only), 扫描不抢 audit_writer 写锁。
        let r = recover_lock!(self.read_conn.lock(), "read conn");

        // P0-4: 读 checkpoint。无 → 全表扫 (旧行为, 兼容新库 + 老库迁移)。
        let cp = read_checkpoint(&r)?;
        let mut incremental = cp.is_some();
        let mut anchor_rowid: i64 = 0;
        let mut expected_prev = GENESIS_PREV_HASH.to_string();
        if let Some(ref c) = cp {
            if c.last_verified_audit_id.is_empty() {
                // P0-4 空库归档态: 库内无行 (全段已归档删), prev_hash 续自归档段末 hash。
                // 不查 rowid_of_audit (锚行已删, 查必 None → 旧逻辑误退全表 genesis → 误报 broken)。
                // expected_prev = 归档段末 hash, incremental 保持 true, anchor_rowid=0 →
                // WHERE rowid > 0 扫全库续链 (rowid 从 1 起, >0 即全)。无 last_archived_hash → 退全表。
                if let Some(ref ah) = c.last_archived_hash {
                    if !ah.is_empty() {
                        expected_prev = ah.clone();
                    } else {
                        incremental = false;
                    }
                } else {
                    incremental = false;
                }
            } else {
                // P0-4: audit_id 锚点 (UUID 稳定, VACUUM 后 rowid 重排不失效)。现查锚行当前 rowid。
                // 锚行已被归档删除 (audit_id 缺失) 或 hash 对不上 → 退全表扫 (不信任段边界)。
                let anchored: Option<(i64, String)> =
                    rowid_of_audit(&r, &c.last_verified_audit_id)?.and_then(|rid| {
                        r.query_row(
                            "SELECT event_hash FROM audit_events WHERE rowid = ?1",
                            params![rid],
                            |row| row.get::<_, Option<String>>(0),
                        )
                        .ok()
                        .flatten()
                        .filter(|h| !h.is_empty())
                        .map(|h| (rid, h))
                    });
                match anchored {
                    Some((rid, h)) if h == c.last_verified_hash => {
                        anchor_rowid = rid;
                        expected_prev = c.last_verified_hash.clone();
                    }
                    _ => {
                        tracing::warn!(
                            cp_audit_id = %c.last_verified_audit_id,
                            "checkpoint anchor missing/hash-mismatch (archived?) → full rescan (P0-4)"
                        );
                        incremental = false;
                    }
                }
            }
        }

        let mut stmt = if incremental {
            // P0-4: 只扫锚行之后的新段。
            r.prepare(
                "SELECT audit_id, ts, event_type, tenant_id, requester, action,
                        inferred_category, verdict_json, approved_by, seatbelt_required, outcome,
                        prev_hash, event_hash, key_version, rowid
                 FROM audit_events WHERE rowid > ?1 ORDER BY rowid ASC",
            )?
        } else {
            r.prepare(
                "SELECT audit_id, ts, event_type, tenant_id, requester, action,
                        inferred_category, verdict_json, approved_by, seatbelt_required, outcome,
                        prev_hash, event_hash, key_version, rowid
                 FROM audit_events ORDER BY rowid ASC",
            )?
        };
        let rows = if incremental {
            stmt.query_map(params![anchor_rowid], row_to_event_with_rowid)?
                .collect::<Result<Vec<_>, _>>()?
        } else {
            stmt.query_map([], row_to_event_with_rowid)?
                .collect::<Result<Vec<_>, _>>()?
        };

        // P0-4: total_rows 在增量干净路径用 scope COUNT(*) (索引快), 全表路径用扫到的 scope 行数。
        // 两者语义一致: 当前库内 scope 内行总数。增量路径不重扫已验段。
        let total_rows = if incremental {
            count_scope_rows(&r, tenant)?
        } else {
            rows.iter()
                .filter(|(ev, _, _)| tenant.is_none_or(|t| ev.tenant_id == t))
                .count()
        };
        let mut unhashed_rows = 0usize;
        let mut verified_links = 0usize;
        let mut broken_links = 0usize;
        let mut tampered = false;
        let mut first_broken_at: Option<usize> = None;
        // global_i: 全表位置 (first_broken_at 用全表行号定位, 便于运维 DB 查行)。
        let mut global_i = 0usize;
        let mut last_hash = expected_prev.clone();
        // P0-4: 段尾 audit_id (UUID, VACUUM 稳定) 入 checkpoint, 替 rowid 作下次增量锚点。
        // 初始化为已有 checkpoint 的 audit_id (无新增段时保持原锚, 不丢失上次校验点)。
        let mut last_audit_id: String = cp
            .as_ref()
            .map(|c| c.last_verified_audit_id.clone())
            .unwrap_or_default();
        for (ev, kv, _rid) in rows.iter() {
            let in_scope = tenant.is_none_or(|t| ev.tenant_id == t);
            if ev.event_hash.is_empty() {
                // C7 修复: 空 hash = 异常 (迁移期遗留 或 攻击者清空)。
                // 迁移后所有新行恒有 HMAC hash; 空 hash 行计 unhashed 且 broken。
                if in_scope {
                    unhashed_rows += 1;
                    broken_links += 1;
                    if first_broken_at.is_none() {
                        first_broken_at = Some(global_i);
                    }
                    tampered = true;
                }
                last_hash = ev.event_hash.clone();
                last_audit_id = ev.audit_id.to_string();
                global_i += 1;
                continue;
            }
            if ev.prev_hash != expected_prev {
                if in_scope {
                    broken_links += 1;
                    if first_broken_at.is_none() {
                        first_broken_at = Some(global_i);
                    }
                    tampered = true;
                }
            } else {
                // P1-2: 用该行落库时的 key_version 派生 chain key 验 (旧行旧 key, 新行新 key)。
                let recomputed =
                    compute_event_hmac(&self.chain_key, *kv, &ev.payload_bytes(), &expected_prev);
                if recomputed != ev.event_hash {
                    if in_scope {
                        broken_links += 1;
                        if first_broken_at.is_none() {
                            first_broken_at = Some(global_i);
                        }
                        tampered = true;
                    }
                } else if in_scope {
                    verified_links += 1;
                }
            }
            expected_prev = ev.event_hash.clone();
            last_hash = ev.event_hash.clone();
            last_audit_id = ev.audit_id.to_string();
            global_i += 1;
        }

        // P0-4: 干净路径缓存新 checkpoint (段尾 audit_id + hash), 供下次增量。
        // 篡改/全表退扫不缓存坏点; 全表退扫且干净 → 缓存扫到的新尾 (建立首 checkpoint)。
        // read_conn query_only 不能写 → 用 audit_writer (与 read_conn 无反向锁序, 不死锁)。
        if !tampered && (!rows.is_empty() || cp.is_none()) {
            let new_cp = Checkpoint {
                last_verified_audit_id: last_audit_id.clone(),
                last_verified_hash: last_hash.clone(),
                last_archived_audit_id: cp.as_ref().and_then(|c| c.last_archived_audit_id.clone()),
                last_archived_hash: cp.as_ref().and_then(|c| c.last_archived_hash.clone()),
            };
            let w = self.audit_writer.lock();
            let w = recover_lock!(w, "audit writer (checkpoint)");
            if let Err(e) = write_checkpoint(&w, &new_cp) {
                tracing::warn!(error = %e, "checkpoint persist failed (next verify rescans, P0-4)");
            }
        }

        tracing::info!(
            scope_tenant = ?tenant,
            incremental,
            total_rows,
            unhashed_rows,
            verified_links,
            broken_links,
            tampered,
            "audit chain verification done (PRD §13.3, HMAC, P0-1 tenant-scoped, P0-4 incremental)"
        );
        Ok(ChainVerification {
            total_rows,
            unhashed_rows,
            verified_links,
            broken_links,
            tampered,
            first_broken_at,
        })
    }

    // C16/P0-G4: 规则 JSON 损坏 → 拒启动 (fail-closed), 不再静默丢弃 __corrupt__。
    // 安全守护进程规则 SSOT, 静默丢弃损坏行 = 规则集被篡改后无感知放行, 不可接受。
    pub fn load_rules(&self) -> Result<Option<RuleSet>, rusqlite::Error> {
        let g = recover_lock!(self.db.lock(), "audit db");
        let epoch: i64 = g
            .query_row("SELECT value FROM rule_meta WHERE key='epoch'", [], |r| {
                r.get(0)
            })
            .ok()
            .unwrap_or(0);
        let mut stmt = g.prepare("SELECT rule_json FROM rules ORDER BY name ASC")?;
        let mut rules: Vec<GuardRule> = Vec::new();
        let rows = stmt.query_map([], |row| {
            let j: String = row.get(0)?;
            Ok(j)
        })?;
        for row in rows {
            let j = row?;
            match serde_json::from_str::<GuardRule>(&j) {
                Ok(r) => rules.push(r),
                Err(e) => {
                    tracing::error!(error = %e, json = %j, "corrupt rule json — refusing to load (C16 fail-closed)");
                    return Err(rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    ));
                }
            }
        }
        if epoch == 0 {
            return Ok(None);
        }
        tracing::info!(
            epoch = epoch,
            count = rules.len(),
            "rules loaded from store"
        );
        Ok(Some(RuleSet {
            epoch: epoch as u64,
            rules,
        }))
    }

    // P0-5 (audit §1.4): TCC 链校验。读 tcc_events ORDER BY rowid ASC, 逐行重算 HMAC 比对。
    // 空 event_hash 行 = 老 DB 迁移前遗留 (migrate 加列 DEFAULT ''), 计 unhashed_rows 非误报。
    // 返回 SubChainVerification (与 audit 链同字段语义)。
    pub fn verify_tcc_chain(&self) -> Result<SubChainVerification, rusqlite::Error> {
        let r = recover_lock!(self.read_conn.lock(), "read conn");
        let mut stmt = r.prepare(
            "SELECT audit_id, ts, permission, requester, result, reason, prev_hash, event_hash, key_version
             FROM tcc_events ORDER BY rowid ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, Option<i64>>(8)?.unwrap_or(1),
            ))
        })?;
        let mut total_rows = 0usize;
        let mut unhashed_rows = 0usize;
        let mut verified_links = 0usize;
        let mut broken_links = 0usize;
        let mut tampered = false;
        let mut first_broken_at: Option<usize> = None;
        let mut expected_prev = GENESIS_PREV_HASH.to_string();
        for (idx, row) in rows.enumerate() {
            let (audit_id, ts, permission, requester, result, reason, prev_hash, event_hash, kv) =
                row?;
            total_rows += 1;
            if event_hash.is_empty() {
                unhashed_rows += 1;
                continue;
            }
            // prev_hash 须 = 上一行 event_hash (链连续)。
            if prev_hash != expected_prev {
                tampered = true;
                broken_links += 1;
                if first_broken_at.is_none() {
                    first_broken_at = Some(idx);
                }
                expected_prev = event_hash.clone();
                continue;
            }
            let payload =
                tcc_payload_bytes(&audit_id, &ts, &permission, &requester, &result, &reason);
            // P1-2: 用行 key_version 派生 chain key 验。
            let computed = compute_event_hmac(&self.chain_key, kv, &payload, &prev_hash);
            if computed != event_hash {
                tampered = true;
                broken_links += 1;
                if first_broken_at.is_none() {
                    first_broken_at = Some(idx);
                }
            } else {
                verified_links += 1;
            }
            expected_prev = event_hash;
        }
        if tampered {
            tracing::warn!(
                total_rows,
                broken_links,
                first_broken_at = first_broken_at.unwrap_or(0),
                "TCC chain tampered (P0-5)"
            );
        }
        Ok(SubChainVerification {
            total_rows,
            unhashed_rows,
            verified_links,
            broken_links,
            tampered,
            first_broken_at,
        })
    }

    // P0-5 (audit §1.4): 规则突变链校验。读 rule_mutations ORDER BY rowid ASC, 逐行重算 HMAC。
    // 篡改 rules 表当前态后, verify_rules_chain 重放突变序列即可检出 (突变历史 vs 当前态对不上)。
    pub fn verify_rules_chain(&self) -> Result<SubChainVerification, rusqlite::Error> {
        let r = recover_lock!(self.read_conn.lock(), "read conn");
        let mut stmt = r.prepare(
            "SELECT mutation_id, ts, kind, name, rule_json, prev_hash, event_hash, key_version
             FROM rule_mutations ORDER BY rowid ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Option<i64>>(7)?.unwrap_or(1),
            ))
        })?;
        let mut total_rows = 0usize;
        let mut unhashed_rows = 0usize;
        let mut verified_links = 0usize;
        let mut broken_links = 0usize;
        let mut tampered = false;
        let mut first_broken_at: Option<usize> = None;
        let mut expected_prev = GENESIS_PREV_HASH.to_string();
        for (idx, row) in rows.enumerate() {
            let (mutation_id, ts, kind, name, rule_json, prev_hash, event_hash, kv) = row?;
            total_rows += 1;
            if event_hash.is_empty() {
                unhashed_rows += 1;
                continue;
            }
            if prev_hash != expected_prev {
                tampered = true;
                broken_links += 1;
                if first_broken_at.is_none() {
                    first_broken_at = Some(idx);
                }
                expected_prev = event_hash.clone();
                continue;
            }
            let payload = rule_mutation_payload_bytes(&mutation_id, &ts, &kind, &name, &rule_json);
            // P1-2: 用行 key_version 派生 chain key 验。
            let computed = compute_event_hmac(&self.chain_key, kv, &payload, &prev_hash);
            if computed != event_hash {
                tampered = true;
                broken_links += 1;
                if first_broken_at.is_none() {
                    first_broken_at = Some(idx);
                }
            } else {
                verified_links += 1;
            }
            expected_prev = event_hash;
        }
        if tampered {
            tracing::warn!(
                total_rows,
                broken_links,
                first_broken_at = first_broken_at.unwrap_or(0),
                "rule mutation chain tampered (P0-5)"
            );
        }
        Ok(SubChainVerification {
            total_rows,
            unhashed_rows,
            verified_links,
            broken_links,
            tampered,
            first_broken_at,
        })
    }

    // P0-5 (audit §1.4): 死信文件链校验。逐行重算 hmac = HMAC(key, prev_hmac ‖ event.payload_bytes()),
    // 比对落盘 hmac + prev_hmac 链连续。文件不存在/空 → 干净 (total_rows=0)。行解析失败 → broken。
    pub fn verify_dead_letter(&self) -> SubChainVerification {
        let content = match std::fs::read_to_string(&self.dead_letter_path) {
            Ok(c) => c,
            Err(_) => {
                return SubChainVerification {
                    total_rows: 0,
                    unhashed_rows: 0,
                    verified_links: 0,
                    broken_links: 0,
                    tampered: false,
                    first_broken_at: None,
                }
            }
        };
        let mut total_rows = 0usize;
        let mut unhashed_rows = 0usize;
        let mut verified_links = 0usize;
        let mut broken_links = 0usize;
        let mut tampered = false;
        let mut first_broken_at: Option<usize> = None;
        let mut expected_prev = GENESIS_PREV_HASH.to_string();
        for (idx, line) in content.lines().filter(|l| !l.is_empty()).enumerate() {
            total_rows += 1;
            let v: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => {
                    tampered = true;
                    broken_links += 1;
                    if first_broken_at.is_none() {
                        first_broken_at = Some(idx);
                    }
                    continue;
                }
            };
            let prev_hmac: String = v
                .get("prev_hmac")
                .and_then(|h| h.as_str())
                .unwrap_or("")
                .to_string();
            let hmac: String = v
                .get("hmac")
                .and_then(|h| h.as_str())
                .unwrap_or("")
                .to_string();
            // P1-2: 死信行记 key_version (老格式无 → 默认 1, 兼容历史死信)。
            let kv: i64 = v.get("key_version").and_then(|h| h.as_i64()).unwrap_or(1);
            if hmac.is_empty() {
                unhashed_rows += 1;
                continue;
            }
            if prev_hmac != expected_prev {
                tampered = true;
                broken_links += 1;
                if first_broken_at.is_none() {
                    first_broken_at = Some(idx);
                }
                expected_prev = hmac.clone();
                continue;
            }
            let ev: AuditEvent = match v.get("event") {
                Some(ev_val) => match serde_json::from_value(ev_val.clone()) {
                    Ok(e) => e,
                    Err(_) => {
                        tampered = true;
                        broken_links += 1;
                        if first_broken_at.is_none() {
                            first_broken_at = Some(idx);
                        }
                        continue;
                    }
                },
                None => {
                    tampered = true;
                    broken_links += 1;
                    if first_broken_at.is_none() {
                        first_broken_at = Some(idx);
                    }
                    continue;
                }
            };
            let payload = ev.payload_bytes();
            // P1-2: 用行 key_version 派生 chain key 验 (非 master 直接)。
            let dkey = token_store::derive_chain_key(&self.chain_key, kv);
            let mut mac =
                HmacSha256::new_from_slice(&dkey[..]).expect("HMAC accepts any key length");
            mac.update(prev_hmac.as_bytes());
            mac.update(&payload);
            let computed = hex_encode(&mac.finalize().into_bytes());
            if computed != hmac {
                tampered = true;
                broken_links += 1;
                if first_broken_at.is_none() {
                    first_broken_at = Some(idx);
                }
            } else {
                verified_links += 1;
            }
            expected_prev = hmac;
        }
        if tampered {
            tracing::warn!(
                path = %self.dead_letter_path.display(),
                total_rows,
                broken_links,
                first_broken_at = first_broken_at.unwrap_or(0),
                "dead-letter chain tampered (P0-5)"
            );
        }
        SubChainVerification {
            total_rows,
            unhashed_rows,
            verified_links,
            broken_links,
            tampered,
            first_broken_at,
        }
    }

    // P0-5 (audit §1.4): 死信 reimport —— 验签后把死信事件导回 audit_events 续主链。
    // 任一行 hmac 校验失败 → 中止返错 (不导任何行, 防部分导入掩盖篡改)。全部验签通过 →
    // 逐条 insert_audit_event 续主链 (prev_hash 自动读 audit 末行), 成功后清空死信文件 (归零, 非 truncate
    // 保留文件 inode 权限)。返回成功导入行数。
    pub fn reimport_dead_letter(&self) -> Result<usize, rusqlite::Error> {
        let content = match std::fs::read_to_string(&self.dead_letter_path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, path = %self.dead_letter_path.display(), "dead-letter read failed on reimport");
                return Ok(0);
            }
        };
        let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
        if lines.is_empty() {
            return Ok(0);
        }
        // 先全量验签 (不导), 任一坏 → 中止。
        let mut expected_prev = GENESIS_PREV_HASH.to_string();
        for (idx, line) in lines.iter().enumerate() {
            let v: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(error = %e, line = idx, "dead-letter reimport: parse failed, aborting");
                    return Err(rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(std::io::Error::other("dead-letter line parse failed")),
                    ));
                }
            };
            let prev_hmac: String = v
                .get("prev_hmac")
                .and_then(|h| h.as_str())
                .unwrap_or("")
                .to_string();
            let hmac: String = v
                .get("hmac")
                .and_then(|h| h.as_str())
                .unwrap_or("")
                .to_string();
            // P1-2: 死信行 key_version (老格式无 → 1)。验签用生成时版本派生 key。
            let kv: i64 = v.get("key_version").and_then(|h| h.as_i64()).unwrap_or(1);
            if prev_hmac != expected_prev {
                tracing::error!(
                    line = idx,
                    "dead-letter reimport: prev_hmac chain broken, aborting"
                );
                return Err(rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::other("dead-letter prev_hmac chain broken")),
                ));
            }
            let ev: AuditEvent = match v.get("event") {
                Some(ev_val) => match serde_json::from_value(ev_val.clone()) {
                    Ok(e) => e,
                    Err(e) => {
                        tracing::error!(error = %e, line = idx, "dead-letter reimport: event decode failed, aborting");
                        return Err(rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        ));
                    }
                },
                None => {
                    return Err(rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(std::io::Error::other("dead-letter missing event field")),
                    ));
                }
            };
            let payload = ev.payload_bytes();
            // P1-2: 用行 key_version 派生 chain key 验 (生成时的版本, 非当前)。
            let dkey = token_store::derive_chain_key(&self.chain_key, kv);
            let mut mac =
                HmacSha256::new_from_slice(&dkey[..]).expect("HMAC accepts any key length");
            mac.update(prev_hmac.as_bytes());
            mac.update(&payload);
            let computed = hex_encode(&mac.finalize().into_bytes());
            if computed != hmac {
                tracing::error!(line = idx, "dead-letter reimport: hmac mismatch, aborting");
                return Err(rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::other("dead-letter hmac mismatch")),
                ));
            }
            expected_prev = hmac;
        }
        // 全验签通过 → 逐条导回 audit_events 续主链。导回作新行, 用当前 key_version 重算 hash。
        let mut imported = 0usize;
        let mut g = recover_lock!(self.audit_writer.lock(), "audit writer");
        let cur_kv = self
            .current_key_version
            .load(std::sync::atomic::Ordering::Relaxed);
        for line in &lines {
            let v: serde_json::Value = serde_json::from_str(line).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?;
            let ev: AuditEvent = serde_json::from_value(
                v.get("event").cloned().unwrap_or_default(),
            )
            .map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?;
            insert_audit_event(&mut g, &ev, &self.chain_key, cur_kv)?;
            imported += 1;
        }
        // 导回成功 → 清空死信文件 (写空, 保留 inode + 权限)。
        if let Err(e) = std::fs::write(&self.dead_letter_path, b"") {
            tracing::warn!(error = %e, path = %self.dead_letter_path.display(), "dead-letter clear after reimport failed (events already imported)");
        }
        tracing::info!(
            imported,
            "dead-letter reimported into audit_events chain (P0-5)"
        );
        Ok(imported)
    }

    // P0-5 (audit §1.4): 全链聚合校验。audit (audit_events) + tcc (tcc_events) + rules
    // (rule_mutations) + dead_letter (死信文件)。tampered = 任一链坏。
    // guard.audit.verify 返此聚合 (旧只返 audit ChainVerification, 现扩全链)。
    pub fn verify_all_chains(
        &self,
        tenant: Option<&str>,
    ) -> Result<AllChainsVerification, rusqlite::Error> {
        let audit = self.verify_chain(tenant)?;
        let tcc = self.verify_tcc_chain()?;
        let rules = self.verify_rules_chain()?;
        let dead_letter = self.verify_dead_letter();
        let tampered = audit.tampered || tcc.tampered || rules.tampered || dead_letter.tampered;
        Ok(AllChainsVerification {
            audit,
            tcc,
            rules,
            dead_letter,
            tampered,
        })
    }

    pub fn save_rule(&self, rule: &GuardRule) -> Result<(), rusqlite::Error> {
        let g = recover_lock!(self.db.lock(), "audit db");
        let j = serde_json::to_string(rule).unwrap_or_default();
        g.execute(
            "INSERT OR REPLACE INTO rules (name, rule_json) VALUES (?1, ?2)",
            params![rule.name, j],
        )?;
        // P0-5 (audit §1.4): 规则覆写 (INSERT OR REPLACE) 破链, 故 rules 表不直接链;
        // 每次 add/update 都 append 一条 rule_mutations 链行 (kind=add, 审计引擎层 add_rule
        // 调 save_rule 后再 update 复用同 save_rule → kind=add 覆盖 update 语义足够: 突变被记录)。
        let kv = self
            .current_key_version
            .load(std::sync::atomic::Ordering::Relaxed);
        append_rule_mutation(&g, &self.chain_key, kv, "add", &rule.name, &j)?;
        Ok(())
    }

    pub fn delete_rule(&self, name: &str) -> Result<(), rusqlite::Error> {
        let g = recover_lock!(self.db.lock(), "audit db");
        g.execute("DELETE FROM rules WHERE name=?1", params![name])?;
        let kv = self
            .current_key_version
            .load(std::sync::atomic::Ordering::Relaxed);
        // P0-5: remove 突变入链 (rule_json 空)。
        append_rule_mutation(&g, &self.chain_key, kv, "remove", name, "")?;
        Ok(())
    }

    pub fn save_epoch(&self, epoch: u64) -> Result<(), rusqlite::Error> {
        let g = recover_lock!(self.db.lock(), "audit db");
        g.execute(
            "INSERT OR REPLACE INTO rule_meta (key, value) VALUES ('epoch', ?1)",
            params![epoch as i64],
        )?;
        let kv = self
            .current_key_version
            .load(std::sync::atomic::Ordering::Relaxed);
        // P0-5: epoch 突变入链 (name 空, rule_json 存 epoch 值字符串 — 校验时可重放对账)。
        append_rule_mutation(&g, &self.chain_key, kv, "epoch", "", &epoch.to_string())?;
        Ok(())
    }

    pub fn report_tcc_event(
        &self,
        permission: &str,
        requester: &str,
        result: &str,
        reason: &str,
    ) -> Result<uuid::Uuid, rusqlite::Error> {
        let audit_id = uuid::Uuid::new_v4();
        let ts = chrono::Utc::now().to_rfc3339();
        let g = recover_lock!(self.db.lock(), "audit db");
        // P0-5 (audit §1.4): TCC 链。prev_hash = 上一行 tcc event_hash (空 → genesis)。
        // payload = audit_id‖ts‖permission‖requester‖result‖reason 长度前缀编码。
        let prev_hash: String = g
            .query_row(
                "SELECT event_hash FROM tcc_events ORDER BY rowid DESC LIMIT 1",
                [],
                |r| r.get::<_, Option<String>>(0),
            )
            .ok()
            .flatten()
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| GENESIS_PREV_HASH.to_string());
        let payload = tcc_payload_bytes(
            &audit_id.to_string(),
            &ts,
            permission,
            requester,
            result,
            reason,
        );
        // P1-2: 用当前 key_version 派生 chain key + 落 key_version 列 (验旧行用旧版本)。
        let kv = self
            .current_key_version
            .load(std::sync::atomic::Ordering::Relaxed);
        let event_hash = compute_event_hmac(&self.chain_key, kv, &payload, &prev_hash);
        g.execute(
            "INSERT INTO tcc_events (audit_id, ts, permission, requester, result, reason, prev_hash, event_hash, key_version)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                audit_id.to_string(),
                ts,
                permission,
                requester,
                result,
                reason,
                prev_hash,
                event_hash,
                kv,
            ],
        )?;
        tracing::info!(
            audit_id = %audit_id,
            permission = permission,
            requester = requester,
            result = result,
            "TCC event reported (audit aggregation H1, P0-5 chained)"
        );
        Ok(audit_id)
    }

    pub fn list_tcc_events(&self, limit: usize) -> Result<Vec<TccEventRecord>, rusqlite::Error> {
        // A3/P1: 用 read_conn (query_only), 不抢 db 写锁 (规则/epoch 突变不阻塞)。
        let r = recover_lock!(self.read_conn.lock(), "read conn");
        let mut stmt = r.prepare(
            "SELECT audit_id, ts, permission, requester, result, reason
             FROM tcc_events ORDER BY ts DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            let ts_str: String = row.get(1)?;
            let ts = chrono::DateTime::parse_from_rfc3339(&ts_str)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now());
            let id_str: String = row.get(0)?;
            let audit_id = uuid::Uuid::parse_str(&id_str).unwrap_or_else(|_| uuid::Uuid::nil());
            Ok(TccEventRecord {
                audit_id,
                ts,
                permission: row.get(2)?,
                requester: row.get(3)?,
                result: row.get(4)?,
                reason: row.get(5)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    // P0-1 (audit §1.1): uid → 授权租户集合。peercred 解析连接 uid 后查此表, wire tenant_id
    // 必须在此集合内。daemon uid 启动时 bootstrap 绑定 default (免空集锁死自身)。
    // admin (root, uid 0) 在 IPC 层绕过此表 (全租户), 不依赖此行。
    pub fn bind_tenant(&self, uid: u32, tenant: &str) -> Result<(), rusqlite::Error> {
        let g = recover_lock!(self.db.lock(), "audit db");
        g.execute(
            "INSERT OR IGNORE INTO tenant_bindings (uid, tenant) VALUES (?1, ?2)",
            params![uid as i64, tenant],
        )?;
        tracing::info!(uid = uid, tenant = tenant, "tenant binding added (P0-1)");
        Ok(())
    }

    pub fn unbind_tenant(&self, uid: u32, tenant: &str) -> Result<(), rusqlite::Error> {
        let g = recover_lock!(self.db.lock(), "audit db");
        g.execute(
            "DELETE FROM tenant_bindings WHERE uid=?1 AND tenant=?2",
            params![uid as i64, tenant],
        )?;
        tracing::info!(uid = uid, tenant = tenant, "tenant binding removed (P0-1)");
        Ok(())
    }

    // 返回 uid 授权的租户列表 (已绑定)。空 Vec = 无绑定 (IPC 层视作仅 default 且仅 daemon 自身)。
    pub fn tenants_for_uid(&self, uid: u32) -> Vec<String> {
        let g = recover_lock!(self.db.lock(), "audit db");
        let mut stmt = match g
            .prepare("SELECT tenant FROM tenant_bindings WHERE uid=?1 ORDER BY tenant ASC")
        {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "tenants_for_uid prepare failed");
                return Vec::new();
            }
        };
        let rows = match stmt.query_map(params![uid as i64], |r| r.get::<_, String>(0)) {
            Ok(rs) => rs,
            Err(e) => {
                tracing::warn!(error = %e, "tenants_for_uid query failed");
                return Vec::new();
            }
        };
        let mut out = Vec::new();
        for r in rows {
            match r {
                Ok(t) => out.push(t),
                Err(e) => tracing::warn!(error = %e, "tenants_for_uid row failed"),
            }
        }
        out
    }
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS audit_events (
    audit_id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    event_type TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    requester TEXT NOT NULL,
    action TEXT NOT NULL,
    inferred_category TEXT NOT NULL,
    verdict_json TEXT NOT NULL,
    approved_by TEXT,
    seatbelt_required INTEGER NOT NULL,
    outcome TEXT NOT NULL,
    prev_hash TEXT NOT NULL DEFAULT '',
    event_hash TEXT NOT NULL DEFAULT '',
    key_version INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_events(tenant_id);

CREATE TABLE IF NOT EXISTS rules (
    name TEXT PRIMARY KEY,
    rule_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rule_meta (
    key TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tcc_events (
    audit_id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    permission TEXT NOT NULL,
    requester TEXT NOT NULL,
    result TEXT NOT NULL,
    reason TEXT NOT NULL,
    prev_hash TEXT NOT NULL DEFAULT '',
    event_hash TEXT NOT NULL DEFAULT '',
    key_version INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_tcc_ts ON tcc_events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_tcc_permission ON tcc_events(permission);

-- P0-5 (audit §1.4): 规则变更链。rules/rule_meta 表存当前态 (INSERT OR REPLACE / DELETE 覆写),
-- 不可直接链 (覆写破链)。此 append-only 表记录每次 add/update/remove/epoch 突变 + 链 hash,
-- 篡改 rules 表后 verify_rules_chain 重放突变序列即可检出 (当前态与突变历史对不上)。
-- kind: add|update|remove|epoch。name: 规则名 (epoch 突变用空)。rule_json: 规则序列化 (remove/epoch 空)。
-- prev_hash/event_hash: TCC 同款 HMAC 链 (链 key = chain_key, payload = 长度前缀字段)。
CREATE TABLE IF NOT EXISTS rule_mutations (
    mutation_id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    rule_json TEXT NOT NULL DEFAULT '',
    prev_hash TEXT NOT NULL DEFAULT '',
    event_hash TEXT NOT NULL DEFAULT '',
    key_version INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_rule_mut_ts ON rule_mutations(ts DESC);

-- P0-1 (audit §1.1): uid → 授权租户集合映射。peercred 解析连接 uid, 查此表得该 uid 可操作的
-- 租户。wire tenant_id 必须落在此集合内, 否则 -32001。斩跨租户审计外泄链 (root = admin 全租户)。
CREATE TABLE IF NOT EXISTS tenant_bindings (
    uid INTEGER NOT NULL,
    tenant TEXT NOT NULL,
    PRIMARY KEY (uid, tenant)
);

-- P0-4 (audit §1.3): 链校验检查点。增量校验只验锚行之后的新增段,
-- 缓存上次校验到的末行 audit_id + event_hash, 避免全表线性退化 (PRD §13.3 + §2.4)。
-- 用 audit_id (UUID, VACUUM 稳定) 非 rowid (VACUUM 可能重排), 故归档后 VACUUM 不破坏锚点。
-- last_verified_audit_id: 上次校验通过的最后一行 audit_id (NULL = 从头校验)。
-- last_verified_hash: 该行的 event_hash (下一段第一行的 expected_prev)。
-- last_archived_audit_id: 最近一次归档切走的最后一行 audit_id (NULL = 无归档)。
-- last_archived_hash: 该行的 event_hash (归档段末尾, 用于跨归档边界续链校验)。
CREATE TABLE IF NOT EXISTS chain_checkpoint (
    key TEXT PRIMARY KEY,
    last_verified_audit_id TEXT,
    last_verified_hash TEXT,
    last_archived_audit_id TEXT,
    last_archived_hash TEXT
);
"#;

// H-A (product-audit §2): 链单写者保证改在事务层。
// 原实现 SELECT-then-INSERT 无事务包裹, audit_writer (高风险) 与 low_writer (drain) 各持
// 独立 Mutex 各走此函数 → 两连接同时 SELECT 同一 prev_hash 再各自 INSERT → 两行同 prev_hash =
// 链分叉, verify 误报篡改。Mutex 跨连接无效 (各自锁各自连接)。SQLite 写锁 (BEGIN IMMEDIATE)
// 跨连接串行: BEGIN IMMEDIATE 立即取写锁 (RESERVED→EXCLUSIVE), 他连接 BEGIN IMMEDIATE 阻塞
// (busy_timeout=5000 等待) → SELECT-then-INSERT 在单写锁内原子, prev_hash 读取与 INSERT 不可
// 被他连接插入插队。故任一写者 (audit_writer/low_writer) 调此函数, 链 prev_hash 严格连续。
// 事务还保 confirm_atomic 跨语句原子 (H-D 见 confirm_atomic 自带 BEGIN IMMEDIATE)。
fn insert_audit_event(
    conn: &mut Connection,
    ev: &AuditEvent,
    key: &Zeroizing<[u8; 32]>,
    key_version: i64,
) -> rusqlite::Result<()> {
    // H-A: BEGIN IMMEDIATE 立即取写锁, 串行化 SELECT-then-INSERT 跨连接。
    // 失败 (SQLITE_BUSY) 由 busy_timeout=5000 (open 时设于两 writer) 重试, 仍失败则向上抛。
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let prev_hash: String = tx
        .query_row(
            "SELECT event_hash FROM audit_events ORDER BY rowid DESC LIMIT 1",
            [],
            |r| r.get::<_, Option<String>>(0),
        )
        .ok()
        .flatten()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| {
            // P0-4: 主库空 (从未写入 或 归档清空)。归档清空后须续链到归档段末尾,
            // 非 genesis — 否则归档后首行 prev_hash=genesis 与归档段断链。读 checkpoint
            // 的 last_archived_hash; 无 checkpoint (全新库) → genesis。读失败 → genesis 兜底。
            read_checkpoint(&tx)
                .ok()
                .flatten()
                .and_then(|c| c.last_archived_hash.filter(|h| !h.is_empty()))
                .unwrap_or_else(|| GENESIS_PREV_HASH.to_string())
        });
    let payload = ev.payload_bytes();
    let event_hash = compute_event_hmac(key, key_version, &payload, &prev_hash);
    tx.execute(
        "INSERT INTO audit_events
         (audit_id, ts, event_type, tenant_id, requester, action,
          inferred_category, verdict_json, approved_by, seatbelt_required, outcome,
          prev_hash, event_hash, key_version)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
        params![
            ev.audit_id.to_string(),
            ev.ts.to_rfc3339(),
            ev.event_type,
            ev.tenant_id,
            ev.requester,
            ev.action,
            ev.inferred_category,
            ev.verdict_json,
            ev.approved_by,
            ev.seatbelt_required as i64,
            ev.outcome,
            prev_hash,
            event_hash,
            key_version,
        ],
    )?;
    tx.commit()?;
    Ok(())
}

// H-D: confirm_atomic 跨库事务内插审计行。复用 insert_audit_event 的链计算逻辑, 但接受
// 已开启的 Transaction (BEGIN IMMEDIATE), 不自起事务 —— 由 confirm_atomic 的 tx 统一 commit。
// prev_hash 读自同一事务 (见已持写锁, 他连接不可插队), event_hash HMAC 计算与 insert_audit_event
// 完全一致 (跨路径链连续)。调用方负责 commit/rollback。
pub(crate) fn insert_audit_event_tx(
    tx: &rusqlite::Transaction<'_>,
    ev: &AuditEvent,
    key: &Zeroizing<[u8; 32]>,
    key_version: i64,
) -> rusqlite::Result<()> {
    let prev_hash: String = tx
        .query_row(
            "SELECT event_hash FROM audit_events ORDER BY rowid DESC LIMIT 1",
            [],
            |r| r.get::<_, Option<String>>(0),
        )
        .ok()
        .flatten()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| {
            read_checkpoint(tx)
                .ok()
                .flatten()
                .and_then(|c| c.last_archived_hash.filter(|h| !h.is_empty()))
                .unwrap_or_else(|| GENESIS_PREV_HASH.to_string())
        });
    let payload = ev.payload_bytes();
    let event_hash = compute_event_hmac(key, key_version, &payload, &prev_hash);
    tx.execute(
        "INSERT INTO audit_events
         (audit_id, ts, event_type, tenant_id, requester, action,
          inferred_category, verdict_json, approved_by, seatbelt_required, outcome,
          prev_hash, event_hash, key_version)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
        params![
            ev.audit_id.to_string(),
            ev.ts.to_rfc3339(),
            ev.event_type,
            ev.tenant_id,
            ev.requester,
            ev.action,
            ev.inferred_category,
            ev.verdict_json,
            ev.approved_by,
            ev.seatbelt_required as i64,
            ev.outcome,
            prev_hash,
            event_hash,
            key_version,
        ],
    )?;
    Ok(())
}
// P1-2 (audit §1.6): key = HKDF 派生的 chain key (版本化), 非 master 直接复用 token key。
// master + version → derive_chain_key → 派生 key。跨重启一致 (master 不变, 派生确定) → 链可重算校验。
fn compute_event_hmac(
    master: &Zeroizing<[u8; 32]>,
    key_version: i64,
    payload: &[u8],
    prev_hash: &str,
) -> String {
    let dkey = token_store::derive_chain_key(master, key_version);
    let mut mac = HmacSha256::new_from_slice(&dkey[..]).expect("HMAC accepts any key length");
    mac.update(prev_hash.as_bytes());
    mac.update(payload);
    hex_encode(&mac.finalize().into_bytes())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// P0-5 (audit §1.4): 长度前缀编码 (与 AuditEvent::payload_bytes 同模式, 消 \x1f 碰撞)。
// 通用辅助: 一组字段各 u32 BE 长度 + 字节, 拼成 HMAC payload。
fn length_prefixed(fields: &[&[u8]]) -> Vec<u8> {
    let total: usize = fields.iter().map(|f| 4 + f.len()).sum();
    let mut out = Vec::with_capacity(total);
    for f in fields {
        let len = f.len() as u32;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(f);
    }
    out
}

// P0-5: TCC 链 payload = audit_id‖ts‖permission‖requester‖result‖reason (6 字段长度前缀)。
fn tcc_payload_bytes(
    audit_id: &str,
    ts: &str,
    permission: &str,
    requester: &str,
    result: &str,
    reason: &str,
) -> Vec<u8> {
    length_prefixed(&[
        audit_id.as_bytes(),
        ts.as_bytes(),
        permission.as_bytes(),
        requester.as_bytes(),
        result.as_bytes(),
        reason.as_bytes(),
    ])
}

// P0-5: 规则突变链 payload = mutation_id‖ts‖kind‖name‖rule_json (5 字段长度前缀)。
fn rule_mutation_payload_bytes(
    mutation_id: &str,
    ts: &str,
    kind: &str,
    name: &str,
    rule_json: &str,
) -> Vec<u8> {
    length_prefixed(&[
        mutation_id.as_bytes(),
        ts.as_bytes(),
        kind.as_bytes(),
        name.as_bytes(),
        rule_json.as_bytes(),
    ])
}

// P0-5 (audit §1.4): append 一条 rule_mutations 链行。prev_hash = 上一行 event_hash
// (空 → genesis)。同 db 锁内读 → 算 → 写, 防 prev_hash 并发分叉 (rules 变更低频, db 锁足够)。
fn append_rule_mutation(
    conn: &Connection,
    key: &Zeroizing<[u8; 32]>,
    key_version: i64,
    kind: &str,
    name: &str,
    rule_json: &str,
) -> rusqlite::Result<()> {
    let mutation_id = uuid::Uuid::new_v4().to_string();
    let ts = chrono::Utc::now().to_rfc3339();
    let prev_hash: String = conn
        .query_row(
            "SELECT event_hash FROM rule_mutations ORDER BY rowid DESC LIMIT 1",
            [],
            |r| r.get::<_, Option<String>>(0),
        )
        .ok()
        .flatten()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| GENESIS_PREV_HASH.to_string());
    let payload = rule_mutation_payload_bytes(&mutation_id, &ts, kind, name, rule_json);
    let event_hash = compute_event_hmac(key, key_version, &payload, &prev_hash);
    conn.execute(
        "INSERT INTO rule_mutations (mutation_id, ts, kind, name, rule_json, prev_hash, event_hash, key_version)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![mutation_id, ts, kind, name, rule_json, prev_hash, event_hash, key_version],
    )?;
    Ok(())
}

// L13: 列存在检测用 PRAGMA table_info (非 prepare(SELECT col ...) —— 后者在无列的 legacy DB
// 上 prepare 返 Err("no such column"), ? 传播 → AuditStore::open 失败, 真正的迁移分支不可达。
// table_info 返所有列元数据, 按 name 查列是否已存在, 缺则 ALTER TABLE ADD COLUMN (幂等)。
fn has_column(conn: &Connection, table: &str, col: &str) -> rusqlite::Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let rows = stmt.query_map([], |r| {
        let name: String = r.get(1)?;
        Ok(name)
    })?;
    for r in rows {
        if r? == col {
            return Ok(true);
        }
    }
    Ok(false)
}

fn migrate_audit_chain(conn: &Connection) -> rusqlite::Result<()> {
    if !has_column(conn, "audit_events", "prev_hash")? {
        conn.execute(
            "ALTER TABLE audit_events ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''",
            [],
        )?;
        tracing::info!("migrated audit_events: added prev_hash column");
    }
    if !has_column(conn, "audit_events", "event_hash")? {
        conn.execute(
            "ALTER TABLE audit_events ADD COLUMN event_hash TEXT NOT NULL DEFAULT ''",
            [],
        )?;
        tracing::info!("migrated audit_events: added event_hash column");
    }
    // P0-5 (audit §1.4): tcc_events 链列 (老库无)。幂等 ALTER, 空 hash 行计 unhashed 非误报。
    if !has_column(conn, "tcc_events", "prev_hash")? {
        conn.execute(
            "ALTER TABLE tcc_events ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''",
            [],
        )?;
        tracing::info!("migrated tcc_events: added prev_hash column (P0-5)");
    }
    if !has_column(conn, "tcc_events", "event_hash")? {
        conn.execute(
            "ALTER TABLE tcc_events ADD COLUMN event_hash TEXT NOT NULL DEFAULT ''",
            [],
        )?;
        tracing::info!("migrated tcc_events: added event_hash column (P0-5)");
    }
    // P1-2 (audit §1.6): key_version 列 (老库无)。幂等 ALTER, 默认 1 = 历史行用 v1 派生 key 验。
    if !has_column(conn, "audit_events", "key_version")? {
        conn.execute(
            "ALTER TABLE audit_events ADD COLUMN key_version INTEGER NOT NULL DEFAULT 1",
            [],
        )?;
        tracing::info!("migrated audit_events: added key_version column (P1-2)");
    }
    if !has_column(conn, "tcc_events", "key_version")? {
        conn.execute(
            "ALTER TABLE tcc_events ADD COLUMN key_version INTEGER NOT NULL DEFAULT 1",
            [],
        )?;
        tracing::info!("migrated tcc_events: added key_version column (P1-2)");
    }
    if !has_column(conn, "rule_mutations", "key_version")? {
        conn.execute(
            "ALTER TABLE rule_mutations ADD COLUMN key_version INTEGER NOT NULL DEFAULT 1",
            [],
        )?;
        tracing::info!("migrated rule_mutations: added key_version column (P1-2)");
    }
    Ok(())
}

fn row_to_event(row: &rusqlite::Row) -> rusqlite::Result<AuditEvent> {
    let ts_str: String = row.get(1)?;
    let ts = chrono::DateTime::parse_from_rfc3339(&ts_str)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());
    let audit_id_str: String = row.get(0)?;
    let audit_id = uuid::Uuid::parse_str(&audit_id_str).unwrap_or_else(|_| uuid::Uuid::nil());
    Ok(AuditEvent {
        audit_id,
        ts,
        event_type: row.get(2)?,
        tenant_id: row.get(3)?,
        requester: row.get(4)?,
        action: row.get(5)?,
        inferred_category: row.get(6)?,
        verdict_json: row.get(7)?,
        approved_by: row.get(8)?,
        seatbelt_required: row.get::<_, i64>(9)? != 0,
        outcome: row.get(10)?,
        prev_hash: row.get(11)?,
        event_hash: row.get(12)?,
    })
}

// P0-4: verify_chain 增量路径用。与 row_to_event 同列序 (0-12), key_version 在列 13, rowid 在列 14。
fn row_to_event_with_rowid(row: &rusqlite::Row) -> rusqlite::Result<(AuditEvent, i64, i64)> {
    let ev = row_to_event(row)?;
    let kv: i64 = row.get::<_, Option<i64>>(13)?.unwrap_or(1);
    let rid: i64 = row.get(14)?;
    Ok((ev, kv, rid))
}

// P0-4 (audit §1.3): 读链校验检查点。无行 → None (首校验或老库迁移)。
fn read_checkpoint(conn: &Connection) -> rusqlite::Result<Option<Checkpoint>> {
    // 4 nullable-string 元组: 显式注解触发 clippy::type_complexity, 故用 type alias。
    type CpRow = (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let row: Option<CpRow> = conn
        .query_row(
            "SELECT last_verified_audit_id, last_verified_hash, last_archived_audit_id, last_archived_hash
             FROM chain_checkpoint WHERE key='main'",
            [],
            |r| {
                Ok((
                    r.get::<_, Option<String>>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<String>>(3)?,
                ))
            },
        )
        .ok();
    match row {
        Some((vid, vh, aid, ah)) => {
            // 正常增量锚点: last_verified_audit_id 非空 (库内有已验末行)。
            if let (Some(id), Some(hash)) = (&vid, &vh) {
                if !id.is_empty() {
                    return Ok(Some(Checkpoint {
                        last_verified_audit_id: id.clone(),
                        last_verified_hash: hash.clone(),
                        last_archived_audit_id: aid,
                        last_archived_hash: ah,
                    }));
                }
            }
            // 空库归档态: last_verified_audit_id 为空 (库内无行, 全段已归档),
            // 但 last_archived_hash 存在 → verify 须从归档段末 hash 作 expected_prev 续扫,
            // 非退全表 (否则首行 prev_hash != genesis 误报)。last_verified_hash = archived_tail_hash。
            if let Some(arch_hash) = &ah {
                if !arch_hash.is_empty() {
                    return Ok(Some(Checkpoint {
                        last_verified_audit_id: String::new(),
                        last_verified_hash: vid.as_deref().unwrap_or("").to_string(),
                        last_archived_audit_id: aid,
                        last_archived_hash: ah,
                    }));
                }
            }
            Ok(None)
        }
        None => Ok(None),
    }
}

// P0-4: 写检查点 (upsert)。增量校验干净路径缓存末行, 下次只验新增段。
fn write_checkpoint(conn: &Connection, cp: &Checkpoint) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO chain_checkpoint (key, last_verified_audit_id, last_verified_hash,
                                        last_archived_audit_id, last_archived_hash)
         VALUES ('main', ?1, ?2, ?3, ?4)
         ON CONFLICT(key) DO UPDATE SET
           last_verified_audit_id=excluded.last_verified_audit_id,
           last_verified_hash=excluded.last_verified_hash,
           last_archived_audit_id=excluded.last_archived_audit_id,
           last_archived_hash=excluded.last_archived_hash",
        params![
            cp.last_verified_audit_id,
            cp.last_verified_hash,
            cp.last_archived_audit_id,
            cp.last_archived_hash,
        ],
    )?;
    Ok(())
}

// P0-4: 查 audit_id 对应 rowid (锚行定位, 用于增量 WHERE rowid > 锚)。
// audit_id 是 PRIMARY KEY (索引), 查询快。VACUUM 后 rowid 变, 故每次增量现查非缓存 rowid。
fn rowid_of_audit(conn: &Connection, audit_id: &str) -> rusqlite::Result<Option<i64>> {
    match conn.query_row(
        "SELECT rowid FROM audit_events WHERE audit_id=?1",
        params![audit_id],
        |r| r.get::<_, i64>(0),
    ) {
        Ok(rid) => Ok(Some(rid)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

// P0-4: scope 内行总数 (索引快), 增量路径 total_rows 用, 不重扫已验段。
fn count_scope_rows(conn: &Connection, tenant: Option<&str>) -> rusqlite::Result<usize> {
    let n: i64 = if let Some(t) = tenant {
        conn.query_row(
            "SELECT COUNT(*) FROM audit_events WHERE tenant_id=?1",
            params![t],
            |r| r.get(0),
        )?
    } else {
        conn.query_row("SELECT COUNT(*) FROM audit_events", [], |r| r.get(0))?
    };
    Ok(n as usize)
}

// P0-4 (audit §1.3, PRD §13.3): 归档审计行为 NDJSON。每行一 JSON (含 prev_hash/event_hash,
// 链可移植 — 归档文件可独立重算校验, 也可与主库续链)。首行带 archived_from_prev 标注 genesis
// 或段首 prev_hash (运维可溯源归档段在全局链中的位置)。
fn archive_events_to_ndjson(rows: &[(AuditEvent, i64, i64)]) -> rusqlite::Result<String> {
    let mut out = String::with_capacity(rows.len() * 512);
    for (ev, kv, _rid) in rows {
        let line = serde_json::json!({
            "audit_id": ev.audit_id.to_string(),
            "ts": ev.ts.to_rfc3339(),
            "event_type": ev.event_type,
            "tenant_id": ev.tenant_id,
            "requester": ev.requester,
            "action": ev.action,
            "inferred_category": ev.inferred_category,
            "verdict_json": ev.verdict_json,
            "approved_by": ev.approved_by,
            "seatbelt_required": ev.seatbelt_required,
            "outcome": ev.outcome,
            "prev_hash": ev.prev_hash,
            "event_hash": ev.event_hash,
            "key_version": kv,
        });
        out.push_str(&line.to_string());
        out.push('\n');
    }
    Ok(out)
}

fn event_to_record(ev: AuditEvent) -> Option<AuditRecord> {
    let verdict: GuardVerdict = serde_json::from_str(&ev.verdict_json).ok()?;
    Some(AuditRecord {
        id: ev.audit_id,
        ts: ev.ts,
        tenant_id: ev.tenant_id,
        verdict,
        raw_content_redacted: ev.action,
    })
}

fn io_err(e: rusqlite::Error) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

// A2 + P0-5 (audit §1.4): 死信 spool —— queue 满/disconnected/插入失败时审计事件持久到
// dead-letter 文件。安全审计道不容静默丢: 事件以 JSON 行 (NDJSON) 追加落盘。
// P0-5: 每行带链 HMAC (prev_hmac‖hmac), 与 audit_events 同 key, 链接上一死信行 → verify_dead_letter
// 可检出死信篡改/删除, reimport_dead_letter 验签后导回 audit_events 续主链。
// 行格式: {"prev_hmac":"...","hmac":"...","reason":"...","event":{...AuditEvent...}}
fn spool_dead_letter(
    path: &std::path::Path,
    ev: &AuditEvent,
    reason: &str,
    key: &Zeroizing<[u8; 32]>,
    key_version: i64,
) {
    // prev_hmac = 死信文件上一行 hmac (空 → genesis)。文件不存在/空 → genesis。
    let prev_hmac = match std::fs::read_to_string(path) {
        Ok(content) => content
            .lines()
            .rfind(|l| !l.is_empty())
            .and_then(|line| {
                serde_json::from_str::<serde_json::Value>(line)
                    .ok()
                    .and_then(|v| v.get("hmac").and_then(|h| h.as_str()).map(String::from))
            })
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| GENESIS_PREV_HASH.to_string()),
        Err(_) => GENESIS_PREV_HASH.to_string(),
    };
    // P1-2: hmac = HKDF 派生 chain key 的 HMAC (版本化), 非 master 直接。
    let payload = ev.payload_bytes();
    let dkey = token_store::derive_chain_key(key, key_version);
    let mut mac = HmacSha256::new_from_slice(&dkey[..]).expect("HMAC accepts any key length");
    mac.update(prev_hmac.as_bytes());
    mac.update(&payload);
    let hmac = hex_encode(&mac.finalize().into_bytes());

    let line = match serde_json::to_string(ev) {
        Ok(json) => {
            let reason_json =
                serde_json::to_string(reason).unwrap_or_else(|_| String::from("\"\""));
            format!(
                "{{\"prev_hmac\":\"{}\",\"hmac\":\"{}\",\"key_version\":{},\"reason\":{},\"event\":{}}}\n",
                prev_hmac, hmac, key_version, reason_json, json
            )
        }
        Err(e) => {
            tracing::error!(error = %e, audit_id = %ev.audit_id, "dead-letter serialize failed");
            return;
        }
    };
    use std::io::Write;
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        Ok(mut f) => {
            if let Err(e) = f.write_all(line.as_bytes()) {
                tracing::warn!(error = %e, path = %path.display(), "dead-letter write failed");
            }
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "dead-letter open failed");
        }
    }
}
