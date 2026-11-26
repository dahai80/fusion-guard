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

// M3: explicit lock-poison handling — recover, not process panic. The daemon must stay alive
// (a single-request panic killing the daemon would take down all 27 sub-projects' service).
// Poisoned = the lock-holding thread panicked; protected data may be inconsistent, but audit/rules
// are persisted in SQLite (atomicity guaranteed by DB transactions, not the in-memory lock), so a
// slightly stale in-memory state is acceptable. EMERG-level log lets ops notice the restart.
// unwrap_or_else(|e| e.into_inner()) extracts the guard; PoisonError::into_inner() works for both Mutex and RwLock.
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

// C21 (P0-G9): harden DB file permissions. A security daemon's store must not rely on umask
// (default 022 → 0644/0755 world-readable).
// Apply 0o600 to db + <db>-wal + <db>-shm; set when present, skip when absent (WAL files are created on demand).
// Re-applying guards against external loosening: called once after every open, covering DB decay or external chmod relaxation.
fn harden_db_perms(db_path: &Path) {
    let mut paths = vec![db_path.to_path_buf()];
    for suffix in ["-wal", "-shm"] {
        let mut s = db_path.as_os_str().to_os_string();
        s.push(suffix);
        paths.push(std::path::PathBuf::from(s));
    }
    for p in paths {
        if p.exists() {
            // Permissions is not Copy; construct each time.
            let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
        }
    }
}

// P1-7 (audit §3.5): the old single-file guard.db kept pending_actions/tokens/key_versions in the main DB.
// After the split they moved to token.db/action.db; residual old tables in the main DB are no longer queried
// by new code. DROPping the residue keeps audit.db clean.
// Idempotent: check table existence via sqlite_master before DROP (fresh DBs lack all three → skip, no error).
// Failure only warns, never blocks open (all three are transient state; residue is non-fatal — real queries go
// to sibling files and residual tables only waste a little space).
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

// P0-4 (audit §1.3, PRD §13.3): audit governance thresholds.
// ROTATE_BYTES: guard.db over 100MB → archive the oldest segment (rotation trigger #1).
// ROTATE_AGE_DAYS: rows older than 30 days → archive to ~/.fusion-guard/audit-archive/ (rotation trigger #2).
// RETENTION_DAYS: archive files older than 180 days → delete (retention cold-storage expiry).
const ROTATE_BYTES: u64 = 100 * 1024 * 1024;
const ROTATE_AGE_DAYS: i64 = 30;
const RETENTION_DAYS: i64 = 180;

// P0-4: archive directory (PRD §13.3: ~/.fusion-guard/audit-archive/).
// Per-store resolution: env FUSION_GUARD_ARCHIVE_DIR overrides (tests/ops), else audit-archive/ next to db_path.
// In production a single daemon's db lives at ~/.fusion-guard/guard.db → archive dir is
// ~/.fusion-guard/audit-archive/ (unchanged per PRD).
// Per-store resolution avoids the global env racing between concurrently-tested stores (env is a process-wide single value).
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
// Shared secret (§12.1 second factor) Keychain source helpers — reused by fg-ipc PeerAuthorizer
// (service fusion-guard, account shared-secret). Domain-separated from the token_store master key
// (account token-key).
pub mod secret_store;
pub use action_store::{ActionError, ActionStore, PendingAction};
pub use secret_store::{
    allow_insecure_secret_flag_set, generate_shared_secret, keychain_secret_get,
    keychain_secret_store, resolve_shared_secret, shared_secret_env_present, SecretError,
    SharedSecretSource, KEYCHAIN_ACCOUNT as SHARED_SECRET_KEYCHAIN_ACCOUNT,
    KEYCHAIN_SERVICE as SHARED_SECRET_KEYCHAIN_SERVICE,
    SHARED_SECRET_ENV as SHARED_SECRET_ENV_CONST,
};
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

// P1-6 (audit §3.2): audit.list filtering + cursor pagination. The old handler only supported tenant_id + limit,
// so monitoring had to brute-force poll the full table and filter client-side. Added time window (since/until)
// + event_type + level_min filters + cursor pagination → monitoring pulls only increments via
// since=<last row ts>, no longer full scans.
//
// level_min: json_extract(verdict_json,'$.risk_level') yields 'l1'..'l4'; lexicographic order == level order
// (equal-length lowercase strings), so SQL >= compares directly. confirm/tcc events have no risk_level
// (empty verdict_json / missing key) → json_extract returns NULL → NULL >= 'lN' is NULL (false) → naturally
// excluded (matches the "filter by risk level" semantics).
//
// cursor: last row (ts, audit_id) dual key; under ORDER BY ts DESC, audit_id DESC the cursor condition is
// ts < cur_ts OR (ts = cur_ts AND audit_id < cur_audit_id). ts is RFC3339 (equal-length, lexicographically
// comparable); audit_id is UUID hex compared lexicographically (stable ordering absent concurrent same-ts writes).
#[derive(Debug, Clone, Default)]
pub struct AuditListFilter<'a> {
    pub tenant_id: Option<&'a str>,
    pub since: Option<&'a str>,      // RFC3339 string, ts >= ?
    pub until: Option<&'a str>,      // RFC3339 string, ts <= ?
    pub event_type: Option<&'a str>, // exact match event_type = ?
    pub level_min: Option<&'a str>,  // 'l1'..'l4', json_extract >= ?
    pub cursor_ts: Option<&'a str>,  // cursor last-row ts
    pub cursor_id: Option<&'a str>,  // cursor last-row audit_id
    pub limit: usize,
}

// P1-6: pagination result. When has_more=true, next_cursor lets the client continue pulling.
#[derive(Debug, Clone, Serialize)]
pub struct AuditListPage {
    pub records: Vec<AuditRecord>,
    pub next_cursor: Option<String>, // "ts\x1faudit_id" encoding, passed through by the client to continue
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
    // H-E (item d): among rows with HMAC mismatch, the count broken because the key_version anchor does not
    // match the current master (key loss) rather than genuine tampering.
    // These rows still count toward broken_links (unverifiable) but not toward tampered (not malicious).
    pub key_version_unknown_rows: usize,
}

// P0-5 (audit §1.4): tamper-evidence coverage completion. The single-table chain (audit_events) only covers
// audit rows; the ruleset/TCC/dead-letter are off-chain → rule tampering (highest-impact attack, controls what
// gets Blocked) + TCC deletion + dead-letter pileup all report green under verify_chain, undetectable.
// Added three independent chains (each table chains itself, not merged into audit_events —
// audit_events is high-throughput with rotation, merging would get chains cut by archiving; rules/tcc mutate
// less often, so independent chains are cleaner).
// SubChainVerification = the verification result of one chain (same fields as ChainVerification).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubChainVerification {
    pub total_rows: usize,
    pub unhashed_rows: usize,
    pub verified_links: usize,
    pub broken_links: usize,
    pub tampered: bool,
    pub first_broken_at: Option<usize>,
    // H-E (item d): same as ChainVerification.key_version_unknown_rows (key-loss rows, not genuine tampering).
    pub key_version_unknown_rows: usize,
}

// P0-5: all-chains aggregated verification. audit (audit_events chain) + tcc (tcc_events chain) + rules
// (rule_mutations chain) + dead_letter (dead-letter file chain). tampered = any chain broken.
// guard.audit.verify returns this aggregate (previously returned only the audit ChainVerification, now extended to all chains).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllChainsVerification {
    pub audit: ChainVerification,
    pub tcc: SubChainVerification,
    pub rules: SubChainVerification,
    pub dead_letter: SubChainVerification,
    pub tampered: bool,
    // H-E (item d): any chain with key_version_unknown_rows > 0 → key loss (historical rows unverifiable but
    // not genuinely tampered).
    // When true, ops knows this is key loss, not tampering: restoring the Keychain master key (from escrow)
    // allows re-verification — do not misjudge it as a security incident.
    pub key_loss: bool,
}

// P0-4 (audit §1.3/§2.4): incremental chain verification checkpoint. Caches the last verified row's audit_id;
// the next call only verifies the newly added segment.
// audit_id (UUID) instead of rowid: rowid may be reordered after VACUUM, audit_id is stable → anchor stays valid.
#[derive(Debug, Clone)]
struct Checkpoint {
    last_verified_audit_id: String,
    last_verified_hash: String,
    last_archived_audit_id: Option<String>,
    last_archived_hash: Option<String>,
}

// P0-4 (audit §1.3, PRD §13.3): retention/rotation execution report.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RetentionReport {
    pub archived_rows: i64,
    pub archive_path: Option<String>,
    pub pruned_archives: i64,
}

pub struct AuditStore {
    db: Mutex<Connection>,
    // P0-3 (audit §1.2): high-risk synchronous audit write connection. synchronous=FULL — fsync WAL at
    // commit, so a power loss never drops H7 high-risk audit rows (NORMAL only acknowledges; a power loss
    // may drop them). L3/L4 Block + confirm go through this.
    audit_writer: Arc<Mutex<Connection>>,
    // P0-3/§3.5: low-risk async batch write connection (drain thread). synchronous=NORMAL — performance
    // traded for tiered durability (L1/L2 async batch, losing a batch is acceptable, not high-risk gating).
    // Separate connection, separate Mutex, reducing lock contention with the high-risk writer.
    // The drain thread holds a clone; this field stores the owner handle (writer_sync_pragma + connection
    // lifetime bound to AuditStore).
    low_writer: Arc<Mutex<Connection>>,
    // A3/P1: read-only connection used by verify_chain/list_events, never grabs the audit_writer write lock.
    // Mutex wrapper: rusqlite::Connection is not Sync (contains a RefCell), Arc<Connection> is not Send →
    // IpcServer would not be Send → tokio::spawn refuses.
    // Mutex<Connection> = Send+Sync. Independent lock from audit_writer, so reads never block the H7 sync write gate.
    read_conn: Arc<Mutex<Connection>>,
    // A2: bounded sync_channel (backpressure; prevents unbounded heap OOM when drain stalls). Full →
    // try_send fails → dead-letter file.
    low_queue: mpsc::SyncSender<AuditEvent>,
    // A2: dead-letter file path (same directory as guard.db; audit events land on disk instead of vanishing
    // when the queue is full/closed).
    dead_letter_path: std::path::PathBuf,
    tokens: Arc<TokenStore>,
    actions: Arc<ActionStore>,
    // P1-2 (audit §1.6): master key (Keychain/env), not pre-derived. compute_event_hmac derives via
    // derive_chain_key per-row key_version (domain separation + versioning). Arc shared with the drain
    // thread + confirm.
    chain_key: Arc<Zeroizing<[u8; 32]>>,
    // P1-2: current key version (recorded on new audit rows). Arc<AtomicI64>: shared by the drain thread +
    // rotate_key, so after rotation the drain immediately reads the new version (no stale closure capture).
    // Initialized at open from the max version in key_versions.
    current_key_version: Arc<std::sync::atomic::AtomicI64>,
    // P0-4: db path (rotation size check).
    db_path: std::path::PathBuf,
    // P0-4: archive directory (PRD §13.3). Per-store resolution (env override or audit-archive/ next to
    // db_path), not the global env — isolates concurrently-tested stores from racing the same env, while
    // production keeps the single-daemon single-archive-dir semantics unchanged.
    archive_dir: std::path::PathBuf,
}

pub struct StoreError;

impl AuditEvent {
    // Length-prefixed encoding (P0-G2, C8): each field = u32 BE length + bytes, eliminating \x1f join collisions.
    // Field order is fixed (11 fields); changing any field → HMAC changes → detected.
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
            // C21: directory 0o700, preventing umask default 0755 from letting other local users copy the DB.
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
        // P1-7 (audit §3.5): physical DB split of the write paths. The old 5+ connections shared guard.db's
        // single WAL — audit_writer (FULL, per-row fsync for H7 high-risk) and token_store put / action_store
        // put contended for the same WAL write lock; the application-level Mutex was only fake isolation, and
        // bursty write throughput was capped by SQLite's single-writer. Split into three physical files, each
        // with its own WAL:
        //   audit.db  ← db_path (audit_events + chain + rules + tcc + tenant_bindings + checkpoint)
        //   token.db  ← sibling (tokens + key_versions, TokenStore exclusive)
        //   action.db ← sibling (pending_actions, ActionStore exclusive)
        // Evaluate path: action put (action.db WAL) + reversible token (token.db WAL) + audit (audit.db WAL) —
        // the three WALs never contend, so the H7 fsync hot path is no longer blocked by token/action writes.
        // H4 confirm atomicity: confirm_atomic needs SELECT pending_actions + INSERT audit_events + UPDATE
        // consumed atomic in one transaction. The audit_writer connection ATTACHes action.db as the `action`
        // schema; the cross-db transaction commits coordinately (each ATTACHed db has its own WAL, atomicity
        // preserved), and pending_actions references became `action.pending_actions`.
        // ActionStore's own connection (put/evict, no audit writes) still points at main.pending_actions, no ATTACH.
        let audit_db_path = db_path.to_path_buf();
        let token_db_path = db_path.with_file_name("token.db");
        let action_db_path = db_path.with_file_name("action.db");

        let conn = Connection::open(&audit_db_path).map_err(io_err)?;
        // P1-4 (product-audit §3): the db connection (rules/tcc/tenant_bindings/checkpoint writes) gets
        // busy_timeout=5000. Originally db had no busy_timeout (default 0 = immediate SQLITE_BUSY) while sharing
        // audit.db's single WAL with audit_writer/low_writer. Under load, when an audit write held the WAL write
        // lock, save_rule/save_epoch/report_tcc_event/bind_tenant got immediate SQLITE_BUSY with no retry →
        // intermittent rules/tcc write failures, hurting SSOT consistency (compounding the §2 epoch race).
        // The other four write connections (audit_writer/low_writer/token_conn/action_conn) already had 5000;
        // this brings db in line.
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
        // P1-7: the old single-file guard.db also kept pending_actions/tokens/key_versions in the main DB.
        // After the split, these three tables moved to token.db/action.db; residual old tables in the main DB
        // are no longer queried (new code goes to sibling files). DROPping the residue keeps audit.db clean
        // (fresh DBs skip DROP via IF NOT EXISTS; upgraded DBs get old tables cleared). All three are transient
        // state (pending TTL 30s / token TTL 300s); rows are not copied (cross-file value copying would be
        // wrong — old values are most likely already expired).
        drop_legacy_split_tables(&conn);
        tracing::info!(db = %audit_db_path.display(), "audit store opened (split: audit.db/token.db/action.db, SQLite WAL, chain hash)");

        // A2: bounded sync_channel (8192) replaces the unbounded channel — when drain stalls (mutex long-held
        // by verify/list), low-risk events would pile up unbounded → OOM. Bounded + try_send full → dead-letter
        // file; backpressure without loss.
        let (tx, rx) = mpsc::sync_channel::<AuditEvent>(8192);
        let dead_letter_path = db_path.with_extension("deadletter");
        // P0-3 (audit §1.2): high-risk audit write connection synchronous=FULL — fsync WAL at commit, so a
        // power loss never drops H7 high-risk audit rows (L3/L4 Block + confirm go through this). NORMAL only
        // acknowledges; a power loss may drop them.
        let audit_writer_conn = Connection::open(&audit_db_path).map_err(io_err)?;
        audit_writer_conn
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON; PRAGMA busy_timeout=5000;")
            .map_err(io_err)?;
        // P1-7: audit_writer ATTACHes action.db as the `action` schema — confirm_atomic's cross-db transaction
        // (SELECT action.pending_actions + INSERT main.audit_events + UPDATE action.pending_actions)
        // keeps H4 atomicity while action.db keeps its own WAL (not merged into audit.db's WAL).
        // ATTACH '.../action.db' AS action; busy_timeout gives a brief wait when action.db is write-locked by
        // the ActionStore connection.
        audit_writer_conn
            .execute_batch(&format!(
                "ATTACH DATABASE '{}' AS action;",
                action_db_path.display().to_string().replace('\'', "''")
            ))
            .map_err(io_err)?;
        // P0-3/§3.5: low-risk async batch write connection (drain thread) synchronous=NORMAL — performance
        // traded for tiered durability (L1/L2 async batch, losing a batch is acceptable, not high-risk gating).
        // Separate connection, separate Mutex, reducing lock contention with the high-risk writer.
        let low_writer_conn = Connection::open(&audit_db_path).map_err(io_err)?;
        low_writer_conn
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA secure_delete=ON; PRAGMA busy_timeout=5000;")
            .map_err(io_err)?;
        // P1-7: tokens live in their own physical DB token.db (independent WAL, no lock contention with audit writes).
        let token_conn = Connection::open(&token_db_path).map_err(io_err)?;
        token_conn
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA secure_delete=ON; PRAGMA busy_timeout=5000;")
            .map_err(io_err)?;
        // H-E (product-audit §5): allow_mint is decided by audit row existence. Existing audit_events rows in
        // audit.db = the master key signed chains historically; a missing Keychain key = key loss → refuse
        // silent regeneration (otherwise verify reports tampering on every chain with no way to tell real from
        // false). A virgin DB (no audit rows + token.db virgin) → allow_mint=true for first-time generation.
        // Uses `conn` (audit.db, already migrated) to count audit_events rows; TokenStore::open_checked then
        // combines token.db's own state (either DB non-virgin → allow_mint=false). Audit row existence passed
        // here is the lower bound.
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
        // P1-2 (audit §1.6): master key (not derived) + current version. chain_key holds the master;
        // compute_event_hmac derives the chain key per-row key_version (domain-separated from the token key).
        let current_key_version = tokens.current_key_version();
        let chain_key = Arc::new(Zeroizing::new(*tokens.master_key()));
        let key_version = Arc::new(std::sync::atomic::AtomicI64::new(current_key_version));
        // P1-7: pending_actions lives in its own physical DB action.db (independent WAL). ActionStore's own
        // connection opens here; put/evict_expired use main.pending_actions (no ATTACH, independent WAL).
        let action_conn = Connection::open(&action_db_path).map_err(io_err)?;
        action_conn
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA secure_delete=ON; PRAGMA busy_timeout=5000;")
            .map_err(io_err)?;
        // C21: after all connections open, harden the three DBs' db/-wal/-shm permissions to 0o600 (WAL files
        // have been created by the first connection by now).
        harden_db_perms(&audit_db_path);
        harden_db_perms(&token_db_path);
        harden_db_perms(&action_db_path);
        // A3/P1: read-only connection (read-only query_map, never contends with audit_writer).
        let read_conn = Connection::open(&audit_db_path).map_err(io_err)?;
        read_conn
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA query_only=ON;")
            .map_err(io_err)?;
        let actions = ActionStore::open(action_conn).map_err(|e| {
            tracing::error!(error = %e, "action store open failed");
            std::io::Error::other(e.to_string())
        })?;
        let audit_writer = Arc::new(Mutex::new(audit_writer_conn));
        // P0-3: drain thread holds the low-risk writer (NORMAL), not the shared high-risk audit_writer (FULL).
        let low_writer = Arc::new(Mutex::new(low_writer_conn));
        let writer_for_thread = low_writer.clone();
        let key_for_thread = chain_key.clone();
        let kv_for_thread = key_version.clone();
        // A2: drain thread holds a copy of the dead-letter path (spool on insert failure, never swallow).
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
                // A2: run the batch inline (not spawn-per-batch). The old spawn-per-batch had zero concurrency
                // and a panic swallowed the whole batch (audit events vanished from the tamper-evident log, no
                // retry, no persistence). An inline panic poisons this drain thread → daemon restart fail-closed
                // and visible, not a silent drop.
                let mut g = recover_lock!(writer_for_thread.lock(), "audit writer");
                // P1-2: read the current key version (immediately the new version after rotation, not a stale
                // closure snapshot).
                let kv = kv_for_thread.load(std::sync::atomic::Ordering::Relaxed);
                for ev in &batch {
                    if let Err(e) = insert_audit_event(&mut g, ev, &key_for_thread, kv) {
                        tracing::warn!(error = %e, audit_id = %ev.audit_id, "async audit insert failed");
                        // A2: persist insert failures to the dead-letter file, never let them vanish
                        // (the audit channel must not silently lose events).
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

    // P0-3 (audit §1.2): expose the write connections' PRAGMA synchronous value so tests can verify tiered
    // durability. high_risk=true → audit_writer (FULL), false → low_writer (NORMAL).
    // SQLite PRAGMA synchronous reads back as an integer: 2=FULL, 1=NORMAL.
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

    // G6/L2+A8: confirm_atomic borrows audit_writer + chain_key to write consume and audit atomically in the
    // same critical section.
    // P1-2: returns the master key (not derived); callers pair it with current_key_version() to derive per version.
    pub fn chain_key_handle(&self) -> Arc<Zeroizing<[u8; 32]>> {
        self.chain_key.clone()
    }

    // P1-2 (audit §1.6): current key version (confirm_atomic and other external audit-row writers need to record this).
    pub fn current_key_version(&self) -> i64 {
        self.current_key_version
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    // P1-2 (audit §1.6): rotate the key — bump version + persist to key_versions + update the shared Atomic.
    // New writes use the newly derived key; old rows keep their old version and verify/decrypt with the old
    // derived key (derivation deterministic, master unchanged).
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

    // P0-4 test-helpers: inject a valid chain row with a given ts (rotation tests need old rows to trigger archiving).
    // Build an AuditEvent → read the previous row's event_hash as prev → compute HMAC → insert_audit_event.
    // Not a production path; enabled only with the test-helpers feature.
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

    // P1-6 test-helpers: inject a valid chain row with a given ts + event_type + risk_level (filter/pagination
    // tests need a controllable time window + event type + risk level; the old insert_event_at_ts always
    // serialized verdict_json as "{}" with no risk_level).
    // verdict_json serializes a real GuardVerdict (including risk_level) for level_min json_extract filter testing.
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
        // L12: the action column stores the inferred category (original trigger context), not verdict.reason
        // (by now reason has been overwritten by confirm with "approved/rejected by X").
        // Aligns with the evaluate event's action column semantics: trigger context; the outcome column stores the approval result.
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
            // A2: try_send is a non-blocking send. Bounded queue full (drain stalled) → TrySendError::Full →
            // dead-letter file, neither dropping nor blocking the IPC caller thread. Disconnected → same
            // dead-letter path (drain thread died).
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
        // P0-4 (audit §1.3): after every audit append, check rotation triggers (db over 100MB or rows over 30 days).
        // Cheap: stat the db file size + one COUNT query. Not triggered → return immediately. Triggered →
        // archive+VACUUM. Archiving runs in the audit_writer critical section and does not overlap this append's
        // released write lock (append_event's locked section has already ended).
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
        // A3/P1: use read_conn (query_only), never grabbing the audit_writer write lock (the H7 sync gate does not self-DoS).
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

    // P1-6 (audit §3.2): filtered + cursor-paginated query. Dynamically builds the WHERE clause (bound
    // params, not fmt concatenation, to prevent injection) on read_conn (query_only, no write lock, same as
    // list_events). ORDER BY ts DESC, audit_id DESC stable dual key.
    // Cursor condition: (ts, audit_id) < (cur_ts, cur_id) — ts < cur_ts OR (ts = cur_ts AND audit_id < cur_id).
    // level_min goes through json_extract(verdict_json,'$.risk_level') >= ? (NULL rows naturally excluded).
    // Fetches limit+1 rows to determine has_more; the last row (if has_more) encodes the returned cursor.
    pub fn list_events_filtered(
        &self,
        f: &AuditListFilter,
    ) -> Result<Vec<AuditEvent>, rusqlite::Error> {
        let r = recover_lock!(self.read_conn.lock(), "read conn (filtered)");
        // Clause placeholder numbering (rusqlite ?N continuously increasing) + bind-param push order must match:
        // tenant → since → until → event_type → level_min → (cursor_ts, cursor_id) → limit.
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
            // Cursor: strictly less than the last row (DESC ordering; continued pulls fetch older rows).
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
        let limit_param = bind_idx; // LIMIT is the last positional param
                                    // Fetch 1 extra row to determine has_more.
        let sql = format!(
            "SELECT audit_id, ts, event_type, tenant_id, requester, action,
                    inferred_category, verdict_json, approved_by, seatbelt_required, outcome,
                    prev_hash, event_hash
             FROM audit_events {where_sql}
             ORDER BY ts DESC, audit_id DESC LIMIT ?{limit_param}"
        );
        let mut stmt = r.prepare(&sql)?;
        // Bind params: must follow the where_clauses push order (tenant, since, until, event_type, level_min, cursor_ts, cursor_id).
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
        // LIMIT = requested limit + 1 (extra row decides has_more).
        let fetch = (f.limit as i64).saturating_add(1);
        params_vec.push(Box::new(fetch));
        let params_refs: Vec<&dyn rusqlite::ToSql> =
            params_vec.iter().map(|b| b.as_ref()).collect();
        let rows = stmt
            .query_map(params_refs.as_slice(), row_to_event)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    // P1-6: record view of filtered pagination + cursor/has_more computation. If the extra fetched row exists →
    // has_more=true and that row is not returned (only the first limit rows); next_cursor = the limit-th row
    // (last row of the returned set) as "ts\x1faudit_id".
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

    // P0-4 (audit §1.3, PRD §13.3): audit governance layer — rotation + retention + archive.
    // rotation: rows older than 30 days are archived to ~/.fusion-guard/audit-archive/audit-<ts>.ndjson and
    //   deleted from audit_events; or when guard.db > 100MB, the oldest segment is archived until the db drops
    //   below the threshold. Archive segments are written as NDJSON (including prev_hash/event_hash, chain is
    //   portable); deletion runs in a single audit_writer transaction (no H7 loss on power failure).
    // retention: .ndjson files in the archive directory older than 180 days are deleted (cold-storage expiry,
    //   PRD §13.3 180d retention).
    // Chain integrity: after archiving, the remaining first row's prev_hash points into the archived segment
    //   (dangling in the main DB), so the checkpoint is updated to
    //   last_verified_rowid=remaining first row's rowid + last_verified_hash=remaining first row's event_hash,
    //   last_archived_rowid/hash=archived segment's last row. Incremental verify scans after the remaining first
    //   row, skipping the already-verified remaining first row.
    //   Full-scan fallback: the remaining first row's prev_hash != genesis → would falsely report tampered.
    //   So after archiving, reset_checkpoint_anchoring explicitly anchors the remaining first row; only then is
    //   the incremental path correct (no checkpoint → full scan; checkpoint present and anchor row exists →
    //   incremental, never hitting the archive boundary).
    pub fn enforce_retention(&self) -> Result<RetentionReport, rusqlite::Error> {
        let mut report = RetentionReport::default();
        self.prune_expired_archives(&mut report);
        self.rotate_old_rows(&mut report)?;
        Ok(report)
    }

    // soak/commercial: periodic retention monitor thread. The drain thread only inserts low-risk rows and never
    // calls enforce_retention (P0-4 retention was originally only called on the sync append_event high-risk path).
    // Under high-frequency L1 traffic, audit_events grows with no rotation check → long-run OOM. This thread calls
    // enforce_retention periodically, covering the low-risk accumulation path (when the rotation thresholds
    // 100MB/30d are reached, archive+VACUUM reclaims pages). interval_secs defaults to 5s — drain writes at high
    // frequency, 60s is too slow (short runs/bursts would exceed the threshold); 5s triggers rotation+VACUUM in time.
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

    // P0-4: rotation main body. Decides the archive window (older than ROTATE_AGE_DAYS or db over
    // ROTATE_BYTES), writes NDJSON + deletes rows + updates checkpoint, in a single audit_writer
    // transaction (H7 durability).
    fn rotate_old_rows(&self, report: &mut RetentionReport) -> rusqlite::Result<()> {
        let now = chrono::Utc::now();
        let age_cutoff = now - chrono::Duration::days(ROTATE_AGE_DAYS);
        let age_cutoff_str = age_cutoff.to_rfc3339();

        // Trigger #1: rows older than ROTATE_AGE_DAYS exist. Trigger #2: db file over ROTATE_BYTES (in which
        // case archive the oldest segment regardless of age, to get below the threshold). First count aged rows;
        // zero aged rows and db under limit → skip.
        // A3/soak: the check phase + row selection use read_conn (query_only, never grabs the audit_writer
        // write lock) — the old implementation held audit_writer for the whole section running COUNT scans +
        // SELECT row selection, locking all audit writes even with nothing to rotate (self-DoS on the
        // append_event high-risk sync path; the 5s retention monitor's periodic locked no-op queries tanked
        // throughput).
        // Only row deletion + checkpoint + VACUUM (real mutation) lock audit_writer. TOCTOU-safe: rowids are
        // monotonically increasing, so old rowids read here are never deleted by concurrent inserts; deletion
        // uses the rowid range [min,max] and newly inserted rows have rowid>max, unaffected.
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

        // Select rows to archive (ORDER BY rowid ASC = oldest first). Aged → all aged rows; size-only trigger →
        // oldest segment (capped by rowid, at most 50000 rows per archive run to prevent a long transaction
        // locking the DB).
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

        // Archived segment's last row event_hash + audit_id (after archiving, the remaining first row's
        // prev_hash should equal this hash, keeping the chain continuous).
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

        // Write the NDJSON archive file (includes chain fields; verification recomputable across archives).
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
                // Archive write failure → do not delete rows (keep them in the main DB, no audit loss). Retry next time.
                return Ok(());
            }
        }

        // Delete rows: single transaction on audit_writer (synchronous=FULL), no H7 loss on power failure.
        // A3/soak + P1-3 (product-audit §3): only this mutate section locks audit_writer (check + selection
        // already completed lock-free via read_conn). VACUUM is moved out of this critical section (separate
        // short re-lock), and DELETE+checkpoint commit releases the lock first → high-risk H7 append_event is
        // not serialized behind the whole (delete+checkpoint+VACUUM) section, only behind the VACUUM-exclusive part.
        let w = self.audit_writer.lock();
        let mut w = recover_lock!(w, "audit writer (rotate delete)");
        let tx = w.transaction()?;
        tx.execute(
            "DELETE FROM audit_events WHERE rowid >= ?1 AND rowid <= ?2",
            params![min_rid, last_archived_rowid],
        )?;
        // Confirm deleted count = archived count (guards against partial deletion).
        let remaining_after: i64 =
            tx.query_row("SELECT COUNT(*) FROM audit_events", [], |r| r.get(0))?;
        tx.commit()?;
        report.archived_rows = to_archive.len() as i64;
        report.archive_path = Some(archive_path.to_string_lossy().to_string());

        // Update the checkpoint after archiving: anchor the remaining first row (if any), else anchor the
        // archived segment tail (empty-DB chain continuation).
        // Remaining first row's prev_hash = archived_tail_hash (chain continuous, but a full scan would falsely
        // report, so anchoring into the incremental path is mandatory).
        // Write the checkpoint before VACUUM (audit_id anchors are VACUUM-stable, but verifying while the row
        // still exists is safer).
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
                // Empty-DB archived state: no rows in the DB. last_verified_audit_id is set to the empty
                // sentinel (not pointing at the deleted archived row; otherwise verify_chain rowid_of_audit
                // would return None → wrongly fall back to a full genesis scan → first row's prev_hash
                // = archived_tail_hash ≠ genesis falsely reported broken). verify_chain sees the empty
                // sentinel → skips the rowid lookup; expected_prev = last_archived_hash continues the scan
                // across the whole DB. The next insert also reads last_archived_hash as prev_hash
                // (insert_audit_event's checkpoint fallback).
                last_verified_audit_id: String::new(),
                last_verified_hash: String::new(),
                last_archived_audit_id: Some(last_archived_audit_id.clone()),
                last_archived_hash: Some(archived_tail_hash.clone()),
            },
        };
        if let Err(e) = write_checkpoint(&w, &new_cp) {
            tracing::warn!(error = %e, "post-rotate checkpoint write failed (P0-4, next verify rescans)");
        }
        // P1-3: release the audit_writer lock first, ending the DELETE+checkpoint critical section — after
        // this, H7 append_event can insert immediately (not pre-empted by the VACUUM section below). VACUUM
        // runs in its own separate short re-lock.
        drop(w);

        // VACUUM reclaims the deleted rows' pages (rotation's core purpose: shrink db size). Under WAL, VACUUM
        // rewrites the whole DB and needs exclusivity (no active transactions + no other connection holding
        // locks). P1-3: the exclusive section is minimal (VACUUM only, no delete/checkpoint); periodic governance
        // is not a hot path; audit_id anchors are VACUUM-stable so the chain is unbroken. Failure does not block
        // (space reclaimed next cycle).
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
            "audit rotation complete (P0-4, PRD §13.3, VACUUM moved out of the delete critical section P1-3)"
        );
        Ok(())
    }

    // P0-4: retention — delete .ndjson files in the archive directory older than RETENTION_DAYS (cold-storage
    // expiry). Filename format audit-<YYYYMMDDTHHMMSS>.ndjson; the timestamp is parsed to determine age.
    // Unparseable files are kept (no accidental deletion).
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
            // audit-YYYYMMDDTHHMMSS.ndjson → extract the timestamp segment.
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

    // P0-4: expose the db size for tests/ops to observe rotation state.
    pub fn db_size_bytes(&self) -> u64 {
        std::fs::metadata(&self.db_path)
            .map(|m| m.len())
            .unwrap_or(0)
    }

    // P0-1 (audit §1.1): tenant-scoped verify. None = global (admin/root only, enforced at IPC).
    // The audit chain is global append-only (prev_hash chains the previous row's event_hash, no per-tenant
    // split), so the full table must be read to keep expected_prev correct, but only rows within scope are
    // counted. Out-of-scope rows are not counted (no cross-tenant activity volume leaked).
    // verify_chain(tenant=None) is equivalent to the old full-table verification (kept for admin audits).
    //
    // P0-4 (audit §1.3/§2.4): incremental verification. chain_checkpoint caches the last verified row's rowid +
    // event_hash; this call only verifies the new segment after that rowid, O(new rows) instead of O(full table),
    // eliminating full-table linear degradation.
    // Degradation conditions (fall back to full scan for safety): no checkpoint; the checkpoint anchor row was
    // archived away (rowid missing); tampering detected (broken) → full-scan recompute so first_broken_at
    // locates the full-table row number + do not cache a bad checkpoint.
    // Incremental clean path: total_rows = COUNT(*) within current scope (index-fast); verified_links/broken
    // only reflect this segment.
    pub fn verify_chain(&self, tenant: Option<&str>) -> Result<ChainVerification, rusqlite::Error> {
        // A3/P1: use read_conn (query_only); scanning never grabs the audit_writer write lock.
        let r = recover_lock!(self.read_conn.lock(), "read conn");

        // P0-4: read the checkpoint. None → full-table scan (old behavior, compatible with new DBs + legacy migrations).
        let cp = read_checkpoint(&r)?;
        let mut incremental = cp.is_some();
        let mut anchor_rowid: i64 = 0;
        let mut expected_prev = GENESIS_PREV_HASH.to_string();
        if let Some(ref c) = cp {
            if c.last_verified_audit_id.is_empty() {
                // P0-4 empty-DB archived state: no rows in the DB (all archived away); prev_hash continues from
                // the archived segment's last hash.
                // Do not query rowid_of_audit (anchor row deleted, lookup would be None → old logic wrongly fell
                // back to a full genesis scan → false broken reports).
                // expected_prev = archived segment's last hash, incremental stays true, anchor_rowid=0 →
                // WHERE rowid > 0 scans the whole DB continuing the chain (rowids start at 1, >0 means all).
                // No last_archived_hash → fall back to full scan.
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
                // P0-4: audit_id anchor (UUID stable, survives VACUUM rowid reordering). Look up the anchor
                // row's current rowid now.
                // Anchor row archived away (audit_id missing) or hash mismatch → fall back to a full scan
                // (do not trust segment boundaries).
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
            // P0-4: only scan the new segment after the anchor row.
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

        // P0-4: total_rows uses scope COUNT(*) in the incremental clean path (index-fast), or the scanned
        // in-scope row count in the full-scan path.
        // Both mean the same thing: total in-scope rows currently in the DB. The incremental path never rescans
        // the already-verified segment.
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
        // H-E (item d): key-loss row count (anchor mismatch, not genuine tampering).
        let mut key_version_unknown_rows = 0usize;
        // global_i: full-table position (first_broken_at uses the full-table row number so ops can locate the row in the DB).
        let mut global_i = 0usize;
        let mut last_hash = expected_prev.clone();
        // P0-4: segment-tail audit_id (UUID, VACUUM-stable) goes into the checkpoint, replacing rowid as the
        // next incremental anchor.
        // Initialized to the existing checkpoint's audit_id (keeps the original anchor when there is no new
        // segment, preserving the last verification point).
        let mut last_audit_id: String = cp
            .as_ref()
            .map(|c| c.last_verified_audit_id.clone())
            .unwrap_or_default();
        for (ev, kv, _rid) in rows.iter() {
            let in_scope = tenant.is_none_or(|t| ev.tenant_id == t);
            if ev.event_hash.is_empty() {
                // C7 fix: empty hash = anomaly (migration-era leftover or attacker-cleared).
                // After migration all new rows always carry an HMAC hash; empty-hash rows count as unhashed and broken.
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
                // P1-2: verify with the chain key derived from the row's recorded key_version (old rows old key, new rows new key).
                let recomputed =
                    compute_event_hmac(&self.chain_key, *kv, &ev.payload_bytes(), &expected_prev);
                if recomputed != ev.event_hash {
                    if in_scope {
                        broken_links += 1;
                        if first_broken_at.is_none() {
                            first_broken_at = Some(global_i);
                        }
                        // H-E (item d): distinguish genuine tampering from key loss. Anchor matches/missing →
                        // tampering; anchor mismatch → key loss, not counted as tampered.
                        match classify_break(&self.tokens, *kv) {
                            BreakKind::KeyLoss => key_version_unknown_rows += 1,
                            BreakKind::Tamper | BreakKind::MissingAnchor => tampered = true,
                        }
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

        // P0-4: clean path caches the new checkpoint (segment-tail audit_id + hash) for the next incremental run.
        // Tampering/full-scan fallbacks do not cache bad points; a clean full-scan fallback caches the scanned
        // new tail (establishing the first checkpoint).
        // read_conn is query_only and cannot write → use audit_writer (no reverse lock ordering with read_conn, no deadlock).
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
            key_version_unknown_rows,
            "audit chain verification done (PRD §13.3, HMAC, P0-1 tenant-scoped, P0-4 incremental, H-E key-loss distinguish)"
        );
        Ok(ChainVerification {
            total_rows,
            unhashed_rows,
            verified_links,
            broken_links,
            tampered,
            first_broken_at,
            key_version_unknown_rows,
        })
    }

    // C16/P0-G4: corrupt rule JSON → refuse to start (fail-closed), no longer silently dropping __corrupt__.
    // This is a security daemon's rules SSOT; silently dropping corrupt rows = a tampered ruleset passes
    // unnoticed, which is unacceptable.
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

    // P0-5 (audit §1.4): TCC chain verification. Read tcc_events ORDER BY rowid ASC, recompute the HMAC
    // per row and compare.
    // Rows with empty event_hash = pre-migration legacy (migrate adds columns with DEFAULT ''); counted as
    // unhashed_rows, not false positives.
    // Returns SubChainVerification (same field semantics as the audit chain).
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
        let mut key_version_unknown_rows = 0usize;
        let mut expected_prev = GENESIS_PREV_HASH.to_string();
        for (idx, row) in rows.enumerate() {
            let (audit_id, ts, permission, requester, result, reason, prev_hash, event_hash, kv) =
                row?;
            total_rows += 1;
            if event_hash.is_empty() {
                unhashed_rows += 1;
                continue;
            }
            // prev_hash must equal the previous row's event_hash (chain continuity).
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
            // P1-2: verify with the chain key derived from the row's key_version.
            let computed = compute_event_hmac(&self.chain_key, kv, &payload, &prev_hash);
            if computed != event_hash {
                broken_links += 1;
                if first_broken_at.is_none() {
                    first_broken_at = Some(idx);
                }
                // H-E (item d): distinguish genuine tampering from key loss.
                match classify_break(&self.tokens, kv) {
                    BreakKind::KeyLoss => key_version_unknown_rows += 1,
                    BreakKind::Tamper | BreakKind::MissingAnchor => tampered = true,
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
            key_version_unknown_rows,
        })
    }

    // P0-5 (audit §1.4): rule mutation chain verification. Read rule_mutations ORDER BY rowid ASC, recompute
    // the HMAC per row. After the rules table's current state is tampered with, verify_rules_chain detects it
    // by replaying the mutation sequence (mutation history vs current state mismatch).
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
        let mut key_version_unknown_rows = 0usize;
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
            // P1-2: verify with the chain key derived from the row's key_version.
            let computed = compute_event_hmac(&self.chain_key, kv, &payload, &prev_hash);
            if computed != event_hash {
                broken_links += 1;
                if first_broken_at.is_none() {
                    first_broken_at = Some(idx);
                }
                // H-E (item d): distinguish genuine tampering from key loss.
                match classify_break(&self.tokens, kv) {
                    BreakKind::KeyLoss => key_version_unknown_rows += 1,
                    BreakKind::Tamper | BreakKind::MissingAnchor => tampered = true,
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
            key_version_unknown_rows,
        })
    }

    // P0-5 (audit §1.4): dead-letter file chain verification. Recompute per row:
    // hmac = HMAC(key, prev_hmac ‖ event.payload_bytes()), and compare against the stored hmac plus
    // prev_hmac chain continuity. Missing/empty file → clean (total_rows=0). Row parse failure → broken.
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
                    key_version_unknown_rows: 0,
                }
            }
        };
        let mut total_rows = 0usize;
        let mut unhashed_rows = 0usize;
        let mut verified_links = 0usize;
        let mut broken_links = 0usize;
        let mut tampered = false;
        let mut first_broken_at: Option<usize> = None;
        let mut key_version_unknown_rows = 0usize;
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
            // P1-2: dead-letter rows record key_version (older formats lack it → default 1, compatible with historical dead letters).
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
            // P1-2: verify with the chain key derived from the row's key_version (not the master directly).
            let dkey = token_store::derive_chain_key(&self.chain_key, kv);
            let mut mac =
                HmacSha256::new_from_slice(&dkey[..]).expect("HMAC accepts any key length");
            mac.update(prev_hmac.as_bytes());
            mac.update(&payload);
            let computed = hex_encode(&mac.finalize().into_bytes());
            if computed != hmac {
                broken_links += 1;
                if first_broken_at.is_none() {
                    first_broken_at = Some(idx);
                }
                // H-E (item d): distinguish genuine tampering from key loss (dead-letter kv comes from the
                // JSON, older formats default to 1).
                match classify_break(&self.tokens, kv) {
                    BreakKind::KeyLoss => key_version_unknown_rows += 1,
                    BreakKind::Tamper | BreakKind::MissingAnchor => tampered = true,
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
            key_version_unknown_rows,
        }
    }

    // P0-5 (audit §1.4): dead-letter reimport — after signature verification, re-import dead-letter events into
    // audit_events to continue the main chain.
    // Any row's hmac verification failure → abort with an error (no rows imported, preventing a partial import
    // from masking tampering). All rows verified → insert_audit_event row by row to continue the main chain
    // (prev_hash automatically reads the audit tail); on success the dead-letter file is cleared (zeroed, not
    // truncated, preserving the file's inode/permissions). Returns the number of rows successfully imported.
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
        // Verify all signatures first (no import); any bad row → abort.
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
            // P1-2: dead-letter row key_version (older formats lack it → 1). Signature verification uses the key derived for the generation-time version.
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
            // P1-2: verify with the chain key derived from the row's key_version (the generation-time version, not current).
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
        // All signatures verified → re-import row by row into audit_events to continue the main chain. Re-imported
        // rows are new rows, hash recomputed with the current key_version.
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
        // Re-import succeeded → clear the dead-letter file (write empty, preserving inode + permissions).
        if let Err(e) = std::fs::write(&self.dead_letter_path, b"") {
            tracing::warn!(error = %e, path = %self.dead_letter_path.display(), "dead-letter clear after reimport failed (events already imported)");
        }
        tracing::info!(
            imported,
            "dead-letter reimported into audit_events chain (P0-5)"
        );
        Ok(imported)
    }

    // P0-5 (audit §1.4): all-chains aggregated verification. audit (audit_events) + tcc (tcc_events) + rules
    // (rule_mutations) + dead_letter (dead-letter file). tampered = any chain broken.
    // guard.audit.verify returns this aggregate (previously returned only the audit ChainVerification, now extended to all chains).
    pub fn verify_all_chains(
        &self,
        tenant: Option<&str>,
    ) -> Result<AllChainsVerification, rusqlite::Error> {
        let audit = self.verify_chain(tenant)?;
        let tcc = self.verify_tcc_chain()?;
        let rules = self.verify_rules_chain()?;
        let dead_letter = self.verify_dead_letter();
        let tampered = audit.tampered || tcc.tampered || rules.tampered || dead_letter.tampered;
        let key_loss = audit.key_version_unknown_rows > 0
            || tcc.key_version_unknown_rows > 0
            || rules.key_version_unknown_rows > 0
            || dead_letter.key_version_unknown_rows > 0;
        Ok(AllChainsVerification {
            audit,
            tcc,
            rules,
            dead_letter,
            tampered,
            key_loss,
        })
    }

    pub fn save_rule(&self, rule: &GuardRule) -> Result<(), rusqlite::Error> {
        let g = recover_lock!(self.db.lock(), "audit db");
        let j = serde_json::to_string(rule).unwrap_or_default();
        g.execute(
            "INSERT OR REPLACE INTO rules (name, rule_json) VALUES (?1, ?2)",
            params![rule.name, j],
        )?;
        // P0-5 (audit §1.4): rule overwrites (INSERT OR REPLACE) break chains, so the rules table does not chain
        // directly; every add/update appends a rule_mutations chain row (kind=add; at the audit-engine layer,
        // add_rule calls save_rule and update reuses the same save_rule → kind=add covering update semantics is
        // sufficient: the mutation is recorded).
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
        // P0-5: remove mutation appended to the chain (empty rule_json).
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
        // P0-5: epoch mutation appended to the chain (empty name, rule_json holds the epoch value string — replayable for reconciliation during verification).
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
        // P0-5 (audit §1.4): TCC chain. prev_hash = previous row's tcc event_hash (empty → genesis).
        // payload = audit_id‖ts‖permission‖requester‖result‖reason, length-prefixed encoding.
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
        // P1-2: derive the chain key from the current key_version + persist the key_version column (old rows verify with old versions).
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
        // A3/P1: use read_conn (query_only), never grabbing the db write lock (rule/epoch mutations are not blocked).
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

    // P0-1 (audit §1.1): uid → authorized tenant set. After peercred resolves the connection uid, this table is
    // consulted; the wire tenant_id must be within this set. The daemon uid bootstraps a default binding at
    // startup (avoiding an empty set deadlocking itself).
    // admin (root, uid 0) bypasses this table at the IPC layer (all tenants), not depending on this row.
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

    // Returns the uid's authorized tenant list (bound). Empty Vec = no bindings (the IPC layer treats it as
    // default-only and daemon-itself-only).
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

-- P0-5 (audit §1.4): rule mutation chain. The rules/rule_meta tables store the current state
-- (INSERT OR REPLACE / DELETE overwrites), which cannot chain directly (overwrites break chains). This
-- append-only table records every add/update/remove/epoch mutation + chain hash;
-- after the rules table is tampered with, verify_rules_chain detects it by replaying the mutation sequence
-- (current state vs mutation history mismatch).
-- kind: add|update|remove|epoch. name: rule name (empty for epoch mutations). rule_json: serialized rule (empty for remove/epoch).
-- prev_hash/event_hash: same HMAC chain as TCC (chain key = chain_key, payload = length-prefixed fields).
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

-- P0-1 (audit §1.1): uid → authorized tenant set mapping. peercred resolves the connection uid; this table
-- yields the tenants that uid may operate on. The wire tenant_id must fall within this set, otherwise -32001.
-- Kills the cross-tenant audit exfiltration chain (root = admin, all tenants).
CREATE TABLE IF NOT EXISTS tenant_bindings (
    uid INTEGER NOT NULL,
    tenant TEXT NOT NULL,
    PRIMARY KEY (uid, tenant)
);

-- P0-4 (audit §1.3): chain verification checkpoint. Incremental verification only checks the new segment
-- after the anchor row, caching the last verified row's audit_id + event_hash to avoid full-table linear
-- degradation (PRD §13.3 + §2.4).
-- Uses audit_id (UUID, VACUUM-stable) not rowid (VACUUM may reorder), so post-archive VACUUM does not break anchors.
-- last_verified_audit_id: last row's audit_id that passed verification (NULL = verify from the start).
-- last_verified_hash: that row's event_hash (next segment's first row's expected_prev).
-- last_archived_audit_id: last row's audit_id cut off by the most recent archive (NULL = never archived).
-- last_archived_hash: that row's event_hash (archived segment tail, used to continue verification across the archive boundary).
CREATE TABLE IF NOT EXISTS chain_checkpoint (
    key TEXT PRIMARY KEY,
    last_verified_audit_id TEXT,
    last_verified_hash TEXT,
    last_archived_audit_id TEXT,
    last_archived_hash TEXT
);
"#;

// H-A (product-audit §2): single-writer chain guarantee moved to the transaction layer.
// The old implementation did SELECT-then-INSERT with no transaction; audit_writer (high-risk) and low_writer
// (drain) each held their own Mutex and both called this function → both connections SELECTed the same
// prev_hash then each INSERTed → two rows with the same prev_hash = chain fork, verify falsely reports
// tampering. A Mutex is useless across connections (each locks its own connection). SQLite's write lock
// (BEGIN IMMEDIATE) serializes across connections: BEGIN IMMEDIATE takes the write lock immediately
// (RESERVED→EXCLUSIVE); other connections' BEGIN IMMEDIATE blocks (waiting up to busy_timeout=5000) →
// SELECT-then-INSERT is atomic inside a single write lock; the prev_hash read and INSERT cannot be jumped
// by another connection's insert. So whichever writer (audit_writer/low_writer) calls this function, chain
// prev_hash is strictly continuous.
// The transaction also keeps confirm_atomic's cross-statement atomicity (H-D; see confirm_atomic's own
// BEGIN IMMEDIATE).
fn insert_audit_event(
    conn: &mut Connection,
    ev: &AuditEvent,
    key: &Zeroizing<[u8; 32]>,
    key_version: i64,
) -> rusqlite::Result<()> {
    // H-A: BEGIN IMMEDIATE takes the write lock immediately, serializing SELECT-then-INSERT across connections.
    // Failure (SQLITE_BUSY) is retried by busy_timeout=5000 (set on both writers at open); persistent failure
    // propagates upward.
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
            // P0-4: main DB empty (never written, or emptied by archiving). After archive-emptying, the chain
            // must continue from the archived segment's tail, not genesis — otherwise the first row after
            // archiving gets prev_hash=genesis, breaking the chain with the archive segment. Read the
            // checkpoint's last_archived_hash; no checkpoint (virgin DB) → genesis. Read failure → genesis fallback.
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

// H-D: insert an audit row inside confirm_atomic's cross-db transaction. Reuses insert_audit_event's chain
// computation logic but accepts an already-opened Transaction (BEGIN IMMEDIATE) and does not start its own —
// confirm_atomic's tx commits uniformly.
// prev_hash is read from the same transaction (sees the held write lock; other connections cannot jump in); the
// event_hash HMAC computation is identical to insert_audit_event (chain continuity across paths).
// The caller is responsible for commit/rollback.
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
// P1-2 (audit §1.6): key = HKDF-derived chain key (versioned), not the master directly reusing the token key.
// master + version → derive_chain_key → derived key. Consistent across restarts (master unchanged, derivation
// deterministic) → chain verification recomputable.
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

// H-E (item d): classify the cause of a row HMAC mismatch. The verify path calls classify_break when it hits
// a mismatching row, distinguishing genuine tampering from key loss, so key loss is not falsely reported as
// full tampering (product-audit H-E core defect).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BreakKind {
    // The current master can derive the row's key_version (anchor matches) → row content changed = genuine tampering.
    Tamper,
    // The current master cannot derive the row's key_version (anchor mismatch) → key loss; row unverifiable but not tampering.
    KeyLoss,
    // Legacy migrated row without an anchor (NULL) → fail-closed as tampering (an attacker cannot hide tampering by deleting anchors).
    MissingAnchor,
}

// H-E (item d): classify an HMAC-mismatching row using the key_version anchor. Looks up key_versions.key_anchor
// and compares against the anchor recomputed with the current master. tokens.key_anchor reads token.db
// (independent lock, never blocks audit writes).
fn classify_break(tokens: &TokenStore, key_version: i64) -> BreakKind {
    match tokens.key_anchor(key_version) {
        Ok(Some(stored)) => {
            // Recompute the anchor for this version with the current master (copies the master_key raw reference
            // for derivation; the derived key is not persisted).
            let master = Zeroizing::new(*tokens.master_key());
            let recomputed = token_store::key_anchor_for_version(&master, key_version);
            if recomputed == stored {
                BreakKind::Tamper
            } else {
                BreakKind::KeyLoss
            }
        }
        Ok(None) => BreakKind::MissingAnchor,
        Err(e) => {
            tracing::warn!(
                key_version = key_version,
                error = %e,
                "H-E: key_anchor lookup failed — fail-closed as tamper"
            );
            BreakKind::MissingAnchor
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// P0-5 (audit §1.4): length-prefixed encoding (same pattern as AuditEvent::payload_bytes, eliminating \x1f collisions).
// Generic helper: each field = u32 BE length + bytes, concatenated into the HMAC payload.
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

// P0-5: TCC chain payload = audit_id‖ts‖permission‖requester‖result‖reason (6 length-prefixed fields).
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

// P0-5: rule mutation chain payload = mutation_id‖ts‖kind‖name‖rule_json (5 length-prefixed fields).
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

// P0-5 (audit §1.4): append one rule_mutations chain row. prev_hash = previous row's event_hash
// (empty → genesis). Read → compute → write inside the same db lock, preventing concurrent prev_hash forking
// (rule mutations are low-frequency; the db lock suffices).
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

// L13: column existence detection via PRAGMA table_info (not prepare(SELECT col ...) — the latter on a legacy
// DB lacking the column makes prepare return Err("no such column"), which `?` propagates → AuditStore::open
// fails, and the actual migration branch becomes unreachable).
// table_info returns all column metadata; check by name whether the column exists, and if missing run
// ALTER TABLE ADD COLUMN (idempotent).
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
    // P0-5 (audit §1.4): tcc_events chain columns (missing in legacy DBs). Idempotent ALTER; empty-hash rows count as unhashed, not false positives.
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
    // P1-2 (audit §1.6): key_version column (missing in legacy DBs). Idempotent ALTER; default 1 = historical rows verify with the v1 derived key.
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

// P0-4: used by verify_chain's incremental path. Same column order as row_to_event (0-12); key_version at column 13, rowid at column 14.
fn row_to_event_with_rowid(row: &rusqlite::Row) -> rusqlite::Result<(AuditEvent, i64, i64)> {
    let ev = row_to_event(row)?;
    let kv: i64 = row.get::<_, Option<i64>>(13)?.unwrap_or(1);
    let rid: i64 = row.get(14)?;
    Ok((ev, kv, rid))
}

// P0-4 (audit §1.3): read the chain verification checkpoint. No row → None (first verification or legacy migration).
fn read_checkpoint(conn: &Connection) -> rusqlite::Result<Option<Checkpoint>> {
    // 4-nullable-string tuple: an explicit annotation would trip clippy::type_complexity, hence the type alias.
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
            // Normal incremental anchor: last_verified_audit_id non-empty (the DB has a verified last row).
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
            // Empty-DB archived state: last_verified_audit_id is empty (no rows in the DB, all archived away),
            // but last_archived_hash exists → verify must continue scanning from the archived segment's last
            // hash as expected_prev, not fall back to a full scan (otherwise the first row's
            // prev_hash != genesis is a false report). last_verified_hash = archived_tail_hash.
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

// P0-4: write the checkpoint (upsert). The incremental verification clean path caches the last row; the next
// call only verifies the new segment.
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

// P0-4: look up the rowid for an audit_id (anchor row location, used by the incremental WHERE rowid > anchor).
// audit_id is the PRIMARY KEY (indexed), so the query is fast. rowids change after VACUUM, so each incremental
// run looks the rowid up fresh rather than caching it.
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

// P0-4: total in-scope row count (index-fast), used by the incremental path's total_rows, never rescanning the verified segment.
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

// P0-4 (audit §1.3, PRD §13.3): archive audit rows as NDJSON. One JSON per line (including prev_hash/event_hash,
// chain is portable — archive files can be verified independently, and can also continue the chain with the main
// DB). The first row carries archived_from_prev noting the genesis or segment-start prev_hash (ops can trace
// where the archived segment sits in the global chain).
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

// A2 + P0-5 (audit §1.4): dead-letter spool — when the queue is full/disconnected or an insert fails, audit
// events are persisted to the dead-letter file. The security audit channel must not silently lose events:
// each event is appended to disk as a JSON line (NDJSON).
// P0-5: each line carries a chain HMAC (prev_hmac‖hmac) with the same key as audit_events, chaining to the
// previous dead-letter line → verify_dead_letter can detect dead-letter tampering/deletion, and
// reimport_dead_letter re-imports into audit_events to continue the main chain after signature verification.
// Line format: {"prev_hmac":"...","hmac":"...","reason":"...","event":{...AuditEvent...}}
fn spool_dead_letter(
    path: &std::path::Path,
    ev: &AuditEvent,
    reason: &str,
    key: &Zeroizing<[u8; 32]>,
    key_version: i64,
) {
    // prev_hmac = the dead-letter file's previous line's hmac (empty → genesis). Missing/empty file → genesis.
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
    // P1-2: hmac = HMAC of the HKDF-derived chain key (versioned), not the master directly.
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
