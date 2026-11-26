use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::Sha256;
use std::sync::Mutex;
use zeroize::Zeroizing;

const KEYCHAIN_SERVICE: &str = "fusion-guard";
const KEYCHAIN_ACCOUNT: &str = "token-key";
const TOKEN_TTL_SECS: i64 = 300;
const KEY_LEN: usize = 32;

// P1-2 (audit §1.6): HKDF domain separation + versioned key derivation. The master key (Keychain/env)
// is the PRK; different info labels derive an independent chain-HMAC key and token-AES-GCM key —
// a single-point leak does not compromise both.
// version is embedded in the info label: rotation = bump version (new derived key); rows with an old
// key_version verify/decrypt with the old derived key.
// Derivation is deterministic (master unchanged → same version always yields the same key), so the DB
// stores only key_version INT, never key material.
const CHAIN_INFO_PREFIX: &[u8] = b"fusion-guard/audit-chain-hmac/v";
const TOKEN_INFO_PREFIX: &[u8] = b"fusion-guard/token-aes-gcm/v";

// H-E (product-audit §5 item d): per-version verification anchor. On mint/rotate, key_versions.key_anchor
// stores HMAC(canonical_msg, derive_chain_key(master, version)). When verify hits a row with an HMAC
// mismatch, it looks up the anchor for that row's key_version and recomputes it with the current master:
//   anchor matches → current master can derive that version → genuine tampering (tampered=true)
//   anchor mismatch → current master cannot derive that version → key loss (key_version_unknown_rows++)
//   anchor NULL (legacy migrated row) → fail-closed as tampering (an attacker cannot hide by deleting anchors)
// canonical_msg is fixed and serves only as a version derivability probe, not key material.
const KEY_ANCHOR_MSG: &[u8] = b"fusion-guard/key-anchor/v1";
type HmacSha256 = Hmac<Sha256>;

pub struct TokenStore {
    db: Mutex<Connection>,
    key: Zeroizing<[u8; KEY_LEN]>,
    // P1-2: current key version (used for new writes). At open, read the max version from key_versions, default 1.
    // AtomicI64: AuditStore holds Arc<TokenStore>, so rotate_key bumps via &self (no &mut).
    current_version: std::sync::atomic::AtomicI64,
}

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("keychain error: {0}")]
    Keychain(String),
    #[error("encrypt error: {0}")]
    Encrypt(String),
    #[error("decrypt error: {0}")]
    Decrypt(String),
    #[error("token not found: {0}")]
    NotFound(String),
    #[error("token expired: {0}")]
    Expired(String),
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("key init error: {0}")]
    KeyInit(String),
}

impl TokenStore {
    pub fn open(conn: Connection) -> Result<Self, TokenError> {
        // H-E (product-audit §5): allow_mint = whether token.db is virgin (no token rows + key_versions
        // only has the seed v1). Non-virgin (encrypted tokens exist) with a lost Keychain master key →
        // refuse to start with a clear error, instead of silently minting a new master key that would make
        // all historical tokens unrecoverable and invalidate historical verification.
        let allow_mint = token_db_is_virgin(&conn);
        Self::open_checked(conn, allow_mint)
    }

    // H-E: called by AuditStore.open — allow_mint is passed in based on audit row existence (rows in
    // audit.db = the master key was used historically; a lost key must not be silently regenerated).
    // Then combined with token.db's own state: either DB non-virgin → allow_mint=false.
    // token.db virgin but audit.db has rows (audits written but no reversible redact tokens yet) must also
    // refuse; and vice versa.
    pub(crate) fn open_checked(conn: Connection, allow_mint: bool) -> Result<Self, TokenError> {
        // H-E: token.db itself non-virgin → force allow_mint=false (a true passed from the audit side only
        // applies when the token side is also virgin).
        let allow_mint = allow_mint && token_db_is_virgin(&conn);
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS tokens (
                token_id TEXT PRIMARY KEY,
                ciphertext BLOB NOT NULL,
                nonce BLOB NOT NULL,
                created_ts INTEGER NOT NULL,
                in_flight INTEGER NOT NULL DEFAULT 0,
                ttl_secs INTEGER NOT NULL,
                tenant_id TEXT NOT NULL DEFAULT 'default'
            );
            CREATE INDEX IF NOT EXISTS idx_tokens_ts ON tokens(created_ts);
            CREATE TABLE IF NOT EXISTS key_versions (
                version INTEGER PRIMARY KEY,
                created_ts INTEGER NOT NULL,
                key_anchor TEXT
            );
            INSERT OR IGNORE INTO key_versions (version, created_ts) VALUES (1, 0);
            ",
        )?;
        // H-E (item d): legacy DB key_versions lacks the key_anchor column → idempotent column add
        // (NULL = legacy migrated row, verify fail-closed as tampering).
        let _ = conn.execute("ALTER TABLE key_versions ADD COLUMN key_anchor TEXT", []);
        // C2 legacy DB migration: add tenant_id column (idempotent)
        let _ = conn.execute(
            "ALTER TABLE tokens ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'",
            [],
        );
        // P1-2 (audit §1.6): token encryption records key_version; reveal decrypts with the key derived for
        // that version (old tokens use the old key, new tokens the new key). Default 1 = fallback for legacy
        // DBs without this column.
        let _ = conn.execute(
            "ALTER TABLE tokens ADD COLUMN key_version INTEGER NOT NULL DEFAULT 1",
            [],
        );
        let key = load_or_create_key(allow_mint)?;
        // H-E (item d): backfill anchors for all versions with NULL anchors (only legacy rows missing an
        // anchor; existing anchors are never overwritten — anchors are immutable, derivation is deterministic,
        // recomputation yields the same value, so backfill fills gaps rather than rewriting). The new-DB seed
        // v1 row also gets its anchor written here for the first time.
        backfill_key_anchors(&conn, &key)?;
        let current_version = max_key_version(&conn);
        Ok(Self {
            db: Mutex::new(conn),
            key,
            current_version: std::sync::atomic::AtomicI64::new(current_version),
        })
    }

    pub fn put(&self, token_id: &str, plaintext: &str) -> Result<(), TokenError> {
        self.put_tenant(token_id, plaintext, "default")
    }

    // C2 cross-tenant exfiltration chain: tokens are tenant-bound at put; reveal verifies ownership.
    pub fn put_tenant(
        &self,
        token_id: &str,
        plaintext: &str,
        tenant_id: &str,
    ) -> Result<(), TokenError> {
        // P1-2: encrypt with the token key derived from the current version; record key_version on the row.
        let cv = self
            .current_version
            .load(std::sync::atomic::Ordering::Relaxed);
        let dkey = derive_token_key(&self.key, cv);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dkey[..]));
        let nonce_bytes = generate_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| TokenError::Encrypt(e.to_string()))?;
        let now = now_ts();
        let g = recover_lock!(self.db.lock(), "token db");
        g.execute(
            "INSERT OR REPLACE INTO tokens (token_id, ciphertext, nonce, created_ts, in_flight, ttl_secs, tenant_id, key_version)
             VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6, ?7)",
            params![token_id, ct, nonce_bytes, now, TOKEN_TTL_SECS, tenant_id, cv],
        )?;
        tracing::debug!(
            token_id = token_id,
            tenant = tenant_id,
            kv = cv,
            "token stored (encrypted, tenant-bound)"
        );
        Ok(())
    }

    pub fn get(&self, token_id: &str) -> Result<String, TokenError> {
        self.get_tenant(token_id, "default")
    }

    // C2: reveal verifies the token belongs to the calling tenant. Cross-tenant → NotFound (refuse to
    // decrypt; H6 fallback is handled by the caller).
    pub fn get_tenant(&self, token_id: &str, tenant_id: &str) -> Result<String, TokenError> {
        let g = recover_lock!(self.db.lock(), "token db");
        let row = g
            .query_row(
                "SELECT ciphertext, nonce, created_ts, ttl_secs, tenant_id, key_version FROM tokens WHERE token_id = ?1",
                params![token_id],
                |r| {
                    let ct: Vec<u8> = r.get(0)?;
                    let nonce: Vec<u8> = r.get(1)?;
                    let created: i64 = r.get(2)?;
                    let ttl: i64 = r.get(3)?;
                    let tenant: String = r.get(4)?;
                    let kv: i64 = r.get::<_, Option<i64>>(5)?.unwrap_or(1);
                    Ok((ct, nonce, created, ttl, tenant, kv))
                },
            )
            .optional()?;
        let (ct, nonce_bytes, created, ttl, stored_tenant, kv) =
            row.ok_or_else(|| TokenError::NotFound(token_id.to_string()))?;
        if stored_tenant != tenant_id {
            tracing::warn!(
                token_id = token_id,
                caller_tenant = tenant_id,
                stored_tenant = stored_tenant,
                "cross-tenant reveal rejected (C2)"
            );
            return Err(TokenError::NotFound(token_id.to_string()));
        }
        let now = now_ts();
        if created + ttl < now {
            tracing::warn!(token_id = token_id, "token expired (TTL exceeded)");
            let _ = g.execute(
                "DELETE FROM tokens WHERE token_id = ?1 AND in_flight = 0",
                params![token_id],
            );
            return Err(TokenError::Expired(token_id.to_string()));
        }
        // P1-2: decrypt with the key derived from the key_version recorded at put (old tokens use old-version keys).
        let dkey = derive_token_key(&self.key, kv);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dkey[..]));
        let nonce = Nonce::from_slice(&nonce_bytes);
        let pt = cipher
            .decrypt(nonce, ct.as_ref())
            .map_err(|e| TokenError::Decrypt(e.to_string()))?;
        let s = String::from_utf8(pt).map_err(|e| TokenError::Decrypt(e.to_string()))?;
        tracing::debug!(token_id = token_id, "token revealed");
        Ok(s)
    }

    pub fn set_in_flight(&self, token_id: &str, in_flight: bool) -> Result<(), TokenError> {
        let g = recover_lock!(self.db.lock(), "token db");
        g.execute(
            "UPDATE tokens SET in_flight = ?1 WHERE token_id = ?2",
            params![in_flight as i64, token_id],
        )?;
        Ok(())
    }

    pub fn evict_expired(&self) -> Result<usize, TokenError> {
        let now = now_ts();
        let g = recover_lock!(self.db.lock(), "token db");
        let n = g.execute(
            "DELETE FROM tokens WHERE created_ts + ttl_secs < ?1 AND in_flight = 0",
            params![now],
        )?;
        if n > 0 {
            tracing::info!(evicted = n, "expired non-in-flight tokens evicted");
        }
        Ok(n)
    }

    // P1-2: raw master key reference (Keychain/env 32B), held by AuditStore for per-row version derivation.
    // Never exposed across processes — fg-store same-crate only.
    pub(crate) fn master_key(&self) -> &[u8; KEY_LEN] {
        &self.key
    }

    // P1-2: current key version (used for new audit rows / new tokens). AuditStore records this version on each row it writes.
    pub(crate) fn current_key_version(&self) -> i64 {
        self.current_version
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    // P1-2: rotate the key — bump current_version + persist to key_versions (auditable rotation timestamp).
    // New writes use the newly derived key; old rows keep their old version and verify/decrypt with the old
    // derived key (derivation deterministic, master unchanged).
    // Returns the new version.
    pub fn rotate_key(&self) -> Result<i64, TokenError> {
        let new_version = self
            .current_version
            .load(std::sync::atomic::Ordering::Relaxed)
            + 1;
        // H-E (item d): write the anchor for the new version (derived from the current master) so verify can
        // later distinguish genuine tampering from key loss.
        let anchor = key_anchor_for_version(&self.key, new_version);
        let g = recover_lock!(self.db.lock(), "token db");
        g.execute(
            "INSERT OR REPLACE INTO key_versions (version, created_ts, key_anchor) VALUES (?1, ?2, ?3)",
            params![new_version, now_ts(), anchor],
        )?;
        drop(g);
        self.current_version
            .store(new_version, std::sync::atomic::Ordering::Relaxed);
        tracing::info!(
            new_version = new_version,
            "key rotated (P1-2 HKDF version bump, H-E anchor written)"
        );
        Ok(new_version)
    }

    // H-E (item d): look up the anchor for a given version. Used by the verify path — when a row's HMAC
    // mismatches, compare that row's key_version anchor (recomputed with the current master) to distinguish
    // genuine tampering (anchor matches) from key loss (anchor mismatches).
    // Returns None = legacy migrated row without an anchor (verify fail-closed as tampering).
    #[cfg_attr(not(feature = "test-helpers"), allow(dead_code))]
    pub(crate) fn key_anchor(&self, version: i64) -> Result<Option<String>, TokenError> {
        let g = recover_lock!(self.db.lock(), "token db");
        let row = g
            .query_row(
                "SELECT key_anchor FROM key_versions WHERE version = ?1",
                params![version],
                |r| r.get::<_, Option<String>>(0),
            )
            .optional()?;
        Ok(row.flatten())
    }
}

fn now_ts() -> i64 {
    chrono::Utc::now().timestamp()
}

fn generate_nonce() -> [u8; 12] {
    let mut n = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut n);
    n
}

// P1-2 (audit §1.6): HKDF-Expand(master=PRK, info=label, 32B).
// The master key is 32B high-entropy from Keychain/env → used directly as PRK (skipping Extract, RFC5869 §3.3).
// Different info labels → independently derived keys: chain-HMAC key ≠ token-AES-GCM key (domain separation).
// version embedded in info: v1/v2… → same master derives different keys (rotation); derivation is
// deterministic and recomputable (verify old chains / decrypt old tokens).
fn hkdf_expand(
    master: &Zeroizing<[u8; KEY_LEN]>,
    info_prefix: &[u8],
    version: i64,
) -> Zeroizing<[u8; KEY_LEN]> {
    let ver_str = version.to_string();
    let mut info = Vec::with_capacity(info_prefix.len() + ver_str.len());
    info.extend_from_slice(info_prefix);
    info.extend_from_slice(ver_str.as_bytes());
    let hk = Hkdf::<Sha256>::from_prk(&master[..]).expect("master key is 32B >= HashLen");
    let mut okm = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(&info, &mut *okm).expect("32B <= 255*HashLen");
    okm
}

// P1-2: chain HMAC derived key. pub(crate): called by fg-store::lib compute_event_hmac (same crate).
// test-helpers: tests asserting domain separation (chain key != token key) call the derivation directly.
#[cfg_attr(not(feature = "test-helpers"), allow(dead_code))]
pub fn derive_chain_key(
    master: &Zeroizing<[u8; KEY_LEN]>,
    version: i64,
) -> Zeroizing<[u8; KEY_LEN]> {
    hkdf_expand(master, CHAIN_INFO_PREFIX, version)
}

// P1-2: token AES-GCM derived key.
#[cfg_attr(not(feature = "test-helpers"), allow(dead_code))]
pub fn derive_token_key(
    master: &Zeroizing<[u8; KEY_LEN]>,
    version: i64,
) -> Zeroizing<[u8; KEY_LEN]> {
    hkdf_expand(master, TOKEN_INFO_PREFIX, version)
}

// P1-2: read the max version from key_versions (missing table/empty → 1).
fn max_key_version(conn: &Connection) -> i64 {
    conn.query_row("SELECT MAX(version) FROM key_versions", [], |r| {
        r.get::<_, Option<i64>>(0)
    })
    .ok()
    .flatten()
    .unwrap_or(1)
}

// H-E (item d): compute the verification anchor for a version = HMAC(KEY_ANCHOR_MSG, derive_chain_key(master, version)).
// Uses the chain derived key (not the token key) — the anchor probe tests chain-path derivability, same domain as the audit HMAC.
// pub(crate): called by fg-store::lib verify path (compares per-row key_version anchor recomputed with the current master).
pub(crate) fn key_anchor_for_version(master: &Zeroizing<[u8; KEY_LEN]>, version: i64) -> String {
    let dkey = derive_chain_key(master, version);
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(&dkey[..]).expect("HMAC accepts any key length");
    mac.update(KEY_ANCHOR_MSG);
    hex::encode(mac.finalize().into_bytes())
}

// H-E (item d): backfill anchors for all versions with NULL anchors. Anchors are immutable (deterministic
// derivation → recomputation yields the same value), so backfill fills gaps rather than rewriting.
// Only UPDATE WHERE key_anchor IS NULL: versions that already have an anchor (including ones written by an
// old master) are never overwritten — the old master's anchor is preserved; recomputing with a new master
// mismatches → verify reports key loss, not a false tampering verdict.
fn backfill_key_anchors(
    conn: &Connection,
    master: &Zeroizing<[u8; KEY_LEN]>,
) -> Result<(), TokenError> {
    let versions: Vec<(i64, Option<String>)> = conn
        .prepare("SELECT version, key_anchor FROM key_versions ORDER BY version ASC")?
        .query_map([], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (version, existing) in versions {
        if existing.is_some() {
            continue;
        }
        let anchor = key_anchor_for_version(master, version);
        let n = conn.execute(
            "UPDATE key_versions SET key_anchor = ?1 WHERE version = ?2 AND key_anchor IS NULL",
            params![anchor, version],
        )?;
        if n > 0 {
            tracing::info!(version = version, "H-E: backfilled key_anchor for version");
        }
    }
    Ok(())
}

// P2-1 (audit §2.6): env key gating + warning decision. Pure function (rule 5: decide with code, not
// tokens; testable).
// cfg(debug_assertions) = dev allows env (EnvDebug, info posture); release only allows via
// FUSION_GUARD_ALLOW_ENV_KEY=1 or the --insecure-env-key CLI flag (set via fg-bin set_var)
// (EnvInsecure, warn alert — not for prod).
// env not authorized or absent → KeychainRequired (macOS uses Keychain, non-macOS errors).
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum KeySource {
    EnvDebug,
    EnvInsecure,
    KeychainRequired,
}

#[cfg_attr(not(feature = "test-helpers"), allow(dead_code))]
pub fn resolve_key_source(is_debug: bool, allow_env_flag: bool, env_present: bool) -> KeySource {
    if env_present && (is_debug || allow_env_flag) {
        if is_debug {
            KeySource::EnvDebug
        } else {
            KeySource::EnvInsecure
        }
    } else {
        KeySource::KeychainRequired
    }
}

fn allow_env_flag_set() -> bool {
    std::env::var("FUSION_GUARD_ALLOW_ENV_KEY")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

// H-E (product-audit §5): when allow_mint=false, a missing Keychain master key → refuse to start with a
// clear error, not silently mint a new master key. allow_mint=true only permits generation + Keychain store
// on first start (virgin DB).
// The env key path is unaffected by allow_mint — an explicitly provided env means ops knowingly supplied the
// key (dev/CI posture).
fn load_or_create_key(allow_mint: bool) -> Result<Zeroizing<[u8; KEY_LEN]>, TokenError> {
    let env_present = std::env::var("FUSION_GUARD_TOKEN_KEY").is_ok();
    match resolve_key_source(cfg!(debug_assertions), allow_env_flag_set(), env_present) {
        KeySource::EnvDebug => {
            let key = decode_env_key()?;
            tracing::info!(
                "guard token key loaded from FUSION_GUARD_TOKEN_KEY env (debug build, dev posture)"
            );
            Ok(key)
        }
        KeySource::EnvInsecure => {
            let key = decode_env_key()?;
            // P2-1 warning: prod (release) using an env key = master key in process environment, readable by
            // same-UID processes (ps eww / lsof / launchctl); all cross-tenant reversible redact tokens become
            // decryptable + audit chains forgeable.
            // This path is dev/CI convenience only; prod MUST use Keychain. warn level keeps it visible to ops audits.
            tracing::warn!(
                "INSECURE (P2-1): master key loaded from FUSION_GUARD_TOKEN_KEY env in release build — \
                 visible to any same-UID process; prod MUST use Keychain (FUSION_GUARD_ALLOW_ENV_KEY=1 or --insecure-env-key was set)"
            );
            Ok(key)
        }
        KeySource::KeychainRequired => load_keychain_or_err(allow_mint),
    }
}

// H-E: whether token.db is virgin (no token rows + key_versions only has the seed v1). Virgin → allow
// first-time master key generation; non-virgin (encrypted tokens exist) → missing Keychain key = key loss,
// refuse silent regeneration.
fn token_db_is_virgin(conn: &Connection) -> bool {
    let token_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM tokens", [], |r| r.get(0))
        .unwrap_or(0);
    if token_count > 0 {
        return false;
    }
    // key_versions only has the seed (1,0) = never rotated = virgin. A v2+ row or created_ts>0 → key used historically.
    let kv_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM key_versions WHERE version > 1 OR created_ts > 0",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    kv_count == 0
}

// H-E test-helpers: expose the virgin check + allow_mint decision so unit tests can verify key-loss gating logic.
#[cfg(feature = "test-helpers")]
pub fn test_token_db_is_virgin(conn: &Connection) -> bool {
    token_db_is_virgin(conn)
}

// H-E test-helpers: simulate the allow_mint=false refusal decision when the Keychain key is missing
// (without touching the real Keychain).
// Err = would refuse to start; Ok = would silently generate. The env path ignores allow_mint (an explicit
// env is allowed through).
// env_present is passed explicitly (not read from env) — avoids tests mutating process-level env and
// interfering with parallel tests (store_test/token_test rely on FUSION_GUARD_TOKEN_KEY to keep Keychain
// from hanging).
#[cfg(feature = "test-helpers")]
pub fn test_key_loss_refuses(allow_mint: bool, env_present: bool) -> Result<(), &'static str> {
    if env_present {
        return Ok(()); // env path bypasses allow_mint (dev/CI posture)
    }
    // KeychainRequired path: allow_mint=false → refuse; true → generate (first start).
    if allow_mint {
        Ok(())
    } else {
        Err("master key lost: Keychain missing but data exists — refusing to remint (H-E)")
    }
}

fn decode_env_key() -> Result<Zeroizing<[u8; KEY_LEN]>, TokenError> {
    let hex = std::env::var("FUSION_GUARD_TOKEN_KEY")
        .map_err(|_| TokenError::KeyInit("FUSION_GUARD_TOKEN_KEY env unset".to_string()))?;
    let bytes = hex_decode(&hex)?;
    if bytes.len() != KEY_LEN {
        return Err(TokenError::KeyInit(
            "FUSION_GUARD_TOKEN_KEY not 32 bytes".to_string(),
        ));
    }
    let mut k = Zeroizing::new([0u8; KEY_LEN]);
    k.copy_from_slice(&bytes);
    Ok(k)
}

#[cfg(target_os = "macos")]
fn load_keychain_or_err(allow_mint: bool) -> Result<Zeroizing<[u8; KEY_LEN]>, TokenError> {
    if let Some(k) = keychain_get()? {
        if k.len() == KEY_LEN {
            tracing::info!("guard token key loaded from Keychain");
            let mut key = Zeroizing::new([0u8; KEY_LEN]);
            key.copy_from_slice(&k);
            return Ok(key);
        }
        return Err(TokenError::KeyInit("keychain key not 32 bytes".to_string()));
    }
    // H-E (product-audit §5): Keychain master key missing. allow_mint=false (DB has historical data) =
    // key loss, refuse to start with a clear error — not silently minting a new master key (a new key fails
    // to decrypt all historical tokens + verify reports tampering on every chain, with no way to distinguish
    // genuine tampering from key loss). allow_mint=true (virgin DB, first start) → generate + store to Keychain.
    if !allow_mint {
        tracing::error!(
            "H-E: Keychain master key missing but data exists — refusing to start \
             (silent remint would invalidate all historical token decryption + audit chain verification). \
             Restore the Keychain key (service=fusion-guard, account=token-key) or provide FUSION_GUARD_TOKEN_KEY env."
        );
        return Err(TokenError::KeyInit(
            "master key lost: Keychain key missing but historical data exists — refusing to remint \
             (restore Keychain key fusion-guard/token-key or set FUSION_GUARD_TOKEN_KEY)"
                .to_string(),
        ));
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut *key);
    keychain_store(&key[..]).map_err(|e| {
        tracing::error!(error = %e, "keychain store failed — refusing to start (no ephemeral key)");
        TokenError::Keychain(format!("store failed: {e}"))
    })?;
    tracing::info!("guard token key generated + stored to Keychain (first start)");
    Ok(key)
}

#[cfg(not(target_os = "macos"))]
fn load_keychain_or_err(allow_mint: bool) -> Result<Zeroizing<[u8; KEY_LEN]>, TokenError> {
    // P2-1: non-macOS has no Keychain; env key not authorized → refuse to start (fail-closed, no weak-key fallback).
    // H-E: allow_mint is irrelevant in this branch (non-macOS has no Keychain path, can never mint).
    let _ = allow_mint;
    Err(TokenError::KeyInit(
        "non-macOS requires FUSION_GUARD_TOKEN_KEY env (debug build, or FUSION_GUARD_ALLOW_ENV_KEY=1, or --insecure-env-key)"
            .to_string(),
    ))
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, TokenError> {
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(hex.get(i..i + 2).unwrap_or(""), 16)
                .map_err(|e| TokenError::Keychain(format!("hex decode: {e}")))
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn keychain_get() -> Result<Option<Vec<u8>>, TokenError> {
    use security_framework::passwords::get_generic_password;
    match get_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT) {
        Ok(v) => Ok(Some(v)),
        Err(e) => {
            tracing::debug!(error = %e, "keychain get (likely first start)");
            Ok(None)
        }
    }
}

#[cfg(target_os = "macos")]
fn keychain_store(key: &[u8]) -> Result<(), TokenError> {
    use security_framework::passwords::set_generic_password;
    set_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, key)
        .map_err(|e| TokenError::Keychain(e.to_string()))?;
    Ok(())
}
