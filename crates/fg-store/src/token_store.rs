use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use rusqlite::{params, Connection};
use sha2::Sha256;
use std::sync::Mutex;
use zeroize::Zeroizing;

const KEYCHAIN_SERVICE: &str = "fusion-guard";
const KEYCHAIN_ACCOUNT: &str = "token-key";
const TOKEN_TTL_SECS: i64 = 300;
const KEY_LEN: usize = 32;

// P1-2 (audit §1.6): HKDF 域分离 + 版本化派生 key。master key (Keychain/env) 为 PRK,
// 经不同 info label 派生独立 chain-HMAC key 与 token-AES-GCM key —— 单点泄露不双失守。
// version 嵌入 info label: 轮换 = bump version (新派生 key); 旧 key_version 行用旧派生 key 验/解。
// 派生确定 (master 不变 → 同 version 永同 key), 故 DB 只存 key_version INT, 不存密钥材料。
const CHAIN_INFO_PREFIX: &[u8] = b"fusion-guard/audit-chain-hmac/v";
const TOKEN_INFO_PREFIX: &[u8] = b"fusion-guard/token-aes-gcm/v";

pub struct TokenStore {
    db: Mutex<Connection>,
    key: Zeroizing<[u8; KEY_LEN]>,
    // P1-2: 当前 key 版本 (新写入用此)。open 时从 key_versions 表读最大 version, 无则 1。
    // AtomicI64: AuditStore 持 Arc<TokenStore>, rotate_key 经 &self bump (无 &mut)。
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
                created_ts INTEGER NOT NULL
            );
            INSERT OR IGNORE INTO key_versions (version, created_ts) VALUES (1, 0);
            ",
        )?;
        // C2 旧库迁移: 加 tenant_id 列 (幂等)
        let _ = conn.execute(
            "ALTER TABLE tokens ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'",
            [],
        );
        // P1-2 (audit §1.6): token 加密记 key_version, reveal 用对应版本派生 key 解密
        // (旧 token 用旧 key, 新 token 用新 key)。默认 1 = 历史库无此列时兜底。
        let _ = conn.execute(
            "ALTER TABLE tokens ADD COLUMN key_version INTEGER NOT NULL DEFAULT 1",
            [],
        );
        let key = load_or_create_key()?;
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

    // C2 跨租户外泄链: token 落库时绑定租户, reveal 校验归属。
    pub fn put_tenant(
        &self,
        token_id: &str,
        plaintext: &str,
        tenant_id: &str,
    ) -> Result<(), TokenError> {
        // P1-2: 用当前版本派生的 token key 加密, 落库记 key_version。
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

    // C2: reveal 校验 token 归属租户。跨租户 → NotFound (拒绝解密, H6 fallback 由调用方处理)。
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
        // P1-2: 用该 token 落库时的 key_version 派生 key 解密 (旧 token 用旧版本 key)。
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

    // P1-2: master key 原始引用 (Keychain/env 32B), 供 AuditStore 持有 + 按行版本派生。
    // 不跨进程暴露 — 仅 fg-store 同 crate。
    pub(crate) fn master_key(&self) -> &[u8; KEY_LEN] {
        &self.key
    }

    // P1-2: 当前 key 版本 (新审计行/新 token 用此)。AuditStore 写入时记此 version 到行。
    pub(crate) fn current_key_version(&self) -> i64 {
        self.current_version
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    // P1-2: 轮换 key —— bump current_version + 落 key_versions 表 (审计追溯轮换时刻)。
    // 新写入用新派生 key; 旧行保留旧 version, 验/解用旧派生 key (派生确定, master 不变)。
    // 返回新 version。
    pub fn rotate_key(&self) -> Result<i64, TokenError> {
        let new_version = self
            .current_version
            .load(std::sync::atomic::Ordering::Relaxed)
            + 1;
        let g = recover_lock!(self.db.lock(), "token db");
        g.execute(
            "INSERT OR REPLACE INTO key_versions (version, created_ts) VALUES (?1, ?2)",
            params![new_version, now_ts()],
        )?;
        drop(g);
        self.current_version
            .store(new_version, std::sync::atomic::Ordering::Relaxed);
        tracing::info!(
            new_version = new_version,
            "key rotated (P1-2 HKDF version bump)"
        );
        Ok(new_version)
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

// P1-2 (audit §1.6): HKDF-Expand(master=PRK, info=label, 32B)。
// master key 是 Keychain/env 32B 高熵 → 直接作 PRK (跳过 Extract, RFC5869 §3.3)。
// 不同 info label → 独立派生 key: chain-HMAC key ≠ token-AES-GCM key (域分离)。
// version 嵌 info: v1/v2… → 同 master 派生不同 key (轮换), 派生确定可重算 (验旧链/解旧 token)。
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

// P1-2: 链 HMAC 派生 key。pub(crate): fg-store::lib compute_event_hmac 调 (同 crate)。
// test-helpers: 测试断言域分离 (chain key != token key) 直接调派生。
#[cfg_attr(not(feature = "test-helpers"), allow(dead_code))]
pub fn derive_chain_key(
    master: &Zeroizing<[u8; KEY_LEN]>,
    version: i64,
) -> Zeroizing<[u8; KEY_LEN]> {
    hkdf_expand(master, CHAIN_INFO_PREFIX, version)
}

// P1-2: token AES-GCM 派生 key。
#[cfg_attr(not(feature = "test-helpers"), allow(dead_code))]
pub fn derive_token_key(
    master: &Zeroizing<[u8; KEY_LEN]>,
    version: i64,
) -> Zeroizing<[u8; KEY_LEN]> {
    hkdf_expand(master, TOKEN_INFO_PREFIX, version)
}

// P1-2: 读 key_versions 表最大 version (无表/空 → 1)。
fn max_key_version(conn: &Connection) -> i64 {
    conn.query_row("SELECT MAX(version) FROM key_versions", [], |r| {
        r.get::<_, Option<i64>>(0)
    })
    .ok()
    .flatten()
    .unwrap_or(1)
}

// P2-1 (audit §2.6): env key 门控 + 告警决策。纯函数 (规则 5: 决策用代码非 token, 可测)。
// cfg(debug_assertions) = dev 放行 env (EnvDebug, info 姿态); release 仅 FUSION_GUARD_ALLOW_ENV_KEY=1
// 或 --insecure-env-key CLI flag (经 fg-bin set_var) 放行 (EnvInsecure, warn 告警 —— prod 不应用)。
// env 不放行或缺 → KeychainRequired (macOS 走 Keychain, 非 macOS err)。
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

fn load_or_create_key() -> Result<Zeroizing<[u8; KEY_LEN]>, TokenError> {
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
            // P2-1 告警: prod (release) 用 env key = 主密钥进进程环境, 同 UID 进程可读
            // (ps eww / lsof / launchctl), 跨租户可逆脱敏 token 全可解 + 审计链可伪造。
            // 此路径仅 dev/CI 便利, prod MUST 用 Keychain。warn 级让运维审计可见。
            tracing::warn!(
                "INSECURE (P2-1): master key loaded from FUSION_GUARD_TOKEN_KEY env in release build — \
                 visible to any same-UID process; prod MUST use Keychain (FUSION_GUARD_ALLOW_ENV_KEY=1 or --insecure-env-key was set)"
            );
            Ok(key)
        }
        KeySource::KeychainRequired => load_keychain_or_err(),
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
fn load_keychain_or_err() -> Result<Zeroizing<[u8; KEY_LEN]>, TokenError> {
    if let Some(k) = keychain_get()? {
        if k.len() == KEY_LEN {
            tracing::info!("guard token key loaded from Keychain");
            let mut key = Zeroizing::new([0u8; KEY_LEN]);
            key.copy_from_slice(&k);
            return Ok(key);
        }
        return Err(TokenError::KeyInit("keychain key not 32 bytes".to_string()));
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut *key);
    keychain_store(&key[..]).map_err(|e| {
        tracing::error!(error = %e, "keychain store failed — refusing to start (no ephemeral key)");
        TokenError::Keychain(format!("store failed: {e}"))
    })?;
    tracing::info!("guard token key generated + stored to Keychain");
    Ok(key)
}

#[cfg(not(target_os = "macos"))]
fn load_keychain_or_err() -> Result<Zeroizing<[u8; KEY_LEN]>, TokenError> {
    // P2-1: 非 macOS 无 Keychain, env key 未放行 → 拒启动 (fail-closed, 不回退弱密钥)。
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

use rusqlite::OptionalExtension;
