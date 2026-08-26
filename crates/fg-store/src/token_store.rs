use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rusqlite::{params, Connection};
use std::sync::Mutex;

const KEYCHAIN_SERVICE: &str = "fusion-guard";
const KEYCHAIN_ACCOUNT: &str = "token-key";
const TOKEN_TTL_SECS: i64 = 300;

pub struct TokenStore {
    db: Mutex<Connection>,
    key: Vec<u8>,
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
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
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
                ttl_secs INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_tokens_ts ON tokens(created_ts);
            ",
        )?;
        let key = load_or_create_key()?;
        Ok(Self {
            db: Mutex::new(conn),
            key,
        })
    }

    pub fn put(&self, token_id: &str, plaintext: &str) -> Result<(), TokenError> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let nonce_bytes = generate_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| TokenError::Encrypt(e.to_string()))?;
        let now = now_ts();
        let g = self.db.lock().expect("token db mutex poisoned");
        g.execute(
            "INSERT OR REPLACE INTO tokens (token_id, ciphertext, nonce, created_ts, in_flight, ttl_secs)
             VALUES (?1, ?2, ?3, ?4, 0, ?5)",
            params![token_id, ct, nonce_bytes, now, TOKEN_TTL_SECS],
        )?;
        tracing::debug!(token_id = token_id, "token stored (encrypted)");
        Ok(())
    }

    pub fn get(&self, token_id: &str) -> Result<String, TokenError> {
        let g = self.db.lock().expect("token db mutex poisoned");
        let row = g
            .query_row(
                "SELECT ciphertext, nonce FROM tokens WHERE token_id = ?1",
                params![token_id],
                |r| {
                    let ct: Vec<u8> = r.get(0)?;
                    let nonce: Vec<u8> = r.get(1)?;
                    Ok((ct, nonce))
                },
            )
            .optional()?;
        let (ct, nonce_bytes) = row.ok_or_else(|| TokenError::NotFound(token_id.to_string()))?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key));
        let nonce = Nonce::from_slice(&nonce_bytes);
        let pt = cipher
            .decrypt(nonce, ct.as_ref())
            .map_err(|e| TokenError::Decrypt(e.to_string()))?;
        let s = String::from_utf8(pt).map_err(|e| TokenError::Decrypt(e.to_string()))?;
        tracing::debug!(token_id = token_id, "token revealed");
        Ok(s)
    }

    pub fn set_in_flight(&self, token_id: &str, in_flight: bool) -> Result<(), TokenError> {
        let g = self.db.lock().expect("token db mutex poisoned");
        g.execute(
            "UPDATE tokens SET in_flight = ?1 WHERE token_id = ?2",
            params![in_flight as i64, token_id],
        )?;
        Ok(())
    }

    pub fn evict_expired(&self) -> Result<usize, TokenError> {
        let now = now_ts();
        let g = self.db.lock().expect("token db mutex poisoned");
        let n = g.execute(
            "DELETE FROM tokens WHERE created_ts + ttl_secs < ?1 AND in_flight = 0",
            params![now],
        )?;
        if n > 0 {
            tracing::info!(evicted = n, "expired non-in-flight tokens evicted");
        }
        Ok(n)
    }

    pub fn key_bytes(&self) -> Vec<u8> {
        self.key.clone()
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

fn load_or_create_key() -> Result<Vec<u8>, TokenError> {
    if let Ok(hex) = std::env::var("FUSION_GUARD_TOKEN_KEY") {
        if let Ok(bytes) = hex_decode(&hex) {
            if bytes.len() == 32 {
                tracing::info!("guard token key loaded from FUSION_GUARD_TOKEN_KEY env");
                return Ok(bytes);
            }
            tracing::warn!("FUSION_GUARD_TOKEN_KEY not 32 bytes, ignoring");
        }
    }
    if let Some(k) = keychain_get()? {
        tracing::info!("guard token key loaded from Keychain");
        return Ok(k);
    }
    let mut key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key);
    match keychain_store(&key) {
        Ok(()) => {
            tracing::info!("guard token key generated + stored to Keychain");
        }
        Err(e) => {
            tracing::warn!(error = %e, "keychain store failed, key ephemeral (non-prod)");
        }
    }
    Ok(key.to_vec())
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

#[cfg(not(target_os = "macos"))]
fn keychain_get() -> Result<Option<Vec<u8>>, TokenError> {
    tracing::warn!("non-macOS: keychain disabled, ephemeral key");
    Ok(None)
}

#[cfg(not(target_os = "macos"))]
fn keychain_store(_key: &[u8]) -> Result<(), TokenError> {
    Ok(())
}

use rusqlite::OptionalExtension;
