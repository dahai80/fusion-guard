// Shared secret (§12.1 second auth factor) Keychain source helpers.
//
// token-key (token_store.rs) is a 32-byte symmetric AES-GCM master key, using the bytes Keychain path (private).
// shared-secret is the string second factor (carried by the client over the wire, constant-time compare), using the string Keychain path.
// Both share the same Keychain service "fusion-guard" with different accounts ("token-key" / "shared-secret") — domain separation.
//
// Design (rule 5: decide with code, not tokens): resolve_shared_secret is a pure function deciding the source (Keychain/env/none),
// actual loading is done by PeerAuthorizer calling keychain_secret_get / keychain_secret_store.
// This mirrors token_store::resolve_key_source (the secret-side mirror of the same audit findings H-C + P2-1).

#[cfg(target_os = "macos")]
use security_framework::passwords::{get_generic_password, set_generic_password};

pub const KEYCHAIN_SERVICE: &str = "fusion-guard";
pub const KEYCHAIN_ACCOUNT: &str = "shared-secret";
// Same value as fg-ipc::SHARED_SECRET_ENV (fg-ipc is the authoritative definition; fg-store keeps a local mirror to avoid a cross-crate circular dependency).
pub const SHARED_SECRET_ENV: &str = "FUSION_GUARD_SHARED_SECRET";

// Shared secret source decision (mirrors token_store::KeySource + resolve_key_source).
// Keychain = recommended for prod (key never enters environment variables; unreadable by same-UID processes).
// EnvDebug = dev allows env (debug_assertions, info posture).
// EnvInsecure = release uses env (requires FUSION_GUARD_ALLOW_INSECURE_SECRET=1 explicit opt-in, warns — not for prod).
// None = no source provided (release refuses to start, dev skips secret verification).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SharedSecretSource {
    Keychain,
    EnvDebug,
    EnvInsecure,
    None,
}

#[cfg_attr(not(feature = "test-helpers"), allow(dead_code))]
pub fn resolve_shared_secret(
    is_debug: bool,
    allow_insecure_flag: bool,
    env_present: bool,
) -> SharedSecretSource {
    if env_present && (is_debug || allow_insecure_flag) {
        if is_debug {
            SharedSecretSource::EnvDebug
        } else {
            SharedSecretSource::EnvInsecure
        }
    } else if env_present {
        // env present but not explicitly authorized (release without flag) — treat as unauthorized, use Keychain; if Keychain is also missing → None.
        // Do not silently use env (prevents accidental downgrade when release misses the flag); PeerAuthorizer decides on Keychain.
        SharedSecretSource::Keychain
    } else {
        // no env → Keychain (prod); Keychain also missing → None (release refuses).
        SharedSecretSource::Keychain
    }
}

pub fn allow_insecure_secret_flag_set() -> bool {
    std::env::var("FUSION_GUARD_ALLOW_INSECURE_SECRET")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub fn shared_secret_env_present() -> bool {
    std::env::var(SHARED_SECRET_ENV).is_ok()
}

// Read shared secret from Keychain (macOS). Missing/read failure → Ok(None) (first start or unset).
// Non-macOS → Ok(None) (no Keychain, env path instead).
#[cfg(target_os = "macos")]
pub fn keychain_secret_get() -> Result<Option<String>, SecretError> {
    match get_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT) {
        Ok(v) => {
            let s = String::from_utf8(v)
                .map_err(|e| SecretError::Keychain(format!("shared secret not utf8: {e}")))?;
            if s.is_empty() {
                Ok(None)
            } else {
                Ok(Some(s))
            }
        }
        Err(e) => {
            tracing::debug!(error = %e, "shared secret keychain get (likely first start / unset)");
            Ok(None)
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub fn keychain_secret_get() -> Result<Option<String>, SecretError> {
    Ok(None)
}

// Store shared secret in Keychain (generated on first macOS start).
#[cfg(target_os = "macos")]
pub fn keychain_secret_store(secret: &str) -> Result<(), SecretError> {
    set_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, secret.as_bytes())
        .map_err(|e| SecretError::Keychain(e.to_string()))?;
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn keychain_secret_store(_secret: &str) -> Result<(), SecretError> {
    Err(SecretError::Keychain(
        "non-macOS has no Keychain — shared secret must come from env".to_string(),
    ))
}

// Generate a strong random shared secret (hex, 32 bytes = 64 hex chars).
// Uses rand::thread_rng (same source as token_store master key generation).
pub fn generate_shared_secret() -> String {
    let mut buf = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
    hex::encode(buf)
}

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("keychain error: {0}")]
    Keychain(String),
}
