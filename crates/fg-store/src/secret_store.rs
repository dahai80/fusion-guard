// 共享 secret (§12.1 第二鉴权因子) Keychain 来源辅助。
//
// token-key (token_store.rs) 是 32 字节对称 AES-GCM 主密钥, 走 bytes Keychain 路径 (私有)。
// shared-secret 是字符串第二因子 (client 走 wire 携带, 常量时间比对), 走 string Keychain 路径。
// 两者 Keychain service 同为 "fusion-guard", account 不同 ("token-key" / "shared-secret") —— 域分离。
//
// 设计 (规则 5: 决策用代码非 token): resolve_shared_secret 纯函数决定来源 (Keychain/env/none),
// 实际加载由 PeerAuthorizer 调 keychain_secret_get / keychain_secret_store 执行。
// 这与 token_store::resolve_key_source 对齐 (同一审计缺陷 H-C + P2-1 的 secret 侧镜像)。

#[cfg(target_os = "macos")]
use security_framework::passwords::{get_generic_password, set_generic_password};

pub const KEYCHAIN_SERVICE: &str = "fusion-guard";
pub const KEYCHAIN_ACCOUNT: &str = "shared-secret";
// 与 fg-ipc::SHARED_SECRET_ENV 同值 (fg-ipc 是权威定义; fg-store 本地镜像避免跨 crate 循环依赖)。
pub const SHARED_SECRET_ENV: &str = "FUSION_GUARD_SHARED_SECRET";

// shared secret 来源决策 (镜像 token_store::KeySource + resolve_key_source)。
// Keychain = prod 推荐 (密钥不入环境变量, 同 UID 进程不可读)。
// EnvDebug = dev 放行 env (debug_assertions, info 姿态)。
// EnvInsecure = release 用 env (FUSION_GUARD_ALLOW_INSECURE_SECRET=1 显式放行, warn 告警 —— prod 不应用)。
// None = 未提供任何来源 (release 启动拒, dev 跳过 secret 校验)。
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
        // env 提供但未显式放行 (release 无 flag) —— 视为未授权, 走 Keychain; 若 Keychain 也缺 → None。
        // 不静默用 env (防 release 漏 flag 意外降级); 由 PeerAuthorizer 再判 Keychain。
        SharedSecretSource::Keychain
    } else {
        // env 无 → Keychain (prod); Keychain 也缺 → None (release 拒)。
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

// Keychain 读 shared secret (macOS)。缺/读失败 → Ok(None) (首次启动或未配置)。
// 非 macOS → Ok(None) (无 Keychain, 走 env 路径)。
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

// Keychain 存 shared secret (macOS 首次启动生成)。
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

// 生成强随机 shared secret (hex, 32 字节 = 64 hex 字符)。
// 用 rand::thread_rng (与 token_store 主密钥生成同源)。
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
