// H-C secret 侧: shared secret 来源决策纯函数 (resolve_shared_secret) + 生成格式单测。
// 不触真实 Keychain (非确定性, CI 无用户 Keychain) —— 决策逻辑用纯函数验证 (规则 5)。
// Keychain I/O 由 authorizer 集成测试 + 部署文档覆盖 (security find-generic-password 实测)。

use fg_store::secret_store::{generate_shared_secret, resolve_shared_secret, SharedSecretSource};

#[test]
fn resolve_keychain_when_no_env() {
    // env 未提供 → Keychain (prod 路径; Keychain 缺由调用方再判 None)。
    assert_eq!(
        resolve_shared_secret(true, false, false),
        SharedSecretSource::Keychain
    );
    assert_eq!(
        resolve_shared_secret(false, false, false),
        SharedSecretSource::Keychain
    );
}

#[test]
fn resolve_env_debug_when_env_present_debug_build() {
    // dev 构建容 env (EnvDebug, info 姿态)。
    assert_eq!(
        resolve_shared_secret(true, false, true),
        SharedSecretSource::EnvDebug
    );
}

#[test]
fn resolve_env_insecure_when_env_present_release_with_flag() {
    // release + env + 显式放行 flag → EnvInsecure (warn 告警)。
    assert_eq!(
        resolve_shared_secret(false, true, true),
        SharedSecretSource::EnvInsecure
    );
}

#[test]
fn resolve_keychain_when_env_present_release_no_flag() {
    // release + env 但未放行 → Keychain (不静默用 env, 防漏 flag 降级)。
    assert_eq!(
        resolve_shared_secret(false, false, true),
        SharedSecretSource::Keychain
    );
}

#[test]
fn generate_shared_secret_is_hex_64_chars() {
    // 生成 32 字节 hex = 64 字符, 纯 hex (可作 security add-generic-password -w 值)。
    let s = generate_shared_secret();
    assert_eq!(s.len(), 64, "shared secret 须 32 字节 hex = 64 字符");
    assert!(
        s.chars().all(|c| c.is_ascii_hexdigit()),
        "shared secret 须纯 hex"
    );
}

#[test]
fn generate_shared_secret_is_random() {
    // 两次生成不同 (非固定值)。
    let a = generate_shared_secret();
    let b = generate_shared_secret();
    assert_ne!(a, b, "生成须随机非固定");
}
