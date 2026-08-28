// P2-1 (audit §2.6): env key 门控 + 告警测试。
// 缺陷根因: env key 静默旁路 Keychain, 误配即主密钥进进程环境, 同 UID 进程可读。
// 修复: release 模式仅 FUSION_GUARD_ALLOW_ENV_KEY=1 或 --insecure-env-key flag 放行 env,
// 且放行时 warn 级告警 (运维审计可见); debug 放行 env 为 dev 姿态; env 不放行 → Keychain 强制。
// 测真实决策函数 token_store::resolve_key_source (规则 5: 决策用代码非 token, 不引 env/Keychain 阻塞)。

use fg_store::token_store::{resolve_key_source, KeySource};
use fg_store::AuditStore;

const TEST_KEY_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn ensure_env_key() {
    if std::env::var("FUSION_GUARD_TOKEN_KEY").is_err() {
        std::env::set_var("FUSION_GUARD_TOKEN_KEY", TEST_KEY_HEX);
    }
}

// P2-1 决策矩阵 (resolve_key_source is_debug, allow_env_flag, env_present):
//   debug + env → EnvDebug (dev 姿态, info)
//   release + allow_env_flag + env → EnvInsecure (warn 告警)
//   release + env (无 flag) → KeychainRequired (env 被门控, 不旁路 Keychain)
//   release + 无 env → KeychainRequired
//   debug + 无 env → KeychainRequired
//   release + flag + 无 env → KeychainRequired (flag 无 env 无意义)
#[test]
fn p21_decision_matrix_all_branches() {
    // debug build: env 放行为 dev 姿态。
    assert_eq!(
        resolve_key_source(true, false, true),
        KeySource::EnvDebug,
        "debug + env → EnvDebug"
    );
    assert_eq!(
        resolve_key_source(true, true, true),
        KeySource::EnvDebug,
        "debug + flag + env → EnvDebug (debug 优先)"
    );
    assert_eq!(
        resolve_key_source(true, false, false),
        KeySource::KeychainRequired,
        "debug + 无 env → KeychainRequired"
    );

    // release: env 须 flag 放行, 否则门控 → Keychain。
    assert_eq!(
        resolve_key_source(false, true, true),
        KeySource::EnvInsecure,
        "release + flag + env → EnvInsecure (warn)"
    );
    assert_eq!(
        resolve_key_source(false, false, true),
        KeySource::KeychainRequired,
        "release + env 无 flag → 门控, 不旁路 Keychain (P2-1 核心)"
    );
    assert_eq!(
        resolve_key_source(false, true, false),
        KeySource::KeychainRequired,
        "release + flag 无 env → KeychainRequired (flag 无 env 无意义)"
    );
    assert_eq!(
        resolve_key_source(false, false, false),
        KeySource::KeychainRequired,
        "release + 无 env → KeychainRequired"
    );
}

// P2-1 核心: release + env 存在但无 allow flag → env 被门控, 走 Keychain 路径。
// 现实 release 无 Keychain (non-macOS 或 Keychain 空) → 应拒启动 (fail-closed),
// 不静默用 env key 旁路。此测验证: 即使 env key 存在, 无 flag 时 TokenStore open
// 在 macOS 走 Keychain (env 不读); non-macOS 无 Keychain → err。
// 本测在 debug build 跑 (CI 主力) —— debug + 无 env → KeychainRequired, 无 env 路径。
// 验证 debug build 下 env 存在时走 EnvDebug (load 成功, 非 Keychain hang)。
#[test]
fn p21_debug_env_loads_without_keychain() {
    ensure_env_key();
    let dir = std::env::temp_dir().join(format!(
        "fg-p21-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("guard-p21.db");

    // debug build: env 存在 → EnvDebug → env key 加载, 不触 Keychain (无 hang)。
    let store = AuditStore::open(&db).unwrap();
    drop(store);

    // 写一个 token + reveal 验证 env key 生效 (非 Keychain 临时 key)。
    let store = AuditStore::open(&db).unwrap();
    let tid = uuid::Uuid::new_v4().to_string();
    store
        .tokens()
        .put_tenant(&tid, "secret-value", "default")
        .unwrap();
    let revealed = store.tokens().get_tenant(&tid, "default").unwrap();
    assert_eq!(
        revealed, "secret-value",
        "env key encrypt/decrypt roundtrip works (P2-1 debug env path)"
    );

    std::fs::remove_file(&db).ok();
    std::fs::remove_file(db.with_file_name("token.db")).ok();
    std::fs::remove_file(db.with_file_name("action.db")).ok();
    let _ = std::fs::remove_dir_all(&dir);
}

// P2-1: release 门控回归 —— release + env 无 flag 时 resolve 返 KeychainRequired。
// 调真实 resolve_key_source (非 oracle, 规则 7: 不维护两份决策逻辑)。若未来误删 flag 门控, 此测先红。
#[test]
fn p21_release_env_without_flag_is_keychain_required() {
    // 模拟 release: is_debug=false, allow_env_flag=false, env 存在。
    assert_eq!(
        resolve_key_source(false, false, true),
        KeySource::KeychainRequired,
        "release + env + no allow flag MUST gate to Keychain (P2-1: env 不旁路 Keychain)"
    );
    // 模拟 release + flag: EnvInsecure (告警路径, 仍可用但 warn)。
    assert_eq!(
        resolve_key_source(false, true, true),
        KeySource::EnvInsecure,
        "release + env + allow flag → EnvInsecure (warn 告警, P2-1 显式放行)"
    );
}
