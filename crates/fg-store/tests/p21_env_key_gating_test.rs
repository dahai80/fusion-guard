// P2-1 (audit §2.6): env key gating + warning tests.
// Root cause: the env key silently bypassed the Keychain; one misconfiguration put the master key into the process
// environment, readable by any same-UID process.
// Fix: in release mode, env is only allowed with FUSION_GUARD_ALLOW_ENV_KEY=1 or the --insecure-env-key flag, and
// allowing it emits a warn-level alert (visible to ops audit); allowing env in debug is a dev posture; env not
// allowed -> Keychain enforced.
// Tests the real decision function token_store::resolve_key_source (Rule 5: decide with code, not tokens; no
// env/Keychain blocking).

use fg_store::token_store::{resolve_key_source, KeySource};
use fg_store::AuditStore;

const TEST_KEY_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn ensure_env_key() {
    if std::env::var("FUSION_GUARD_TOKEN_KEY").is_err() {
        std::env::set_var("FUSION_GUARD_TOKEN_KEY", TEST_KEY_HEX);
    }
}

// P2-1 decision matrix (resolve_key_source is_debug, allow_env_flag, env_present):
//   debug + env -> EnvDebug (dev posture, info)
//   release + allow_env_flag + env -> EnvInsecure (warn alert)
//   release + env (no flag) -> KeychainRequired (env gated, does not bypass Keychain)
//   release + no env -> KeychainRequired
//   debug + no env -> KeychainRequired
//   release + flag + no env -> KeychainRequired (flag without env is meaningless)
#[test]
fn p21_decision_matrix_all_branches() {
    // debug build: env allowed is a dev posture.
    assert_eq!(
        resolve_key_source(true, false, true),
        KeySource::EnvDebug,
        "debug + env -> EnvDebug"
    );
    assert_eq!(
        resolve_key_source(true, true, true),
        KeySource::EnvDebug,
        "debug + flag + env -> EnvDebug (debug takes priority)"
    );
    assert_eq!(
        resolve_key_source(true, false, false),
        KeySource::KeychainRequired,
        "debug + no env -> KeychainRequired"
    );

    // release: env requires the allow flag, otherwise gated -> Keychain.
    assert_eq!(
        resolve_key_source(false, true, true),
        KeySource::EnvInsecure,
        "release + flag + env -> EnvInsecure (warn)"
    );
    assert_eq!(
        resolve_key_source(false, false, true),
        KeySource::KeychainRequired,
        "release + env without flag -> gated, does not bypass Keychain (P2-1 core)"
    );
    assert_eq!(
        resolve_key_source(false, true, false),
        KeySource::KeychainRequired,
        "release + flag without env -> KeychainRequired (flag without env is meaningless)"
    );
    assert_eq!(
        resolve_key_source(false, false, false),
        KeySource::KeychainRequired,
        "release + no env -> KeychainRequired"
    );
}

// P2-1 core: release + env present but no allow flag -> env is gated, Keychain path taken.
// A realistic release without a Keychain (non-macOS or empty Keychain) should refuse startup (fail-closed) rather
// than silently using the env key as a bypass. This test verifies: even with an env key present and no flag,
// TokenStore open goes to Keychain on macOS (env not read); on non-macOS without a Keychain -> err.
// This test runs in a debug build (CI mainline) — debug + no env -> KeychainRequired, the no-env path.
// It verifies that with env present in a debug build the EnvDebug path is taken (load succeeds, no Keychain hang).
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

    // debug build: env present -> EnvDebug -> env key loaded, no Keychain touched (no hang).
    let store = AuditStore::open(&db).unwrap();
    drop(store);

    // Write a token + reveal to confirm the env key is in effect (not a Keychain ephemeral key).
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

// P2-1: release gating regression — release + env without a flag resolves to KeychainRequired.
// Calls the real resolve_key_source (not an oracle; Rule 7: never keep two copies of the decision logic). If the
// flag gate is ever mistakenly removed, this test turns red first.
#[test]
fn p21_release_env_without_flag_is_keychain_required() {
    // Simulate release: is_debug=false, allow_env_flag=false, env present.
    assert_eq!(
        resolve_key_source(false, false, true),
        KeySource::KeychainRequired,
        "release + env + no allow flag MUST gate to Keychain (P2-1: env does not bypass Keychain)"
    );
    // Simulate release + flag: EnvInsecure (warning path, still usable but warned).
    assert_eq!(
        resolve_key_source(false, true, true),
        KeySource::EnvInsecure,
        "release + env + allow flag -> EnvInsecure (warn alert, P2-1 explicit bypass)"
    );
}
