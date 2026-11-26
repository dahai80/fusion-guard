// H-C secret side: pure decision function for the shared-secret source (resolve_shared_secret) + generation format unit tests.
// Does not touch the real Keychain (non-deterministic; CI has no user Keychain) — decision logic verified via pure functions (Rule 5).
// Keychain I/O is covered by the authorizer integration tests + deployment docs (live-tested with security find-generic-password).

use fg_store::secret_store::{generate_shared_secret, resolve_shared_secret, SharedSecretSource};

#[test]
fn resolve_keychain_when_no_env() {
    // env not provided -> Keychain (prod path; a missing Keychain entry is the caller's None decision).
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
    // dev builds tolerate env (EnvDebug, info posture).
    assert_eq!(
        resolve_shared_secret(true, false, true),
        SharedSecretSource::EnvDebug
    );
}

#[test]
fn resolve_env_insecure_when_env_present_release_with_flag() {
    // release + env + explicit bypass flag -> EnvInsecure (warning emitted).
    assert_eq!(
        resolve_shared_secret(false, true, true),
        SharedSecretSource::EnvInsecure
    );
}

#[test]
fn resolve_keychain_when_env_present_release_no_flag() {
    // release + env but no bypass flag -> Keychain (never silently uses env, preventing a missed-flag downgrade).
    assert_eq!(
        resolve_shared_secret(false, false, true),
        SharedSecretSource::Keychain
    );
}

#[test]
fn generate_shared_secret_is_hex_64_chars() {
    // Generates 32 bytes of hex = 64 chars, pure hex (usable as a security add-generic-password -w value).
    let s = generate_shared_secret();
    assert_eq!(s.len(), 64, "shared secret must be 32-byte hex = 64 chars");
    assert!(
        s.chars().all(|c| c.is_ascii_hexdigit()),
        "shared secret must be pure hex"
    );
}

#[test]
fn generate_shared_secret_is_random() {
    // Two generations differ (not a fixed value).
    let a = generate_shared_secret();
    let b = generate_shared_secret();
    assert_ne!(a, b, "generation must be random, not fixed");
}
