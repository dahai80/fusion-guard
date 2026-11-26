// H-E (product-audit §5): regression for the master-key-loss single-point-fatal fix.
// Root cause: load_or_create_key silently minted a new master key on Keychain miss, with no data migration —
// all historical tokens became undecryptable (new key fails on old ciphertext) + full audit-chain verify broke
// (false tamper report), and key loss was indistinguishable from real tampering. Fix: when the DB already has
// historical data (token.db not virgin) but the Keychain lacks the key -> refuse startup with a clear error
// instead of silently reminting. Only a virgin DB allows first-time minting.
//
// This test verifies the gate decision logic (token_db_is_virgin + test_key_loss_refuses) and does not touch the
// real Keychain (it may hold a key from a previous round, making refusal tests flaky). The real-Keychain refusal
// is guaranteed by load_keychain_or_err's allow_mint branch; here we unit-test the pure decision functions.

use fg_store::token_store::{test_key_loss_refuses, test_token_db_is_virgin};
use rusqlite::Connection;

const TEST_KEY_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn ensure_env_key() {
    if std::env::var("FUSION_GUARD_TOKEN_KEY").is_err() {
        std::env::set_var("FUSION_GUARD_TOKEN_KEY", TEST_KEY_HEX);
    }
}

// Build a token.db with the same schema as TokenStore::open_checked (tokens + key_versions seeded v1).
fn fresh_token_db() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE tokens (
            token_id TEXT PRIMARY KEY,
            ciphertext BLOB NOT NULL,
            nonce BLOB NOT NULL,
            created_ts INTEGER NOT NULL,
            in_flight INTEGER NOT NULL DEFAULT 0,
            ttl_secs INTEGER NOT NULL,
            tenant_id TEXT NOT NULL DEFAULT 'default'
        );
        CREATE TABLE key_versions (version INTEGER PRIMARY KEY, created_ts INTEGER NOT NULL);
        INSERT OR IGNORE INTO key_versions (version, created_ts) VALUES (1, 0);",
    )
    .unwrap();
    conn
}

// H-E (a): virgin token.db (no token rows + key_versions only seeded v1) -> virgin=true -> first mint allowed.
#[test]
fn virgin_db_allows_mint() {
    ensure_env_key();
    let conn = fresh_token_db();
    assert!(
        test_token_db_is_virgin(&conn),
        "empty token.db + seed-only key_versions = virgin -> allow first mint (H-E)"
    );
}

// H-E (b): token.db has token rows -> virgin=false -> missing Keychain key = key loss, refuse remint.
#[test]
fn db_with_tokens_blocks_remint() {
    ensure_env_key();
    let conn = fresh_token_db();
    conn.execute(
        "INSERT INTO tokens (token_id, ciphertext, nonce, created_ts, in_flight, ttl_secs)
         VALUES ('tok-1', x'aa', x'bb', 100, 0, 300)",
        [],
    )
    .unwrap();
    assert!(
        !test_token_db_is_virgin(&conn),
        "token.db with token rows = NOT virgin -> missing key = loss, refuse remint (H-E)"
    );
}

// H-E (c): token.db has no token rows but key_versions has v2 (key historically rotated) -> virgin=false.
// The DB has used a master key before (even though tokens were TTL-evicted); a missing Keychain key is still key loss.
#[test]
fn db_with_key_rotation_blocks_remint() {
    ensure_env_key();
    let conn = fresh_token_db();
    conn.execute(
        "INSERT INTO key_versions (version, created_ts) VALUES (2, 1000)",
        [],
    )
    .unwrap();
    assert!(
        !test_token_db_is_virgin(&conn),
        "key_versions v2+ = historically used key -> NOT virgin, refuse remint (H-E)"
    );
}

// H-E (d): key_versions seed created_ts > 0 (non-zero) -> virgin=false.
// created_ts=0 is the seed's convention marker (open_checked INSERT VALUES (1,0)); rotation writes a real ts.
#[test]
fn db_with_nonzero_seed_ts_blocks_remint() {
    ensure_env_key();
    let conn = fresh_token_db();
    // Change the seed to created_ts>0 (simulating an older version writing a real ts into the seed row)
    conn.execute(
        "UPDATE key_versions SET created_ts = 500 WHERE version = 1",
        [],
    )
    .unwrap();
    assert!(
        !test_token_db_is_virgin(&conn),
        "seed key_version with created_ts>0 = historically used -> NOT virgin (H-E)"
    );
}

// H-E (e): decision gate — Keychain key missing (env unset) + allow_mint=false -> refuse startup (Err).
// env_present is explicitly passed as false to simulate the prod Keychain-only posture, without mutating the
// process env (avoiding interference with parallel tests).
#[test]
fn key_loss_decision_refuses_when_data_exists() {
    // env_present=false (prod Keychain-only, no env key) posture
    // allow_mint=false (DB has historical data) -> refuse startup
    let res = test_key_loss_refuses(false, false);
    assert!(
        res.is_err(),
        "Keychain missing + data exists + allow_mint=false -> refuse start (H-E core gate)"
    );
    let msg = res.unwrap_err();
    assert!(
        msg.contains("refusing to remint") || msg.contains("master key lost"),
        "refusal message must explain key loss, got: {msg}"
    );

    // allow_mint=true (virgin DB, first start) -> allow minting
    let res_ok = test_key_loss_refuses(true, false);
    assert!(
        res_ok.is_ok(),
        "Keychain missing + virgin DB + allow_mint=true -> allow first mint (H-E)"
    );
}

// H-E (f): env path bypasses allow_mint — an explicitly provided FUSION_GUARD_TOKEN_KEY means ops know the key,
// so it is allowed even when the DB is not virgin (dev/CI posture, not prod). This branch does not refuse; env is
// itself an explicit key source.
#[test]
fn env_key_bypasses_allow_mint() {
    // env_present=true -> Ok regardless of allow_mint true/false (env is an explicit key source, no Keychain refusal)
    assert!(
        test_key_loss_refuses(false, true).is_ok(),
        "env key present bypasses allow_mint=false (explicit key source, H-E env path)"
    );
    assert!(
        test_key_loss_refuses(true, true).is_ok(),
        "env key present + allow_mint=true -> Ok (H-E env path)"
    );
}
