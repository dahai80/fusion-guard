// H-E (product-audit §5): 主密钥丢失单点致命修复的回归。
// 缺陷根因: load_or_create_key 在 Keychain miss 时静默生成新主密钥, 无数据迁移 ——
// 全量历史 token 不可解 (新 key 解旧密文失败) + 审计链全量 verify 失效 (假报篡改),
// 且密钥丢失与真篡改不可区分。修复: 检测 DB 已有历史数据 (token.db 非全新) 而 Keychain
// 缺密钥 → 拒启动明确报错, 非静默重生成。仅 DB 全新 (virgin) 允许首次生成。
//
// 本测试验证门控决策逻辑 (token_db_is_virgin + test_key_loss_refuses), 不触真实 Keychain
// (Keychain 可能存有上轮 key, refusal 测试 flaky)。真实 Keychain 拒绝由 load_keychain_or_err
// 的 allow_mint 分支保证, 此处单测纯决策函数。

use fg_store::token_store::{test_key_loss_refuses, test_token_db_is_virgin};
use rusqlite::Connection;

const TEST_KEY_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn ensure_env_key() {
    if std::env::var("FUSION_GUARD_TOKEN_KEY").is_err() {
        std::env::set_var("FUSION_GUARD_TOKEN_KEY", TEST_KEY_HEX);
    }
}

// 建与 TokenStore::open_checked 相同 schema 的 token.db (tokens + key_versions 种子 v1)。
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

// H-E (a): virgin token.db (无 token 行 + key_versions 仅种子 v1) → virgin=true → 允许首次生成。
#[test]
fn virgin_db_allows_mint() {
    ensure_env_key();
    let conn = fresh_token_db();
    assert!(
        test_token_db_is_virgin(&conn),
        "empty token.db + seed-only key_versions = virgin → allow first mint (H-E)"
    );
}

// H-E (b): token.db 有 token 行 → virgin=false → Keychain 缺密钥 = 丢失, 拒重生成。
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
        "token.db with token rows = NOT virgin → missing key = loss, refuse remint (H-E)"
    );
}

// H-E (c): token.db 无 token 行但 key_versions 有 v2 (历史轮换过密钥) → virgin=false。
// 说明该库历史用过主密钥 (虽 token 已被 TTL 清), Keychain 缺密钥仍是丢失。
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
        "key_versions v2+ = historically used key → NOT virgin, refuse remint (H-E)"
    );
}

// H-E (d): key_versions 种子 created_ts > 0 (非 0) → virgin=false。
// created_ts=0 是种子的约定标记 (open_checked INSERT VALUES (1,0)); 轮换写真实 ts。
#[test]
fn db_with_nonzero_seed_ts_blocks_remint() {
    ensure_env_key();
    let conn = fresh_token_db();
    // 种子改 created_ts>0 (模拟某旧版写入真实 ts 到种子行)
    conn.execute(
        "UPDATE key_versions SET created_ts = 500 WHERE version = 1",
        [],
    )
    .unwrap();
    assert!(
        !test_token_db_is_virgin(&conn),
        "seed key_version with created_ts>0 = historically used → NOT virgin (H-E)"
    );
}

// H-E (e): 决策门控 —— Keychain 缺密钥 (env 未设) + allow_mint=false → 拒启动 (Err)。
// env_present 显式传入 false 模拟 prod Keychain-only 姿态, 不改进程 env (避免干扰并行测试)。
#[test]
fn key_loss_decision_refuses_when_data_exists() {
    // env_present=false (prod Keychain-only, 无 env key) 姿态
    // allow_mint=false (DB 有历史数据) → 拒启动
    let res = test_key_loss_refuses(false, false);
    assert!(
        res.is_err(),
        "Keychain missing + data exists + allow_mint=false → refuse start (H-E core gate)"
    );
    let msg = res.unwrap_err();
    assert!(
        msg.contains("refusing to remint") || msg.contains("master key lost"),
        "refusal message must explain key loss, got: {msg}"
    );

    // allow_mint=true (DB 全新首次启动) → 放行生成
    let res_ok = test_key_loss_refuses(true, false);
    assert!(
        res_ok.is_ok(),
        "Keychain missing + virgin DB + allow_mint=true → allow first mint (H-E)"
    );
}

// H-E (f): env 路径绕过 allow_mint —— FUSION_GUARD_TOKEN_KEY 显式提供即视为运维知晓密钥,
// 即使 DB 非全新也放行 (dev/CI 姿态, 非 prod)。此分支不拒, env 本就是显式密钥源。
#[test]
fn env_key_bypasses_allow_mint() {
    // env_present=true → 无论 allow_mint true/false 都 Ok (env 显式密钥源, 不走 Keychain 拒绝)
    assert!(
        test_key_loss_refuses(false, true).is_ok(),
        "env key present bypasses allow_mint=false (explicit key source, H-E env path)"
    );
    assert!(
        test_key_loss_refuses(true, true).is_ok(),
        "env key present + allow_mint=true → Ok (H-E env path)"
    );
}
