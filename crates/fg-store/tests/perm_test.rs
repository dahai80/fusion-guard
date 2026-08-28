// C21 (P0-G9): DB 文件/目录权限硬化测试
// 验证 AuditStore::open 后 guard.db 0o600 + 父目录 0o700 (不依赖 umask)。

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use fg_store::AuditStore;

const TEST_KEY_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn ensure_env_key() {
    if std::env::var("FUSION_GUARD_TOKEN_KEY").is_err() {
        std::env::set_var("FUSION_GUARD_TOKEN_KEY", TEST_KEY_HEX);
    }
}

fn temp_db() -> PathBuf {
    ensure_env_key();
    let dir = std::env::temp_dir().join(format!(
        "fg-perm-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("guard-perm.db")
}

fn mode(p: &std::path::Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[test]
fn db_and_dir_hardened_after_open() {
    let db = temp_db();
    let parent = db.parent().unwrap().to_path_buf();
    let _store = AuditStore::open(&db).unwrap();
    // 触发一次写以创建 -wal/-shm (WAL 按需)。
    let store = AuditStore::open(&db).unwrap();
    drop(store);

    // C21: DB 0o600, 目录 0o700。
    assert_eq!(
        mode(&db),
        0o600,
        "guard.db must be 0o600 after open (C21 hardening, not umask 0644)"
    );
    assert_eq!(
        mode(&parent),
        0o700,
        "guard dir must be 0o700 after open (C21 hardening, not umask 0755)"
    );

    // -wal/-shm 若存在亦须 0o600。
    let wal = {
        let mut s = db.as_os_str().to_os_string();
        s.push("-wal");
        PathBuf::from(s)
    };
    let shm = {
        let mut s = db.as_os_str().to_os_string();
        s.push("-shm");
        PathBuf::from(s)
    };
    if wal.exists() {
        assert_eq!(mode(&wal), 0o600, "-wal must be 0o600 (C21)");
    }
    if shm.exists() {
        assert_eq!(mode(&shm), 0o600, "-shm must be 0o600 (C21)");
    }

    // P1-7: 物理分库后 token.db / action.db sibling 亦须 0o600 (C21 三库均硬化)。
    let token_db = db.with_file_name("token.db");
    let action_db = db.with_file_name("action.db");
    assert_eq!(
        mode(&token_db),
        0o600,
        "token.db must be 0o600 (P1-7 split, C21)"
    );
    assert_eq!(
        mode(&action_db),
        0o600,
        "action.db must be 0o600 (P1-7 split, C21)"
    );
}
