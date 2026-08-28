// P1-5 (audit §3.1): Authorizer trait 单测 —— 鉴权纯逻辑独立于 I/O。
// 旧码 peercred→身份 (handle_conn) 与 secret 校验 (dispatch_arc) 散在套接字路径,
// 只能起真实 socket 集成测才覆盖。抽 trait 后单测直接喂 uid/secret 断言决策, 无需套接字/DB。
//
// 覆盖:
//   resolve_identity — admin(uid 0, 空租户集 + is_admin), 非admin(查 FakeLookup 租户),
//                      peercred 拒绝(auth_ok=false)。
//   authorize_method — ping 对任意对端开放 (即使 auth_ok=false 也 Allow),
//                      非 ping + auth_ok=false → DenyPeercred,
//                      非 ping + auth_ok + secret 未设(dev) → Allow,
//                      非 ping + auth_ok + secret 错 → DenySecret,
//                      非 ping + auth_ok + secret 对 → Allow。
// 用 new_with_lookup (test-helpers) 注入 FakeLookup, 无 AuditStore/Keychain/env 依赖。

use std::sync::Arc;

use fg_ipc::{AuthDecision, Authorizer, CallerIdentity, PeerAuthorizer, PeerUid, TenantLookup};

// 假租户表: uid 1000 → ["t1","t2"], 其余空。
struct FakeLookup;
impl TenantLookup for FakeLookup {
    fn tenants_for_uid(&self, uid: u32) -> Vec<String> {
        if uid == 1000 {
            vec!["t1".to_string(), "t2".to_string()]
        } else {
            Vec::new()
        }
    }
}

fn auth_with(secret: Option<&str>) -> PeerAuthorizer {
    PeerAuthorizer::new_with_lookup(Arc::new(FakeLookup), secret.map(|s| s.to_string()))
}

// --- resolve_identity ---

#[test]
fn resolve_identity_admin_root_empty_tenants() {
    let auth = auth_with(None);
    // 对端 uid 0 = root, allow_root → auth_ok, is_admin, 空 tenants (root 全权不查表)。
    let id = auth.resolve_identity(PeerUid::Resolved(0), 501);
    assert!(id.auth_ok);
    assert!(id.is_admin);
    assert!(
        id.tenants.is_empty(),
        "admin tenants 须空 (root 全权, 不查表)"
    );
    assert_eq!(id.uid, 0);
}

#[test]
fn resolve_identity_same_uid_non_admin_loads_tenants() {
    let auth = auth_with(None);
    // 对端 uid == our_uid → peer_allowed → auth_ok, 非 admin → 查 FakeLookup。
    let id = auth.resolve_identity(PeerUid::Resolved(1000), 1000);
    assert!(id.auth_ok);
    assert!(!id.is_admin);
    assert_eq!(id.tenants, vec!["t1".to_string(), "t2".to_string()]);
    assert_eq!(id.uid, 1000);
}

#[test]
fn resolve_identity_peercred_denied_auth_ok_false() {
    let auth = auth_with(None);
    // 对端 uid 999 != our 501 且非 root → peer_allowed false → auth_ok=false。
    let id = auth.resolve_identity(PeerUid::Resolved(999), 501);
    assert!(!id.auth_ok, "非同 uid 非 root 须 peercred 拒绝");
    assert!(!id.is_admin);
    assert!(id.tenants.is_empty());
    assert_eq!(id.uid, 999);
}

// P2-3 (audit §3.4): 系统调用失败 (SyscallFail) vs 跨 UID 拒绝 (Resolved other) 同 fail-closed 拒,
// 但日志须分明 (区分「运维须诊断」与「跨 UID 攻击/误连」)。此测验证决策一致性 + uid 兜底。
#[test]
fn p23_resolve_identity_syscall_fail_distinct_from_cross_uid() {
    let auth = auth_with(None);
    // SyscallFail: 无凭证 → fail-closed 拒; resolved() = None → uid 兜底 u32::MAX。
    let id_fail = auth.resolve_identity(PeerUid::SyscallFail, 501);
    assert!(
        !id_fail.auth_ok,
        "SyscallFail 须 auth_ok=false (fail-closed)"
    );
    assert_eq!(
        id_fail.uid,
        u32::MAX,
        "SyscallFail 无 resolved uid → 兜底 u32::MAX"
    );
    assert!(id_fail.tenants.is_empty());

    // Unsupported 同理 fail-closed。
    let id_unsup = auth.resolve_identity(PeerUid::Unsupported, 501);
    assert!(!id_unsup.auth_ok, "Unsupported 须 auth_ok=false");

    // 跨 UID (Resolved other) 同拒但 uid = 真实对端 uid (999, 非 u32::MAX) —— 与 SyscallFail 区分。
    let id_cross = auth.resolve_identity(PeerUid::Resolved(999), 501);
    assert!(!id_cross.auth_ok);
    assert_eq!(
        id_cross.uid, 999,
        "跨 UID 拒绝保留真实对端 uid (非 u32::MAX 兜底)"
    );

    // 两类同拒 (auth_ok 一致), 但 uid 字段区分: SyscallFail=u32::MAX, cross-UID=999。
    assert_ne!(
        id_fail.uid, id_cross.uid,
        "SyscallFail 与跨 UID 须 uid 可区分 (P2-3 §3.4)"
    );
}

// --- authorize_method ---

#[test]
fn authorize_ping_open_to_all_even_denied_peer() {
    let auth = auth_with(None);
    // peercred 拒绝身份, 但 ping 是健康探针对任意对端开放 → 仍 Allow。
    let id = CallerIdentity {
        uid: 999,
        auth_ok: false,
        is_admin: false,
        tenants: Vec::new(),
    };
    let dec = auth.authorize_method(&id, "guard.ping", None);
    assert_eq!(dec, AuthDecision::Allow, "ping 须对拒绝的对端也放行");
}

#[test]
fn authorize_non_ping_denied_peer_deny_peercred() {
    let auth = auth_with(None);
    let id = CallerIdentity {
        uid: 999,
        auth_ok: false,
        is_admin: false,
        tenants: Vec::new(),
    };
    let dec = auth.authorize_method(&id, "guard.evaluate", None);
    assert_eq!(
        dec,
        AuthDecision::DenyPeercred,
        "非 ping + auth_ok=false 须 DenyPeercred"
    );
}

#[test]
fn authorize_non_ping_dev_no_secret_allow() {
    let auth = auth_with(None);
    let id = CallerIdentity {
        uid: 1000,
        auth_ok: true,
        is_admin: false,
        tenants: vec!["t1".to_string()],
    };
    // secret 未设 (dev) → 跳过 secret 校验 → Allow。
    let dec = auth.authorize_method(&id, "guard.evaluate", None);
    assert_eq!(dec, AuthDecision::Allow, "dev 模式无 secret 须放行");
}

#[test]
fn authorize_non_ping_secret_mismatch_deny_secret() {
    let auth = auth_with(Some("correct-secret"));
    let id = CallerIdentity {
        uid: 1000,
        auth_ok: true,
        is_admin: false,
        tenants: vec!["t1".to_string()],
    };
    let dec = auth.authorize_method(&id, "guard.evaluate", Some("wrong-secret"));
    assert_eq!(
        dec,
        AuthDecision::DenySecret,
        "secret 错须 DenySecret (非 DenyPeercred)"
    );
}

#[test]
fn authorize_non_ping_secret_match_allow() {
    let auth = auth_with(Some("correct-secret"));
    let id = CallerIdentity {
        uid: 1000,
        auth_ok: true,
        is_admin: false,
        tenants: vec!["t1".to_string()],
    };
    let dec = auth.authorize_method(&id, "guard.evaluate", Some("correct-secret"));
    assert_eq!(dec, AuthDecision::Allow);
}

#[test]
fn authorize_non_ping_secret_missing_when_required_deny_secret() {
    let auth = auth_with(Some("correct-secret"));
    let id = CallerIdentity {
        uid: 1000,
        auth_ok: true,
        is_admin: false,
        tenants: vec!["t1".to_string()],
    };
    // 设了 secret 但请求没带 → DenySecret (非 dev 跳过)。
    let dec = auth.authorize_method(&id, "guard.evaluate", None);
    assert_eq!(
        dec,
        AuthDecision::DenySecret,
        "secret 已设但请求未带须 DenySecret"
    );
}

// --- deny_resp 映射 wire 错误码 ---

#[test]
fn deny_resp_emits_32001_error_bytes() {
    let id = serde_json::Value::from(42);
    let peer = AuthDecision::DenyPeercred
        .deny_resp(&id)
        .expect("Deny 须产响应");
    let peer_str = String::from_utf8_lossy(&peer);
    assert!(
        peer_str.contains(r#""code":-32001"#),
        "DenyPeercred 须 -32001, got: {peer_str}"
    );
    assert!(peer_str.contains(r#""id":42"#));

    let secret = AuthDecision::DenySecret
        .deny_resp(&serde_json::Value::from(7))
        .expect("Deny 须产响应");
    let secret_str = String::from_utf8_lossy(&secret);
    assert!(
        secret_str.contains(r#""code":-32001"#),
        "DenySecret 须 -32001, got: {secret_str}"
    );

    assert!(
        AuthDecision::Allow.deny_resp(&id).is_none(),
        "Allow 须无响应"
    );
}
