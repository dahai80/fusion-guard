// P1-5 (audit §3.1): Authorizer trait unit tests — pure authorization logic
// independent of I/O.
// The old code scattered peercred->identity (handle_conn) and secret validation
// (dispatch_arc) across the socket path, so coverage required real-socket
// integration tests. After extracting the trait, unit tests feed uid/secret
// directly and assert decisions, no socket/DB needed.
//
// Coverage:
//   resolve_identity — admin (uid 0, empty tenant set + is_admin),
//                      non-admin (tenants via FakeLookup),
//                      peercred denial (auth_ok=false).
//   authorize_method — ping is open to any peer (Allow even when auth_ok=false),
//                      non-ping + auth_ok=false -> DenyPeercred,
//                      non-ping + auth_ok + secret unset (dev) -> Allow,
//                      non-ping + auth_ok + wrong secret -> DenySecret,
//                      non-ping + auth_ok + correct secret -> Allow.
// Uses new_with_lookup (test-helpers) to inject FakeLookup; no
// AuditStore/Keychain/env dependency.

use std::sync::Arc;

use fg_ipc::{AuthDecision, Authorizer, CallerIdentity, PeerAuthorizer, PeerUid, TenantLookup};

// Fake tenant table: uid 1000 -> ["t1","t2"], empty otherwise.
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
    // Peer uid 0 = root; allow_root -> auth_ok, is_admin, empty tenants (root is
    // fully privileged, no table lookup).
    let id = auth.resolve_identity(PeerUid::Resolved(0), 501);
    assert!(id.auth_ok);
    assert!(id.is_admin);
    assert!(
        id.tenants.is_empty(),
        "admin tenants must be empty (root is fully privileged, no table lookup)"
    );
    assert_eq!(id.uid, 0);
}

#[test]
fn resolve_identity_same_uid_non_admin_loads_tenants() {
    let auth = auth_with(None);
    // Peer uid == our_uid -> peer_allowed -> auth_ok; non-admin -> FakeLookup queried.
    let id = auth.resolve_identity(PeerUid::Resolved(1000), 1000);
    assert!(id.auth_ok);
    assert!(!id.is_admin);
    assert_eq!(id.tenants, vec!["t1".to_string(), "t2".to_string()]);
    assert_eq!(id.uid, 1000);
}

#[test]
fn resolve_identity_peercred_denied_auth_ok_false() {
    let auth = auth_with(None);
    // Peer uid 999 != our 501 and not root -> peer_allowed false -> auth_ok=false.
    let id = auth.resolve_identity(PeerUid::Resolved(999), 501);
    assert!(
        !id.auth_ok,
        "a non-matching non-root uid must be denied by peercred"
    );
    assert!(!id.is_admin);
    assert!(id.tenants.is_empty());
    assert_eq!(id.uid, 999);
}

// P2-3 (audit §3.4): a syscall failure (SyscallFail) vs a cross-UID denial
// (Resolved other) are both fail-closed denials, but the logs must clearly
// distinguish them ("operator must diagnose" vs "cross-UID attack/misconnection").
// This test verifies decision consistency + the uid fallback.
#[test]
fn p23_resolve_identity_syscall_fail_distinct_from_cross_uid() {
    let auth = auth_with(None);
    // SyscallFail: no credentials -> fail-closed denial; resolved() = None -> uid
    // falls back to u32::MAX.
    let id_fail = auth.resolve_identity(PeerUid::SyscallFail, 501);
    assert!(
        !id_fail.auth_ok,
        "SyscallFail must have auth_ok=false (fail-closed)"
    );
    assert_eq!(
        id_fail.uid,
        u32::MAX,
        "SyscallFail has no resolved uid -> falls back to u32::MAX"
    );
    assert!(id_fail.tenants.is_empty());

    // Unsupported is likewise fail-closed.
    let id_unsup = auth.resolve_identity(PeerUid::Unsupported, 501);
    assert!(!id_unsup.auth_ok, "Unsupported must have auth_ok=false");

    // Cross-UID (Resolved other) is denied the same way but keeps uid = the real
    // peer uid (999, not u32::MAX) — distinguishing it from SyscallFail.
    let id_cross = auth.resolve_identity(PeerUid::Resolved(999), 501);
    assert!(!id_cross.auth_ok);
    assert_eq!(
        id_cross.uid, 999,
        "cross-UID denial preserves the real peer uid (not the u32::MAX fallback)"
    );

    // Both are denied (auth_ok agrees), but the uid field distinguishes them:
    // SyscallFail=u32::MAX, cross-UID=999.
    assert_ne!(
        id_fail.uid, id_cross.uid,
        "SyscallFail and cross-UID must be distinguishable by uid (P2-3 §3.4)"
    );
}

// --- authorize_method ---

#[test]
fn authorize_ping_open_to_all_even_denied_peer() {
    let auth = auth_with(None);
    // The identity is denied by peercred, but ping is a health probe open to any
    // peer -> still Allow.
    let id = CallerIdentity {
        uid: 999,
        auth_ok: false,
        is_admin: false,
        tenants: Vec::new(),
    };
    let dec = auth.authorize_method(&id, "guard.ping", None);
    assert_eq!(
        dec,
        AuthDecision::Allow,
        "ping must be allowed even for a denied peer"
    );
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
        "non-ping + auth_ok=false must be DenyPeercred"
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
    // Secret unset (dev) -> skip secret validation -> Allow.
    let dec = auth.authorize_method(&id, "guard.evaluate", None);
    assert_eq!(
        dec,
        AuthDecision::Allow,
        "dev mode without a secret must allow"
    );
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
        "a wrong secret must be DenySecret (not DenyPeercred)"
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
    // Secret set but the request carries none -> DenySecret (no dev skip).
    let dec = auth.authorize_method(&id, "guard.evaluate", None);
    assert_eq!(
        dec,
        AuthDecision::DenySecret,
        "secret set but missing from the request must be DenySecret"
    );
}

// --- deny_resp maps to wire error codes ---

#[test]
fn deny_resp_emits_32001_error_bytes() {
    let id = serde_json::Value::from(42);
    let peer = AuthDecision::DenyPeercred
        .deny_resp(&id)
        .expect("Deny must produce a response");
    let peer_str = String::from_utf8_lossy(&peer);
    assert!(
        peer_str.contains(r#""code":-32001"#),
        "DenyPeercred must be -32001, got: {peer_str}"
    );
    assert!(peer_str.contains(r#""id":42"#));

    let secret = AuthDecision::DenySecret
        .deny_resp(&serde_json::Value::from(7))
        .expect("Deny must produce a response");
    let secret_str = String::from_utf8_lossy(&secret);
    assert!(
        secret_str.contains(r#""code":-32001"#),
        "DenySecret must be -32001, got: {secret_str}"
    );

    assert!(
        AuthDecision::Allow.deny_resp(&id).is_none(),
        "Allow must produce no response"
    );
}
