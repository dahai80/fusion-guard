// E6 peercred contract: the daemon's own uid checking logic (peer_uid needs a real socket; it is
// covered by the IPC integration tests).
// P2-3 (§3.4): peer_uid now returns the three-state PeerUid (Resolved/SyscallFail/Unsupported).

use fg_peercred::PeerUid;

#[test]
fn our_uid_is_nonzero_typically() {
    let uid = fg_peercred::our_uid();
    // CI/containers may run as root(0), normal users are >0; only assert it is obtainable and
    // does not panic.
    let _ = uid;
}

#[test]
fn same_uid_allowed() {
    let our = fg_peercred::our_uid();
    assert!(fg_peercred::peer_allowed(PeerUid::Resolved(our), our, true));
    assert!(fg_peercred::peer_allowed(
        PeerUid::Resolved(our),
        our,
        false
    ));
}

#[test]
fn different_uid_denied() {
    let our = fg_peercred::our_uid();
    let other = if our == 501 { 502 } else { 501 };
    assert!(!fg_peercred::peer_allowed(
        PeerUid::Resolved(other),
        our,
        false
    ));
}

#[test]
fn root_allowed_when_flag_set() {
    let our = fg_peercred::our_uid();
    assert!(fg_peercred::peer_allowed(PeerUid::Resolved(0), our, true));
    if our != 0 {
        assert!(!fg_peercred::peer_allowed(PeerUid::Resolved(0), our, false));
    }
}

// P2-3 (§3.4): syscall failure (no credential) always rejects — fail-closed, never treated as
// trusted and allowed through.
#[test]
fn syscall_fail_peer_denied() {
    let our = fg_peercred::our_uid();
    assert!(
        !fg_peercred::peer_allowed(PeerUid::SyscallFail, our, true),
        "SyscallFail must be rejected fail-closed (allow_root does not let it through either)"
    );
    assert!(
        !fg_peercred::peer_allowed(PeerUid::Unsupported, our, true),
        "Unsupported must be rejected fail-closed"
    );
}

// P2-3 (§3.4): PeerUid three-state helper methods.
#[test]
fn peer_uid_resolved_and_is_syscall_fail() {
    assert_eq!(PeerUid::Resolved(501).resolved(), Some(501));
    assert_eq!(PeerUid::SyscallFail.resolved(), None);
    assert_eq!(PeerUid::Unsupported.resolved(), None);
    assert!(PeerUid::SyscallFail.is_syscall_fail());
    assert!(!PeerUid::Resolved(0).is_syscall_fail());
    assert!(!PeerUid::Unsupported.is_syscall_fail());
}
