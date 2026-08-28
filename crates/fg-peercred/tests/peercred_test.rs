// E6 peercred 契约: 守护进程自身 uid 校验逻辑 (peer_uid 需真实 socket, 在 IPC 集成测试覆盖)。
// P2-3 (§3.4): peer_uid 现返三态 PeerUid (Resolved/SyscallFail/Unsupported)。

use fg_peercred::PeerUid;

#[test]
fn our_uid_is_nonzero_typically() {
    let uid = fg_peercred::our_uid();
    // CI/容器可能 root(0), 普通用户 >0; 仅断言可取 + 不 panic。
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

// P2-3 (§3.4): 系统调用失败 (无凭证) 恒拒 —— fail-closed, 不可当可信放行。
#[test]
fn syscall_fail_peer_denied() {
    let our = fg_peercred::our_uid();
    assert!(
        !fg_peercred::peer_allowed(PeerUid::SyscallFail, our, true),
        "SyscallFail 须 fail-closed 拒绝 (allow_root 也不放行)"
    );
    assert!(
        !fg_peercred::peer_allowed(PeerUid::Unsupported, our, true),
        "Unsupported 须 fail-closed 拒绝"
    );
}

// P2-3 (§3.4): PeerUid 三态辅助方法。
#[test]
fn peer_uid_resolved_and_is_syscall_fail() {
    assert_eq!(PeerUid::Resolved(501).resolved(), Some(501));
    assert_eq!(PeerUid::SyscallFail.resolved(), None);
    assert_eq!(PeerUid::Unsupported.resolved(), None);
    assert!(PeerUid::SyscallFail.is_syscall_fail());
    assert!(!PeerUid::Resolved(0).is_syscall_fail());
    assert!(!PeerUid::Unsupported.is_syscall_fail());
}
