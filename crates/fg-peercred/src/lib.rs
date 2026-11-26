// fg-peercred — UDS peer credential (E6: getpeereid/SO_PEERCRED → peer uid)
//
// fusion-guard is a per-host daemon (PRD: single machine, not a multi-tenant network service).
// E6 requires verifying that the connecting party is a local process (same uid or root). The only
// operation needing unsafe: getsockopt/getpeereid to fetch peer credentials.
// Mirrors the fg-tcc-bridge/fg-es-bridge pattern: this crate is the unsafe_code=allow bridge,
// wrapping only the FFI.
//
// macOS: getpeereid (fd, &uid, &gid) → the peer's real uid. LOCAL_PEERCRED on Darwin 25
//   (macOS 26) was measured returning len=4 cr_uid=0 from the kernel (xucred no longer filled),
//   so it was dropped in favor of getpeereid (stable and portable).
// Linux: SO_PEERCRED (17) → struct ucred { uid }
// Other platforms: returns None (the caller decides to reject or allow).

/// The daemon's own uid (baseline for getsockopt peer comparison).
pub fn our_uid() -> u32 {
    unsafe { libc::getuid() }
}

// P2-3 (audit §3.4): three-state peer uid resolution. The old Option<u32> conflated "syscall
// failure" (SyscallFail) with "cross-UID rejection" (Resolved(other_uid)) into the same None path,
// invisible at prod info level; transient getpeereid/getsockopt failures (stale fd/EBADF/
// ECONNRESET) were silently treated as auth rejects.
// Three separated states: Resolved(uid) genuinely obtained; SyscallFail syscall failure (warn
// level, needs ops diagnosis); Unsupported platform has no peercred (warn level). Callers log
// each distinctly and must not conflate them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerUid {
    Resolved(u32),
    SyscallFail,
    Unsupported,
}

impl PeerUid {
    // Take the resolved uid (only Resolved returns Some; SyscallFail/Unsupported return None).
    pub fn resolved(self) -> Option<u32> {
        match self {
            PeerUid::Resolved(uid) => Some(uid),
            _ => None,
        }
    }

    // Whether this is a syscall failure (for log-level distinction).
    pub fn is_syscall_fail(self) -> bool {
        matches!(self, PeerUid::SyscallFail)
    }
}

/// Take the real uid of the UDS connection peer. Failure → SyscallFail (warn level), unsupported
/// platform → Unsupported.
pub fn peer_uid(fd: std::os::fd::RawFd) -> PeerUid {
    #[cfg(target_os = "macos")]
    {
        // macOS: LOCAL_PEERCRED on Darwin 25 (macOS 26) returns len=4 cr_uid=0 (the kernel no
        // longer fills xucred; a direct C call gave the same result in testing). Switched to
        // getpeereid(fd, &uid, &gid) — returns the peer's real uid/gid, measured uid=501 correct.
        // Portable (macOS/FreeBSD), stable across kernel versions.
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
        if rc != 0 {
            // P2-3 (§3.4): transient failures escalate to warn — stale fd/EBADF/ECONNRESET must be
            // visible at prod info level, not silently treated as an ordinary auth reject (the old
            // debug level = ghost unauthorized, undiagnosable).
            tracing::warn!(
                error = std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
                "getpeereid failed — peer credential unavailable (P2-3 §3.4)"
            );
            return PeerUid::SyscallFail;
        }
        tracing::debug!(peer_uid = uid, peer_gid = gid, "getpeereid resolved");
        PeerUid::Resolved(uid)
    }
    #[cfg(target_os = "linux")]
    {
        use libc::{c_void, getsockopt, socklen_t, SOL_SOCKET, SO_PEERCRED};
        #[repr(C)]
        struct Ucred {
            pid: i32,
            uid: u32,
            gid: u32,
        }
        let mut cred = Ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len: socklen_t = std::mem::size_of::<Ucred>() as socklen_t;
        let rc = unsafe {
            getsockopt(
                fd,
                SOL_SOCKET,
                SO_PEERCRED,
                &mut cred as *mut Ucred as *mut c_void,
                &mut len,
            )
        };
        if rc != 0 {
            // P2-3 (§3.4): SO_PEERCRED transient failures escalate to warn.
            tracing::warn!(
                error = std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
                "SO_PEERCRED getsockopt failed — peer credential unavailable (P2-3 §3.4)"
            );
            return PeerUid::SyscallFail;
        }
        tracing::debug!(peer_uid = cred.uid, "SO_PEERCRED resolved");
        PeerUid::Resolved(cred.uid)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = fd;
        tracing::warn!("peercred unsupported on this platform (P2-3 §3.4)");
        PeerUid::Unsupported
    }
}

/// Check whether the peer uid is allowed (E6: same uid or root).
/// With allow_root=true, uid 0 is allowed through (the daemon itself / privileged processes).
/// P2-3: SyscallFail/Unsupported always reject (no credential = untrusted, fail-closed).
pub fn peer_allowed(peer_uid: PeerUid, our_uid: u32, allow_root: bool) -> bool {
    match peer_uid {
        PeerUid::Resolved(uid) => {
            if allow_root && uid == 0 {
                return true;
            }
            uid == our_uid
        }
        PeerUid::SyscallFail | PeerUid::Unsupported => false,
    }
}
