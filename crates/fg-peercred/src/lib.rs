// fg-peercred — UDS peer credential (E6: getpeereid/SO_PEERCRED → peer uid)
//
// fusion-guard 是 per-host 守护进程 (PRD: 单机, 非多租户网络服务)。E6 要求校验
// 连接方为本机进程 (同 uid 或 root)。唯一需要 unsafe 的操作: getsockopt/getpeereid 取对端凭证。
// 镜像 fg-tcc-bridge/fg-es-bridge 范式: 本 crate 是 unsafe_code=allow 的桥, 仅封装 FFI。
//
// macOS: getpeereid (fd, &uid, &gid) → 对端真实 uid。LOCAL_PEERCRED 在 Darwin 25
//   (macOS 26) 实测内核回 len=4 cr_uid=0 (不再填 xucred), 故弃用改 getpeereid (稳定可移植)。
// Linux: SO_PEERCRED (17) → struct ucred { uid }
// 其他平台: 返回 None (调用方决定拒绝或放行)。

/// 守护进程自身 uid (getsockopt 对端比对基准)。
pub fn our_uid() -> u32 {
    unsafe { libc::getuid() }
}

// P2-3 (audit §3.4): 对端 uid 解析三态。旧 Option<u32> 把「系统调用失败」(SyscallFail)
// 与「跨 UID 拒绝」(Resolved(other_uid)) 混为同一 None 路径, prod info 级不可见,
// 瞬态 getpeereid/getsockopt 失败 (fd 失效/EBADF/ECONNRESET) 被静默当 auth reject。
// 分离三态: Resolved(uid) 真实取到; SyscallFail 系统调用失败 (warn 级, 须运维诊断);
// Unsupported 平台无 peercred (warn 级)。调用方据此分别日志, 不可混淆。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerUid {
    Resolved(u32),
    SyscallFail,
    Unsupported,
}

impl PeerUid {
    // 取已解析的 uid (仅 Resolved 返 Some, SyscallFail/Unsupported 返 None)。
    pub fn resolved(self) -> Option<u32> {
        match self {
            PeerUid::Resolved(uid) => Some(uid),
            _ => None,
        }
    }

    // 是否为系统调用失败 (区分日志级别用)。
    pub fn is_syscall_fail(self) -> bool {
        matches!(self, PeerUid::SyscallFail)
    }
}

/// 取 UDS 连接对端的真实 uid。失败 → SyscallFail (warn 级), 不支持 → Unsupported。
pub fn peer_uid(fd: std::os::fd::RawFd) -> PeerUid {
    #[cfg(target_os = "macos")]
    {
        // macOS: LOCAL_PEERCRED 在 Darwin 25 (macOS 26) 回 len=4 cr_uid=0 (内核不再填 xucred,
        // 实测 C 直调同结果)。改用 getpeereid(fd, &uid, &gid) — 返回对端真实 uid/gid,
        // 实测 uid=501 正确。可移植 (macOS/FreeBSD), 跨内核版本稳定。
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
        if rc != 0 {
            // P2-3 (§3.4): 瞬态失败升 warn —— fd 失效/EBADF/ECONNRESET 在 prod info 级须可见,
            // 不可当普通 auth reject 静默 (旧 debug 级 = ghost unauthorized undiagnosable)。
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
            // P2-3 (§3.4): SO_PEERCRED 瞬态失败升 warn。
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

/// 校验对端 uid 是否允许 (E6: 同 uid 或 root)。
/// allow_root=true 时 uid 0 放行 (守护进程自身/特权进程)。
/// P2-3: SyscallFail/Unsupported 恒拒 (无凭证 = 不可信, fail-closed)。
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
