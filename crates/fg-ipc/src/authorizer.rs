// P1-5 (audit §3.1): IpcServer 单体拆 trait —— Authorizer 层。
// 旧码 peercred→身份解析 (handle_conn) 与 共享 secret 校验 (dispatch_arc) 散在 I/O 路径,
// 无独立单测, 只能起真实 socket 跑集成测试才覆盖。抽 Authorizer trait + PeerAuthorizer 默认实现,
// 把鉴权纯逻辑 (无 I/O) 剥离 → 单测直接喂 uid/secret 断言决策, 不需套接字。
//
// 范围裁剪 (规则 2/7): audit 列 4 trait (Transport/Authorizer/Dispatcher/Policy)。仅 Authorizer 落 trait —
// 它是唯一含「未被测纯逻辑 + 不需复刻 engine 接口」的层。Transport 是 I/O 包壳 (trait 化只增抽象无测试增益),
// Dispatcher 是 engine 上的薄分派 (trait 化须定义覆盖 engine 全方法的 facade, 复刻接口无收益),
// Policy (tenant/limit) 已下沉为 CallerIdentity::tenant_allowed 纯方法 + cap_limit 自由函数 (已是可测纯逻辑)。
// 一处 trait + 文档说明裁剪理由, 避免双模式 (规则 7)。

use std::sync::Arc;

use fg_peercred::{peer_allowed, PeerUid};
use fg_store::AuditStore;

use crate::{err_resp_bytes, CallerIdentity, RpcRequest, SHARED_SECRET_ENV};
use serde_json::Value;

// P1-5: 租户解析依赖最小 trait。AuditStore 实现它 (tenants_for_uid); 测试用 FakeLookup。
// 不直接依赖 AuditStore → 单测无需真实 DB + Keychain key。
pub trait TenantLookup: Send + Sync {
    fn tenants_for_uid(&self, uid: u32) -> Vec<String>;
}

// AuditStore 满足 TenantLookup (tenants_for_uid 已存在, fg-store::lib pub)。
impl TenantLookup for AuditStore {
    fn tenants_for_uid(&self, uid: u32) -> Vec<String> {
        AuditStore::tenants_for_uid(self, uid)
    }
}

// P1-5: 鉴权决策。Allow / DenyPeercred (E6 非 ping 同 uid) / DenySecret (§12.1 共享 secret)。
// 三 Deny 均映射 -32001, 但区分原因便于审计 + 单测断言。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthDecision {
    Allow,
    DenyPeercred,
    DenySecret,
}

impl AuthDecision {
    // 决策 → wire 错误响应字节 (Deny 路径)。Allow 调用方继续业务, 不走此。
    pub fn deny_resp(&self, id: &Value) -> Option<Vec<u8>> {
        match self {
            AuthDecision::Allow => None,
            AuthDecision::DenyPeercred => {
                tracing::warn!(decision = "DenyPeercred", "auth denied (E6 non-peer)");
                Some(err_resp_bytes(
                    id.clone(),
                    -32001,
                    "unauthorized: peercred denied",
                ))
            }
            AuthDecision::DenySecret => {
                tracing::warn!(
                    decision = "DenySecret",
                    "auth denied (shared secret, §12.1)"
                );
                Some(err_resp_bytes(
                    id.clone(),
                    -32001,
                    "unauthorized: secret denied",
                ))
            }
        }
    }
}

// P1-5: Authorizer trait —— 身份解析 + 方法级鉴权, 纯逻辑无 I/O。
// resolve_identity: peercred uid → CallerIdentity (含授权租户集)。
// authorize_method: identity + 方法名 + 请求所带 secret → 决策 (ping 对任意对端开放; 非 ping 须同 uid + secret)。
pub trait Authorizer: Send + Sync {
    fn resolve_identity(&self, peer_uid: PeerUid, our_uid: u32) -> CallerIdentity;

    fn authorize_method(
        &self,
        identity: &CallerIdentity,
        method: &str,
        provided_secret: Option<&str>,
    ) -> AuthDecision;
}

// P1-5: 默认实现。持 Arc<AuditStore> (租户解析) + Option<shared_secret> (§12.1)。
// secret 来源: SHARED_SECRET_ENV env (prod 部署设); None = dev 模式跳过 secret 校验。
pub struct PeerAuthorizer {
    tenants: Arc<dyn TenantLookup>,
    shared_secret: Option<String>,
}

impl PeerAuthorizer {
    pub fn new(audit: Arc<AuditStore>) -> Self {
        let shared_secret = std::env::var(SHARED_SECRET_ENV)
            .ok()
            .filter(|s| !s.is_empty());
        if shared_secret.is_some() {
            tracing::info!("PeerAuthorizer: shared secret loaded from env (P0-1 §12.1)");
        } else {
            tracing::warn!(
                env = SHARED_SECRET_ENV,
                "PeerAuthorizer: shared secret NOT set — dev mode, secret check skipped (P0-1 §12.1: prod MUST set)"
            );
        }
        Self {
            tenants: audit,
            shared_secret,
        }
    }

    // test-helpers: 注入自定义租户表 + secret, 单测构造无需 AuditStore/env。
    #[cfg(feature = "test-helpers")]
    pub fn new_with_lookup(tenants: Arc<dyn TenantLookup>, shared_secret: Option<String>) -> Self {
        Self {
            tenants,
            shared_secret,
        }
    }
}

impl Authorizer for PeerAuthorizer {
    // 对应旧 handle_conn 身份解析 (E6 + P0-1)。
    // P2-3 (§3.4): peer_uid 现三态 PeerUid —— 区分「系统调用失败」与「跨 UID 拒绝」两类日志。
    fn resolve_identity(&self, peer_uid: PeerUid, our_uid: u32) -> CallerIdentity {
        let auth_ok = peer_allowed(peer_uid, our_uid, true);
        if auth_ok {
            let uid = peer_uid.resolved().unwrap_or(our_uid);
            let is_admin = uid == 0;
            let tenants = if is_admin {
                Vec::new()
            } else {
                self.tenants.tenants_for_uid(uid)
            };
            tracing::debug!(
                peer_uid = uid,
                is_admin = is_admin,
                tenant_count = tenants.len(),
                "peercred verified + identity resolved (P0-1)"
            );
            CallerIdentity {
                uid,
                auth_ok: true,
                is_admin,
                tenants,
            }
        } else {
            // P2-3 (§3.4): 区分两类拒绝原因。SyscallFail = 系统调用失败 (非对端过错, 须运维诊断);
            // Resolved(other_uid) = 跨 UID 攻击/误连。两类同 fail-closed 拒, 但日志分明。
            let uid = peer_uid.resolved().unwrap_or(u32::MAX);
            if peer_uid.is_syscall_fail() {
                tracing::warn!(
                    our_uid = our_uid,
                    "peercred DENIED — peer credential syscall failed (P2-3 §3.4); \
                     fail-closed (only guard.ping allowed)"
                );
            } else {
                tracing::warn!(
                    peer_uid = ?peer_uid,
                    our_uid = our_uid,
                    "peercred DENIED — non-peer connection (E6 cross-UID); only guard.ping allowed"
                );
            }
            CallerIdentity {
                uid,
                auth_ok: false,
                is_admin: false,
                tenants: Vec::new(),
            }
        }
    }

    // 对应旧 dispatch_arc 的 E6 闸门 + §12.1 secret 校验。ping 对任意对端开放 (健康探针)。
    fn authorize_method(
        &self,
        identity: &CallerIdentity,
        method: &str,
        provided_secret: Option<&str>,
    ) -> AuthDecision {
        // E6: 非 ping 须同 uid / root。
        if !identity.auth_ok && method != "guard.ping" {
            return AuthDecision::DenyPeercred;
        }
        // §12.1: 非 ping 校验共享 secret (常量时间)。secret 未设 (dev) 跳过。
        if method != "guard.ping" {
            if let Some(expected) = self.shared_secret.as_ref() {
                match provided_secret {
                    Some(p) if constant_time_eq(p.as_bytes(), expected.as_bytes()) => {}
                    _ => return AuthDecision::DenySecret,
                }
            }
        }
        AuthDecision::Allow
    }
}

// P1-5: 从 RpcRequest 抽 secret 参数 (旧码内联 s_param(params, "secret", 99))。
pub fn extract_secret(req: &RpcRequest) -> Option<&str> {
    req.params.get("secret").and_then(|v| v.as_str())
}

// 常量时间字节比对 (防时序侧信道泄漏 secret 长度/前缀差)。长度不等也走完 (不提前 return)。
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut acc: u8 = (a.len() ^ b.len()) as u8;
    let max = a.len().max(b.len());
    for i in 0..max {
        let av = if i < a.len() { a[i] } else { 0 };
        let bv = if i < b.len() { b[i] } else { 0 };
        acc |= av ^ bv;
    }
    acc == 0
}
