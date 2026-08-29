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
// H-C secret 侧修复 (product-audit §5): shared secret Keychain 来源 (与 token-key 同根缺陷:
// 原仅 env = 同 UID 可读 = 被攻陷 subagent 可读)。prod 来源改 macOS Keychain (service fusion-guard,
// account shared-secret)。env 为 escape hatch (须显式 flag 放行)。fg-store::secret_store 提供辅助。
// release-only 辅助 (Keychain I/O + 决策) 在 debug 构建未用 → allow(unused_imports)。
#[allow(unused_imports)]
use fg_store::secret_store::{
    allow_insecure_secret_flag_set, generate_shared_secret, keychain_secret_get,
    keychain_secret_store, resolve_shared_secret, shared_secret_env_present, SharedSecretSource,
};

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
// secret 来源 (H-C secret 侧修复): macOS Keychain (account shared-secret, prod 推荐) 优先;
// env 为 escape hatch (release 须 FUSION_GUARD_ALLOW_INSECURE_SECRET=1 显式放行, warn 告警)。
// None = dev 模式跳过 secret 校验 (release 启动由 require_shared_secret_for_release 拒)。
pub struct PeerAuthorizer {
    tenants: Arc<dyn TenantLookup>,
    shared_secret: Option<String>,
}

// H-C secret 侧: 解析 shared secret 来源 → 实际加载 (Keychain I/O)。返回 (secret, source)。
// 解析序: Keychain (macOS) → env (escape hatch) → none。
// - Keychain 有 → 用 Keychain (prod 路径, 密钥不入环境变量)。
// - Keychain 无 + env 有且放行 (debug 或 FUSION_GUARD_ALLOW_INSECURE_SECRET=1) → 用 env。
// - Keychain 无 + env 有但 release 未放行 → 不静默用 env (防漏 flag 降级), 视为无 secret。
// - 两处皆无 → None (release 启动拒, dev 跳过校验)。
//
// 首次启动 Keychain 无 secret + env 也无 + macos → 生成强随机 secret 存 Keychain (allow_mint)。
// 注意: 生成仅当 env 亦缺失 (env 显式提供 = operator 自管, 不覆盖); release 生成是 prod 默认
// (operator 也可预置 security add-generic-password 走纯 Keychain 不生成)。
#[allow(clippy::needless_return)]
pub fn load_shared_secret() -> (Option<String>, SharedSecretSource) {
    let env_present = shared_secret_env_present();
    // FUSION_GUARD_ALLOW_NO_SECRET=1: 应急/CI 放行 = peercred-only 鉴权, 跳过 secret 校验
    // (与 require_shared_secret_for_release 的放行语义一致: 非 prod, 运维知情)。
    // soak/CI spawn release daemon 设此 flag → 客户端不携 secret 仍通 (旧 env-only 行为)。
    // 否则 release 无 env → Keychain 路径会自动生成 secret → 客户端无 secret 全 DenySecret。
    let allow_no_secret = std::env::var("FUSION_GUARD_ALLOW_NO_SECRET")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if allow_no_secret && !env_present {
        tracing::warn!(
            "PeerAuthorizer: shared secret check SKIPPED (FUSION_GUARD_ALLOW_NO_SECRET=1) — \
             peercred-only auth, INSECURE (CI/soak/emergency posture; prod MUST provision Keychain)"
        );
        return (None, SharedSecretSource::None);
    }
    // dev 构建: 仅走 env (旧行为), 不触 Keychain —— 避免并发测试 spawn server 全调
    // get_generic_password 在非交互环境串行阻塞 (CLAUDE.md 已记录 Keychain 挂起风险)。
    // dev 无 env secret → None (跳过 secret 校验, 测试客户端不携 secret 仍通), 保向后兼容。
    // release 构建: 走 Keychain (prod 路径), gate 兜底拒启动。
    #[cfg(debug_assertions)]
    {
        if env_present {
            let s = std::env::var(SHARED_SECRET_ENV)
                .ok()
                .filter(|v| !v.is_empty());
            tracing::info!(
                "PeerAuthorizer: shared secret loaded from env (debug build, dev posture)"
            );
            return (s, SharedSecretSource::EnvDebug);
        }
        tracing::warn!(
            "PeerAuthorizer: shared secret NOT set — dev mode, secret check skipped \
             (H-C: prod MUST provision Keychain; release start will refuse)"
        );
        return (None, SharedSecretSource::None);
    }
    #[cfg(not(debug_assertions))]
    {
        let decision = resolve_shared_secret(false, allow_insecure_secret_flag_set(), env_present);
        match decision {
            SharedSecretSource::Keychain => {
                match keychain_secret_get() {
                    Ok(Some(s)) => {
                        tracing::info!(
                            "PeerAuthorizer: shared secret loaded from Keychain (H-C prod path)"
                        );
                        return (Some(s), SharedSecretSource::Keychain);
                    }
                    Ok(None) => {
                        // Keychain 无 secret。env 提供但未放行 (release 漏 flag) 落此 —— 不静默用 env。
                        if env_present {
                            tracing::warn!(
                            env = SHARED_SECRET_ENV,
                            "PeerAuthorizer: shared secret env present but NOT authorized in release \
                             (set FUSION_GUARD_ALLOW_INSECURE_SECRET=1 or --insecure-secret-env to use env, \
                             or provision Keychain); falling back — secret check skipped"
                        );
                            return (None, SharedSecretSource::None);
                        }
                        // env 无 + Keychain 无: release 首次启动 macOS 生成存 Keychain (allow_mint)。
                        // dev 构建不自动生成 (保向后兼容: 现有测试客户端不携 secret, dev 无 secret=跳过校验;
                        // dev 若生成则非 ping 请求全 DenySecret 致测试断)。
                        #[cfg(all(target_os = "macos", not(debug_assertions)))]
                        {
                            let new_secret = generate_shared_secret();
                            match keychain_secret_store(&new_secret) {
                                Ok(()) => {
                                    tracing::info!(
                                    "PeerAuthorizer: shared secret generated + stored to Keychain \
                                     (first start, H-C prod path) — operator may replace via \
                                     `security add-generic-password -s fusion-guard -a shared-secret -w <secret>`"
                                );
                                    return (Some(new_secret), SharedSecretSource::Keychain);
                                }
                                Err(e) => {
                                    tracing::error!(
                                        error = %e,
                                        "PeerAuthorizer: keychain store of generated shared secret failed — \
                                         secret check skipped (release start will refuse — H-C)"
                                    );
                                    return (None, SharedSecretSource::None);
                                }
                            }
                        }
                        // dev 构建 / 非 macOS: 无 secret → dev 模式跳过校验 (release 由 gate 拒启动)。
                        #[cfg(any(not(target_os = "macos"), debug_assertions))]
                        {
                            tracing::warn!(
                            "PeerAuthorizer: no Keychain shared secret + no env — dev mode, \
                             secret check skipped (H-C: prod MUST provision Keychain; release start will refuse)"
                        );
                            return (None, SharedSecretSource::None);
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "PeerAuthorizer: keychain secret read error — falling back to no secret"
                        );
                        return (None, SharedSecretSource::None);
                    }
                }
            }
            SharedSecretSource::EnvDebug => {
                let s = std::env::var(SHARED_SECRET_ENV)
                    .ok()
                    .filter(|v| !v.is_empty());
                tracing::info!(
                    "PeerAuthorizer: shared secret loaded from env (debug build, dev posture)"
                );
                (s, SharedSecretSource::EnvDebug)
            }
            SharedSecretSource::EnvInsecure => {
                let s = std::env::var(SHARED_SECRET_ENV)
                    .ok()
                    .filter(|v| !v.is_empty());
                // P2-1 secret 侧镜像告警: prod 用 env = 第二因子进进程环境, 同 UID 进程可读。
                tracing::warn!(
                    "INSECURE (H-C secret): shared secret loaded from env in release build — \
                 visible to any same-UID process; prod MUST use Keychain \
                 (FUSION_GUARD_ALLOW_INSECURE_SECRET=1 or --insecure-secret-env was set)"
                );
                (s, SharedSecretSource::EnvInsecure)
            }
            SharedSecretSource::None => {
                // release 解析序下不可达 (resolve 无 env 总返 Keychain), 保留 exhaustive。
                tracing::warn!(
                    "PeerAuthorizer: shared secret NOT set — secret check skipped \
                 (H-C: release start will refuse via require_shared_secret_for_release)"
                );
                (None, SharedSecretSource::None)
            }
        }
    }
}

impl PeerAuthorizer {
    pub fn new(audit: Arc<AuditStore>) -> Self {
        let (shared_secret, _source) = load_shared_secret();
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

// H-C (product-audit §5): release 构建启动闸门 —— shared secret 两来源 (Keychain / env) 均缺则拒绝启动。
// 缺陷根因: PeerAuthorizer::new 在 secret 缺失时仅 warn (dev 容错), 但 release 部署若也漏设,
// 守护进程照常启动且 secret 校验跳过 → 仅 peercred (同 uid) 兜底, 无第二因子; 同 uid 任意进程
// (含被攻陷的 subagent) 可全权调规则突变/可逆脱敏 reveal。prod MUST 显式设 secret。
// secret 侧修复: 来源扩展到 Keychain (account shared-secret)。env 需 FUSION_GUARD_ALLOW_INSECURE_SECRET=1
// 放行 (否则视为未授权, 不静默降级)。Keychain 存在即放行 (prod 推荐路径)。
// 此函数供 fg-bin run_server 在 IpcServer::new 后调: release 且两来源皆缺 → Err。
// dev 测试不调此 (容 secret 缺, 避全测试改签名); 显式 FUSION_GUARD_ALLOW_NO_SECRET=1 放行 (应急运维)。
// 规则 5: 决策用代码 (Keychain 读 + env 读), 非 token 推断。
pub fn require_shared_secret_for_release() -> std::result::Result<(), String> {
    // dev 构建跳过 (debug_assertions = true) —— 容 secret 缺。
    if cfg!(debug_assertions) {
        return Ok(());
    }
    // 应急放行 flag 优先判 (CI/soak 设此 flag): 跳过 Keychain 读 —— 非交互环境 get_generic_password
    // 可能串行阻塞 (CLAUDE.md 记录 Keychain 挂起风险), CI 无需也读不到 Keychain secret。
    // 设此 flag = 运维知情 peercred-only 鉴权 (INSECURE, 非 prod), 与 load_shared_secret 旁路一致。
    let allow_no_secret = std::env::var("FUSION_GUARD_ALLOW_NO_SECRET")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if allow_no_secret {
        tracing::warn!(
            "H-C: release build starting WITHOUT shared secret (FUSION_GUARD_ALLOW_NO_SECRET=1 set) — \
             peercred-only auth, INSECURE; remove this flag for prod"
        );
        return Ok(());
    }
    // 来源 1: Keychain (macOS prod 推荐路径)。
    let keychain_has = matches!(keychain_secret_get(), Ok(Some(_)));
    if keychain_has {
        return Ok(());
    }
    // 来源 2: env (escape hatch, release 须显式 flag 放行)。
    let env_authorized = shared_secret_env_present() && allow_insecure_secret_flag_set();
    if env_authorized {
        return Ok(());
    }
    tracing::error!(
        env = SHARED_SECRET_ENV,
        "H-C: release build refusing to start — shared secret not found in Keychain or env. \
         Provision Keychain: `security add-generic-password -s fusion-guard -a shared-secret -w <secret>`, \
         or set {} + FUSION_GUARD_ALLOW_INSECURE_SECRET=1 (env escape, same-UID visible — not recommended for prod), \
         or set FUSION_GUARD_ALLOW_NO_SECRET=1 only for emergency insecure operation.",
        SHARED_SECRET_ENV
    );
    Err(format!(
        "refusing to start: shared secret not found in Keychain (fusion-guard/shared-secret) or env (H-C); \
         provision Keychain or set {} + FUSION_GUARD_ALLOW_INSECURE_SECRET=1, \
         or FUSION_GUARD_ALLOW_NO_SECRET=1 for insecure bypass",
        SHARED_SECRET_ENV
    ))
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
