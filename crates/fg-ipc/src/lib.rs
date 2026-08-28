use fg_audit_engine::AuditEngine;
use fg_cluster::{derive_audit_chain_key, verify_chain_segment, ClusterClient, ClusterConfig};
use fg_core::{GuardError, Result, RiskLevel, SafetyAction};
use fg_peercred::{our_uid, peer_uid};
use fg_store::AuditStore;
use futures::FutureExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

mod authorizer;
pub use authorizer::{AuthDecision, Authorizer, PeerAuthorizer, TenantLookup};
// P2-3: PeerUid 三态对端凭证 (区分系统调用失败 vs 跨 UID 拒绝)。
pub use fg_peercred::PeerUid;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;

const MAX_CONNECTIONS: usize = 64;
const MAX_CONCURRENT_REQS: usize = 16;
const MAX_LINE_BYTES: usize = 1024 * 1024;
const REQ_TIMEOUT_SECS: u64 = 2;
// P1-4 (audit §2.3): permit 等待独立短超时。旧码 req_sem.acquire_owned().await 嵌在
// 2s handler timeout 内 → permit 排队时间偷占业务预算, 高并发时 handler 实际可用 < 2s。
// 分离: permit 单独 500ms 等待, 拿不到 → -32002 rate limit 即拒; 拿到后 2s 全程给 handler。
const PERMIT_TIMEOUT_MS: u64 = 500;
// C17/A6 (P0-G8): 连接级总 deadline, 包读取阶段防 slowloris。
// 单连接从 accept 起最多存活这么久; 超时即断连释放 conn_sem 槽。
// 读阶段慢速攻击 (每 1.9s 一个字节无换行) 不再无限占槽。
const CONN_DEADLINE_SECS: u64 = 30;
// C17: 分块读取增量。read_until 仍可能一次缓冲大量字节; 用 take() 上限 +
// 累计字节检查双保险。超 MAX_LINE_BYTES 立即断连 (不回响应)。
const READ_CHUNK_BYTES: usize = 64 * 1024;
const FRAMING_BYTE: u8 = 0x0A;

pub const DEFAULT_SOCK: &str = "/tmp/fusion-guard.sock";

// P0-1 (audit §1.1): 共享 secret 环境变量 (§12.1 P2 落地)。prod 部署设此变量, 每个 caller
// 非请求带 secret 常量时间比对。未设 = dev 模式 (跳过 secret 校验但 warn)。
pub const SHARED_SECRET_ENV: &str = "FUSION_GUARD_SHARED_SECRET";

// P0-1 (audit §1.1): 连接解析出的调用方身份。peercred uid → 授权租户集合 (查 tenant_bindings)。
// admin = root (uid 0) → 全租户 + 全局 verify。非 admin → wire tenant_id 须在 tenants 集合内。
#[derive(Debug, Clone)]
pub struct CallerIdentity {
    pub uid: u32,
    pub auth_ok: bool,
    pub is_admin: bool,
    pub tenants: Vec<String>,
}

impl CallerIdentity {
    // wire tenant_id 是否在该 caller 授权集合内。admin 放任意 (含未知租户, 因 root 全权)。
    // 非 admin: tenant 须显式绑定。未绑定的 uid (空集) → 仅当 daemon 自身且 tenant=default
    // 时放行 (bootstrap 保证 daemon 绑定 default, 故非 daemon 空集 = 真·无权, 拒)。
    pub fn tenant_allowed(&self, tenant: &str) -> bool {
        if self.is_admin {
            return true;
        }
        self.tenants.iter().any(|t| t == tenant)
    }
}

pub struct IpcServer {
    engine: Arc<AuditEngine>,
    audit: Arc<AuditStore>,
    conn_sem: Arc<Semaphore>,
    req_sem: Arc<Semaphore>,
    // P1-5 (audit §3.1): 鉴权层抽 trait —— 身份解析 + 方法级鉴权纯逻辑独立单测。
    // 旧 shared_secret 字段下沉进 PeerAuthorizer (Authorizer trait 实现), server 不再重复持。
    auth: Arc<dyn Authorizer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RpcRequest {
    jsonrpc: String,
    id: Value,
    method: String,
    params: Value,
}

#[derive(Debug, Serialize)]
struct RpcResponse {
    jsonrpc: String,
    id: Value,
    result: Option<Value>,
    error: Option<RpcError>,
}

#[derive(Debug, Serialize)]
struct RpcError {
    code: i32,
    message: String,
}

impl IpcServer {
    pub fn new(engine: AuditEngine, audit: Arc<AuditStore>) -> Self {
        // P0-1 (audit §1.1): daemon uid bootstrap → default 租户绑定 (幂等)。免空绑定集锁死自身。
        let daemon_uid = our_uid();
        if let Err(e) = audit.bind_tenant(daemon_uid, fg_store::DEFAULT_TENANT) {
            tracing::warn!(error = %e, uid = daemon_uid, "daemon tenant bootstrap failed (P0-1)");
        }
        // P1-5: 鉴权层走 PeerAuthorizer trait 实现 (身份解析 + 共享 secret, §12.1)。
        // secret env 读取 + warn 日志下沉到 PeerAuthorizer::new, 不再在 server 重复。
        let auth: Arc<dyn Authorizer> = Arc::new(PeerAuthorizer::new(audit.clone()));
        Self {
            engine: Arc::new(engine),
            audit,
            conn_sem: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            req_sem: Arc::new(Semaphore::new(MAX_CONCURRENT_REQS)),
            auth,
        }
    }

    // P1-4 test-helpers: 自定义 req_sem 槽数 + 暴露句柄。测试预取全部 permit 持有,
    // 强制后续请求走 permit 等待 → 500ms 超时 → -32002 (确定性, 无需真实慢 handler)。
    // 仅 test-helpers feature 编译, 生产路径不受影响。
    #[cfg(feature = "test-helpers")]
    pub fn new_with_req_permits(
        engine: AuditEngine,
        audit: Arc<AuditStore>,
        permits: usize,
    ) -> Self {
        let auth: Arc<dyn Authorizer> = Arc::new(PeerAuthorizer::new(audit.clone()));
        Self {
            engine: Arc::new(engine),
            audit,
            conn_sem: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            req_sem: Arc::new(Semaphore::new(permits)),
            auth,
        }
    }

    #[cfg(feature = "test-helpers")]
    pub fn req_sem_handle(&self) -> Arc<Semaphore> {
        self.req_sem.clone()
    }

    pub async fn serve(self, sock: PathBuf) -> Result<()> {
        // A5 (P0-G9): socket TOCTOU + /tmp 蹲守防御。
        // remove_file 只能删常规文件/socket, 遇目录/symlink 失败; 旧码 `let _` 吞错 → bind 失败启动退出。
        // 改: remove_file 后查 symlink_metadata, 路径仍存在 (目录/恶意蹲守) → 拒 bind, 响亮报错。
        let _ = std::fs::remove_file(&sock);
        if let Ok(meta) = std::fs::symlink_metadata(&sock) {
            // remove_file 后路径仍存在 → 是目录/symlink/不可删实体 → 拒绝 bind (防启动 DoS)。
            return Err(fg_core::GuardError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "socket path occupied by non-removable entity (dir/symlink squat, A5): {} (is_dir={})",
                    sock.display(),
                    meta.is_dir()
                ),
            )));
        }
        let listener = UnixListener::bind(&sock)?;
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;
        tracing::info!(sock = %sock.display(), "fusion-guard UDS server listening");

        let arc = Arc::new(self);
        loop {
            let (stream, peer_addr) = listener.accept().await?;
            tracing::debug!(peer = ?peer_addr, "incoming connection");

            // P0-9 (audit §2.2): conn_sem 与 accept 循环解耦。try_acquire 立即判槽,
            // 失败即拒 (非阻塞主 accept 循环)。旧码 acquire_owned().await 阻塞 accept →
            // 64 慢连接占满槽, 第 65 连接虽 accept 成功却卡在 acquire, 整机授权冻结 30s。
            // try_acquire_owned() 不挂起: 满即发拒绝帧 + 断连, accept 循环继续服务新连接,
            // 紧急 evaluate 不被慢连接队列饿死。
            let conn_sem = arc.conn_sem.clone();
            let permit = match conn_sem.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    tracing::warn!(
                        peer = ?peer_addr,
                        "conn_sem full ({} slots) — rejecting connection (P0-9 fail-fast, not freezing accept)",
                        MAX_CONNECTIONS
                    );
                    // 不静默丢弃: 发拒绝帧让 caller 知是限流非崩溃, fast-closed 重试。
                    reject_conn(stream, -32010, "guard connection limit reached").await;
                    continue;
                }
            };

            let arc2 = arc.clone();
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = arc2.handle_conn(stream).await {
                    tracing::warn!(error = %e, "connection handler error");
                }
            });
        }
    }

    async fn handle_conn(self: Arc<Self>, stream: UnixStream) -> std::io::Result<()> {
        // E6 (PRD §6.2): LOCAL_PEERCRED 校验对端 uid == 守护进程 uid (或 root)。
        // fd 必须在 into_split 前取 (split 后 stream 移动)。
        let fd = stream.as_raw_fd();
        let peer = peer_uid(fd);
        let our = our_uid();
        // P1-5: 身份解析下沉 Authorizer::resolve_identity (E6 + P0-1 纯逻辑)。
        // server 仅留 I/O 边界 (取 fd/peer_uid), 解析进 trait → 独立单测无需套接字。
        let identity = self.auth.resolve_identity(peer, our);

        let (rd, mut wr) = stream.into_split();
        let mut reader = BufReader::with_capacity(READ_CHUNK_BYTES, rd);
        let mut line: Vec<u8> = Vec::new();

        // C17/A6: 连接级总 deadline 包整个 read+dispatch 循环。
        // 超时即断连释放 sem 槽, 防慢速攻击 (slowloris) 无限占连接。
        let deadline = std::time::Duration::from_secs(CONN_DEADLINE_SECS);
        let conn_fut = self.conn_loop(&mut reader, &mut wr, &mut line, identity);
        match tokio::time::timeout(deadline, conn_fut).await {
            Ok(inner) => inner,
            Err(_) => {
                tracing::warn!(
                    peer_uid = ?peer,
                    "connection total deadline exceeded (C17/A6 slowloris guard) — disconnect"
                );
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "conn deadline",
                ))
            }
        }
    }

    // C17: 分块限流读取 + 累计上限断连。read_until 包 take(MAX_LINE_BYTES+1) 截断,
    // 检测到超限立即断连 (不回响应, 防 500MB 无换行 OOM)。take 到顶 = 未遇换行 = 超长。
    async fn conn_loop(
        self: &Arc<Self>,
        reader: &mut tokio::io::BufReader<tokio::net::unix::OwnedReadHalf>,
        wr: &mut tokio::net::unix::OwnedWriteHalf,
        line: &mut Vec<u8>,
        identity: CallerIdentity,
    ) -> std::io::Result<()> {
        loop {
            line.clear();
            // take(MAX_LINE_BYTES + 1): 读到刚好 MAX_LINE_BYTES+1 字节无换行 = 超长。
            // 正常请求 ≤ MAX_LINE_BYTES 且含换行, take 不会触发。
            let n = reader
                .take((MAX_LINE_BYTES + 1) as u64)
                .read_until(FRAMING_BYTE, line)
                .await?;
            if n == 0 {
                break;
            }
            if line.len() > MAX_LINE_BYTES {
                // C17: 超限断连 (不回响应, 不 continue) — 斩内存峰值 + slowloris。
                tracing::warn!(
                    bytes = line.len(),
                    "read exceeded MAX_LINE_BYTES — disconnecting (C17 OOM guard)"
                );
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "request too large",
                ));
            }
            while line.last() == Some(&FRAMING_BYTE) {
                line.pop();
            }
            let req_str = String::from_utf8_lossy(line);
            let resp_json = self.dispatch_arc(&req_str, identity.clone()).await;
            wr.write_all(&resp_json).await?;
        }
        Ok(())
    }

    async fn dispatch_arc(self: &Arc<Self>, req_str: &str, identity: CallerIdentity) -> Vec<u8> {
        let req: RpcRequest = match serde_json::from_str(req_str) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "malformed request");
                return err_resp_bytes(Value::Null, -32700, "parse error");
            }
        };

        let id = req.id.clone();
        let method = req.method.clone();

        // P1-5: E6 鉴权闸门 + §12.1 共享 secret 校验下沉 Authorizer::authorize_method。
        // 旧码内联两段 (peercred 闸 + secret 常量时间比对) 在 dispatch_arc I/O 路径, 无独立单测。
        // 现 trait 决策 → deny_resp 直出 -32001 响应; Allow 继续业务。
        let provided_secret = authorizer::extract_secret(&req);
        let decision = self
            .auth
            .authorize_method(&identity, &method, provided_secret);
        if let Some(deny) = decision.deny_resp(&id) {
            return deny;
        }

        let timeout = std::time::Duration::from_secs(REQ_TIMEOUT_SECS);
        let permit_timeout = std::time::Duration::from_millis(PERMIT_TIMEOUT_MS);

        let req_sem = self.req_sem.clone();
        let arc = self.clone();
        let identity_owned = identity.clone();
        let req_owned = req.clone();

        // P1-4 (audit §2.3): permit 等待独立短超时, 不计入 2s handler 预算。
        // 旧码 acquire_owned().await 嵌在 handler timeout future 内, 排队耗时偷占业务时间,
        // 高并发下 handler 实际可用 < 2s, 拦截路径判定时限被压缩。分离两段:
        //   1) permit 单独 500ms 等待 — 拿不到即 -32002 rate limit (fail-fast, 不占 handler 窗口)。
        //   2) 拿到 permit 后, 2s timeout 只包 spawn_blocking(handle_method) 全程给业务。
        let permit_fut = req_sem.acquire_owned();
        let _permit = match tokio::time::timeout(permit_timeout, permit_fut).await {
            Ok(Ok(owned)) => owned,
            Ok(Err(_acquire_err)) => {
                tracing::warn!(method = %method, "req_sem closed — rate limit (P1-4)");
                return err_resp_bytes(id, -32002, "guard rate limited");
            }
            Err(_) => {
                tracing::warn!(
                    method = %method,
                    limit_ms = PERMIT_TIMEOUT_MS,
                    "permit wait timeout — rate limit (P1-4)"
                );
                return err_resp_bytes(id, -32002, "guard rate limited");
            }
        };

        // P0-6 (audit §2.1): handle_method 是同步阻塞 (SQLite Mutex + 链 hash 计算),
        // 旧码直接 .await 跑在 tokio worker → confirm 突发负载活锁 8 worker 池,
        // 2s 超时无法取消阻塞调用, 拦截路径 (guard.evaluate) 因 worker 阻塞无法调度。
        // spawn_blocking 把阻塞工作移到独立阻塞线程池 (默认 512 线程), tokio worker
        // 仅 await JoinHandle (可取消), 释放 worker 给 accept / 紧急拦截。
        // P0-8/P2-2: 全 handler 包 catch_unwind。handler 内任何 panic (CJK last4 残留、
        // tokenizer index 越界、span 逻辑 invariant 违反) 不再 unwind 出 worker task 致静默断连。
        // 捕获后记栈 + 返 -32010 (与内部错误同码, wire 不泄露 panic 细节)。
        // P1-4: 此 fut 只含 handler, permit 已提前取得 — 2s timeout 全程覆盖业务。
        let fut = async move {
            // spawn_blocking 持 Arc<engine>/Arc<audit>/'static 数据, 阻塞跑 handle_method。
            let arc_for_block = arc.clone();
            match tokio::task::spawn_blocking(move || {
                arc_for_block.handle_method(req_owned, identity_owned)
            })
            .await
            {
                Ok(res) => res,
                Err(join_err) => {
                    tracing::error!(error = %join_err, "spawn_blocking join failed (P0-6)");
                    Err(fg_core::GuardError::Engine(
                        "blocking task join failed".into(),
                    ))
                }
            }
        };

        match tokio::time::timeout(timeout, AssertUnwindSafe(fut).catch_unwind()).await {
            Ok(Ok(Ok(val))) => ok_resp_bytes(id, val),
            Ok(Ok(Err(e))) => {
                // M1/P1: 完整 Display 入服务端日志, wire 仅回 code + 泄露安全的通用消息。
                tracing::warn!(method = %method, error = %e, "method error");
                err_resp_bytes(id, err_code(&e), &err_wire_msg(&e))
            }
            Ok(Err(panic_payload)) => {
                // P0-8: panic 捕获。记 panic 位置 (来源字符串或类型名) + 通用 wire 错误。
                // 非 ASCII 内容 (CJK last4) 或内部 invariant 违反在此兜底, 不静默断连。
                let msg = panic_msg(&panic_payload);
                tracing::error!(
                    method = %method,
                    panic = %msg,
                    "handler PANIC caught (P0-8 catch_unwind) — returning -32010, no silent disconnect"
                );
                err_resp_bytes(id, -32010, "guard internal error")
            }
            Err(_) => {
                tracing::warn!(method = %method, "request timeout (fail-closed)");
                err_resp_bytes(id, -32010, "guard request timeout")
            }
        }
    }

    fn handle_method(self: Arc<Self>, req: RpcRequest, identity: CallerIdentity) -> Result<Value> {
        match req.method.as_str() {
            "guard.ping" => Ok(serde_json::json!({
                "pong": "ok",
                "version": env!("CARGO_PKG_VERSION"),
                "rules_epoch": self.engine.epoch(),
            })),
            "guard.evaluate" => {
                // L8/P1: content 必填, 缺/类型错 → -32602 (不再静默当空 → L1 pass 绕过)。
                let content =
                    s_param(&req.params, "content", 0).ok_or(GuardError::InvalidParams)?;
                let action = s_param(&req.params, "action", 4).unwrap_or("");
                let requester = s_param(&req.params, "requester", 3)
                    .unwrap_or("unknown")
                    .to_string();
                let tenant_id = s_param(&req.params, "tenant_id", 2)
                    .unwrap_or(fg_store::DEFAULT_TENANT)
                    .to_string();
                // P0-1 (audit §1.1): wire tenant_id 须在 caller 授权集合内, 否则 -32001。
                if !identity.tenant_allowed(&tenant_id) {
                    tracing::warn!(
                        method = "guard.evaluate",
                        uid = identity.uid,
                        tenant = %tenant_id,
                        "cross-tenant evaluate denied (P0-1)"
                    );
                    return Err(GuardError::Unauthorized(
                        "tenant not authorized for caller".into(),
                    ));
                }
                let caller_epoch = u_param(&req.params, "caller_epoch", 1).unwrap_or(0);
                // P0-2 (audit §1.7): content_type 分派扫描阶段 (shell/code/json/yaml/text)。
                // 缺省 → Shell (向后兼容)。未知值 → ContentType::parse 兜 Shell。
                let content_type_str = s_param(&req.params, "content_type", 5).unwrap_or("shell");
                let content_type = fg_core::ContentType::parse(content_type_str);
                // P2-6 (audit §3.2/F6, PRD §12.2): category_hint? 可选调用方 hint。
                // 缺省 None (向后兼容)。guard 从 content 推断 category 权威 (H9),
                // hint 仅作风险地板 (max(推断,命中,hint)) 抬等级不压低。
                let category_hint = s_param(&req.params, "category_hint", 6).map(|s| s.to_string());
                let verdict = self.engine.evaluate(
                    content,
                    caller_epoch,
                    &tenant_id,
                    content_type,
                    category_hint.as_deref(),
                )?;
                let redacted = verdict.redacted_content.clone().unwrap_or_default();
                let high_risk = matches!(verdict.risk_level, RiskLevel::L3 | RiskLevel::L4)
                    || verdict.action == SafetyAction::Block;
                if let Err(e) = self
                    .audit
                    .append_event(&tenant_id, &verdict, redacted, &requester)
                {
                    // C23/P0-G4 (H7 fail-closed): 高危判定审计落库失败 → 拒绝下发判定
                    // (守门人不可在无审计凭据下放行高危动作)。低危 (L1/L2) 异步队列丢
                    // 失为非致命, 仅告警 (append_event 内部已 warn 队列关闭)。
                    if high_risk {
                        tracing::error!(
                            error = %e,
                            risk = ?verdict.risk_level,
                            "high-risk audit append failed — refusing evaluate (C23 fail-closed H7)"
                        );
                        return Err(GuardError::Engine(format!(
                            "high-risk audit persist failed: {e}"
                        )));
                    }
                    tracing::warn!(error = %e, "low-risk audit append failed (non-fatal)");
                }
                tracing::info!(
                    action = action,
                    tenant = %tenant_id,
                    requester = %requester,
                    category = %verdict.inferred_category,
                    "guard.evaluate handled"
                );
                Ok(serde_json::to_value(&verdict)?)
            }
            // Issue #1/#3 (PRD §6.7 / D-10, fusion-event 冻结契约): guard.audit 入站 RPC。
            // fusion-event 下发 Agent Task trigger 前调此做权限/注入审计。
            // 参数: trigger_id/event_type/target_path/target_agent/payload{}/node_id。
            // 应答: {decision: pass|block|challenge, reason, risk_level:int, audit_id, trigger_id}。
            // Block 走 result.decision="block" (非 RPC error) —— fusion-event 两态都接受, 统一用 result
            // 避免 caller 把 -32010 当故障降级 (issue #3 明确 S0 error code 仅当 guard 选 RPC error 路径)。
            "guard.audit" => {
                let trigger_id = s_param(&req.params, "trigger_id", 0)
                    .ok_or(GuardError::InvalidParams)?
                    .to_string();
                let event_type = s_param(&req.params, "event_type", 1)
                    .unwrap_or("")
                    .to_string();
                let target_path = s_param(&req.params, "target_path", 2)
                    .unwrap_or("")
                    .to_string();
                let target_agent = s_param(&req.params, "target_agent", 3)
                    .unwrap_or("")
                    .to_string();
                let payload = v_param(&req.params, "payload", 4).unwrap_or(Value::Null);
                let node_id = s_param(&req.params, "node_id", 5).unwrap_or("").to_string();
                let tenant_id = s_param(&req.params, "tenant_id", 6)
                    .unwrap_or(fg_store::DEFAULT_TENANT)
                    .to_string();
                if !identity.tenant_allowed(&tenant_id) {
                    tracing::warn!(
                        method = "guard.audit",
                        uid = identity.uid,
                        tenant = %tenant_id,
                        "cross-tenant audit denied (P0-1)"
                    );
                    return Err(GuardError::Unauthorized(
                        "tenant not authorized for caller".into(),
                    ));
                }
                // requester = target_agent (触发动作的 agent), 审计可见来源。
                let decision = self.engine.audit_event(
                    &trigger_id,
                    &event_type,
                    &target_path,
                    &target_agent,
                    &payload,
                    &node_id,
                    &tenant_id,
                    &target_agent,
                )?;
                tracing::info!(
                    trigger_id = %trigger_id,
                    event_type = %event_type,
                    decision = %decision.decision,
                    "guard.audit handled (fusion-event D-10)"
                );
                Ok(serde_json::to_value(&decision)?)
            }
            // Issue #1 (PRD §6.7): guard.audit_result 反向回调契约 —— challenge 决策后,
            // fusion-guard 回拨 fusion-event @ /tmp/fusion-event.sock 传 resolved decision。
            // 这是出站连接 (guard→fusion-event), 需 fusion-event 守护进程在线 + 其 sock 契约。
            // 当前: guard 是入站服务端, 无主动出站客户端; fusion-event 未落地 (上游 issue 待提)。
            // 故此方法接受 caller (fusion-event) 主动推送回的 audit_result, 落审计作回执记录,
            // 非 guard 主动外呼。契约形状先占位 + 审计, 真正外呼待 fusion-event sock 契约冻结。
            "guard.audit_result" => {
                let audit_id = s_param(&req.params, "audit_id", 0)
                    .ok_or(GuardError::InvalidParams)?
                    .to_string();
                let trigger_id = s_param(&req.params, "trigger_id", 1)
                    .unwrap_or("")
                    .to_string();
                let decision = s_param(&req.params, "decision", 2)
                    .unwrap_or("")
                    .to_string();
                let reason = s_param(&req.params, "reason", 3).unwrap_or("").to_string();
                tracing::info!(
                    audit_id = %audit_id,
                    trigger_id = %trigger_id,
                    decision = %decision,
                    reason = %reason,
                    "guard.audit_result received (fusion-event challenge callback回执, issue #1)"
                );
                Ok(serde_json::json!({
                    "received": true,
                    "audit_id": audit_id,
                    "trigger_id": trigger_id
                }))
            }
            "guard.rule.list" => {
                let rs = self.engine.list_rules();
                Ok(serde_json::json!({ "rules": rs.rules, "epoch": rs.epoch }))
            }
            "guard.rules.dump" => {
                let rs = self.engine.list_rules();
                Ok(serde_json::json!({ "rules": rs.rules, "epoch": rs.epoch }))
            }
            "guard.rule.add" => {
                // L7/P1: 突变前 stale-epoch 校验 (非 0 且 == 当前), 否则 -32003。
                let caller_epoch = u_param(&req.params, "caller_epoch", 0).unwrap_or(0);
                self.engine.check_epoch(caller_epoch)?;
                let rule: fg_rules::GuardRule =
                    serde_json::from_value(v_param(&req.params, "rule", 1).unwrap_or(Value::Null))
                        .map_err(|_| GuardError::InvalidParams)?;
                let new_epoch = self
                    .engine
                    .add_rule(rule)
                    .map_err(|e| GuardError::Engine(e.to_string()))?;
                tracing::info!(new_epoch = new_epoch, "guard.rule.add handled");
                Ok(serde_json::json!({ "new_epoch": new_epoch }))
            }
            "guard.rule.update" => {
                let caller_epoch = u_param(&req.params, "caller_epoch", 0).unwrap_or(0);
                self.engine.check_epoch(caller_epoch)?;
                let name = s_param(&req.params, "name", 1)
                    .ok_or(GuardError::InvalidParams)?
                    .to_string();
                let rule: fg_rules::GuardRule =
                    serde_json::from_value(v_param(&req.params, "rule", 2).unwrap_or(Value::Null))
                        .map_err(|_| GuardError::InvalidParams)?;
                let new_epoch = self
                    .engine
                    .update_rule(&name, rule)
                    .map_err(|e| GuardError::Engine(e.to_string()))?;
                tracing::info!(
                    new_epoch = new_epoch,
                    name = %name,
                    "guard.rule.update handled"
                );
                Ok(serde_json::json!({ "new_epoch": new_epoch }))
            }
            "guard.rule.remove" => {
                let caller_epoch = u_param(&req.params, "caller_epoch", 0).unwrap_or(0);
                self.engine.check_epoch(caller_epoch)?;
                let name = s_param(&req.params, "name", 1)
                    .ok_or(GuardError::InvalidParams)?
                    .to_string();
                let new_epoch = self
                    .engine
                    .remove_rule(&name)
                    .map_err(|e| GuardError::Engine(e.to_string()))?;
                tracing::info!(
                    new_epoch = new_epoch,
                    name = %name,
                    "guard.rule.remove handled"
                );
                Ok(serde_json::json!({ "new_epoch": new_epoch }))
            }
            "guard.redact" => {
                let content =
                    s_param(&req.params, "content", 0).ok_or(GuardError::InvalidParams)?;
                let reversible = b_param(&req.params, "reversible", 1).unwrap_or(false);
                let tenant_id = s_param(&req.params, "tenant_id", 2)
                    .unwrap_or(fg_store::DEFAULT_TENANT)
                    .to_string();
                if !identity.tenant_allowed(&tenant_id) {
                    tracing::warn!(
                        method = "guard.redact",
                        uid = identity.uid,
                        tenant = %tenant_id,
                        "cross-tenant redact denied (P0-1)"
                    );
                    return Err(GuardError::Unauthorized(
                        "tenant not authorized for caller".into(),
                    ));
                }
                let res = self.engine.redact_tenant(content, reversible, &tenant_id)?;
                tracing::info!(
                    reversible = reversible,
                    token_map_id = ?res.token_map_id,
                    tenant = %tenant_id,
                    "guard.redact handled"
                );
                Ok(serde_json::to_value(&res)?)
            }
            "guard.redact.patterns.dump" => {
                // issue #7: 暴露 15 redaction pattern 定义 (name+regex+validator tag), 只读 dump。
                // pattern 全局 (非租户 scoped), 不校验 tenant —— 任何授权 caller 可拉取, 消费方按
                // tag 重实现 validator (fusion-gateway PII SSOT 订阅, 消手动 lockstep)。
                let patterns = self.engine.pattern_defs();
                tracing::info!(count = patterns.len(), "guard.redact.patterns.dump handled");
                Ok(serde_json::json!({ "patterns": patterns }))
            }
            "guard.reveal" => {
                let content =
                    s_param(&req.params, "content", 0).ok_or(GuardError::InvalidParams)?;
                let token_map_id = s_param(&req.params, "token_map_id", 1)
                    .unwrap_or("")
                    .to_string();
                let tenant_id = s_param(&req.params, "tenant_id", 2)
                    .unwrap_or(fg_store::DEFAULT_TENANT)
                    .to_string();
                if !identity.tenant_allowed(&tenant_id) {
                    tracing::warn!(
                        method = "guard.reveal",
                        uid = identity.uid,
                        tenant = %tenant_id,
                        "cross-tenant reveal denied (P0-1)"
                    );
                    return Err(GuardError::Unauthorized(
                        "tenant not authorized for caller".into(),
                    ));
                }
                let restored = self.engine.reveal_tenant(content, &tenant_id)?;
                tracing::info!(token_map_id = %token_map_id, tenant = %tenant_id, "guard.reveal handled (C2 tenant-bound)");
                Ok(serde_json::json!({ "content": restored }))
            }
            "guard.confirm" => {
                let action_id = s_param(&req.params, "action_id", 0)
                    .ok_or(GuardError::InvalidParams)?
                    .to_string();
                let approved = b_param(&req.params, "approved", 1).unwrap_or(false);
                let approved_by = s_param(&req.params, "approved_by", 2)
                    .unwrap_or("unknown")
                    .to_string();
                let tenant_id = s_param(&req.params, "tenant_id", 3)
                    .unwrap_or(fg_store::DEFAULT_TENANT)
                    .to_string();
                if !identity.tenant_allowed(&tenant_id) {
                    tracing::warn!(
                        method = "guard.confirm",
                        uid = identity.uid,
                        tenant = %tenant_id,
                        "cross-tenant confirm denied (P0-1)"
                    );
                    return Err(GuardError::Unauthorized(
                        "tenant not authorized for caller".into(),
                    ));
                }
                let res = self
                    .engine
                    .confirm(&action_id, approved, &approved_by, &tenant_id)?;
                Ok(serde_json::to_value(&res)?)
            }
            "guard.tcc.status" => {
                let statuses = self.engine.tcc_status();
                Ok(serde_json::json!({ "statuses": statuses }))
            }
            "guard.tcc.report" => {
                let permission =
                    s_param(&req.params, "permission", 0).ok_or(GuardError::InvalidParams)?;
                let requester = s_param(&req.params, "requester", 1)
                    .unwrap_or("unknown")
                    .to_string();
                let result = s_param(&req.params, "result", 2)
                    .unwrap_or("unknown")
                    .to_string();
                let reason = s_param(&req.params, "reason", 3).unwrap_or("").to_string();
                // M8/P1: permission 必须是已知 TCC 服务 (TccService::parse 校验),
                // 拒任意字符串入审计库 (防注入噪音 + 规范枚举)。requester/result/reason 截断 1024。
                if fg_tcc::TccService::parse(permission).is_none() {
                    tracing::warn!(
                        permission = permission,
                        "tcc.report unknown permission (M8)"
                    );
                    return Err(GuardError::InvalidParams);
                }
                let requester = truncate_field(&requester, 1024);
                let result = truncate_field(&result, 1024);
                let reason = truncate_field(&reason, 1024);
                let audit_id = self
                    .engine
                    .report_tcc(permission, &requester, &result, &reason)?;
                tracing::info!(
                    permission = permission,
                    requester = %requester,
                    result = %result,
                    "guard.tcc.report handled (audit aggregation H1)"
                );
                Ok(serde_json::json!({ "audit_id": audit_id }))
            }
            "guard.tcc.events" => {
                // P3/P1: limit 硬上限 10000, 防 u64::MAX → 全表扫 OOM。
                let limit = cap_limit(u_param(&req.params, "limit", 0).unwrap_or(50));
                let events = self.engine.list_tcc_events(limit)?;
                Ok(serde_json::json!({ "events": events }))
            }
            "guard.audit.list" => {
                // P0-1 (audit §1.1): 真·强制按 caller 授权 tenant 过滤 (旧注释自声明 wire 为假)。
                // wire tenant_id 须在授权集合内; 非 admin 跨租户 → -32001。P3: limit 硬上限 10000。
                // P1-6 (audit §3.2): 补 since/until/event_type/level_min 过滤 + 游标分页。
                //   监控 since=<上次末行 ts> 只拉增量, 不再暴力轮询全量 10000 行。
                let limit = cap_limit(u_param(&req.params, "limit", 0).unwrap_or(50));
                let tenant_id =
                    s_param(&req.params, "tenant_id", 1).unwrap_or(fg_store::DEFAULT_TENANT);
                if !identity.tenant_allowed(tenant_id) {
                    tracing::warn!(
                        method = "guard.audit.list",
                        uid = identity.uid,
                        tenant = tenant_id,
                        "cross-tenant audit.list denied (P0-1)"
                    );
                    return Err(GuardError::Unauthorized(
                        "tenant not authorized for caller".into(),
                    ));
                }
                let since = s_param(&req.params, "since", 2);
                let until = s_param(&req.params, "until", 3);
                let event_type = s_param(&req.params, "event_type", 4);
                // level_min: 'l1'..'l4' (大小写不敏感, 内部转小写匹配 json_extract 输出)。
                let level_min = s_param(&req.params, "level_min", 5).map(|s| s.to_lowercase());
                // 游标: 客户端透传上次 next_cursor ("ts\x1faudit_id")。解双键续拉更旧行。
                let cursor = s_param(&req.params, "cursor", 6);
                let (cursor_ts, cursor_id) = match cursor {
                    Some(c) if c.contains('\x1f') => {
                        let mut parts = c.splitn(2, '\x1f');
                        let ts = parts.next().filter(|s| !s.is_empty());
                        let id = parts.next().filter(|s| !s.is_empty());
                        match (ts, id) {
                            (Some(ts), Some(id)) => (Some(ts), Some(id)),
                            _ => (None, None), // 畸形游标忽略, 退化为首页。
                        }
                    }
                    _ => (None, None),
                };
                let page = self.audit.list_filtered_page(&fg_store::AuditListFilter {
                    tenant_id: Some(tenant_id),
                    since,
                    until,
                    event_type,
                    level_min: level_min.as_deref(),
                    cursor_ts,
                    cursor_id,
                    limit,
                });
                Ok(serde_json::json!({
                    "records": page.records,
                    "next_cursor": page.next_cursor,
                    "has_more": page.has_more
                }))
            }
            "guard.audit.verify" => {
                // P0-1 (audit §1.1): verify 加 tenant 作用域。非 admin → 强制其授权 tenant
                // (斩跨租户行数外泄)。admin → 接受 wire tenant_id 或 None (全局)。
                let wire_tenant = s_param(&req.params, "tenant_id", 0);
                let scope: Option<&str> = if identity.is_admin {
                    wire_tenant
                } else {
                    // 非 admin: scope 必须是其授权租户之一。wire 给其他租户 → 拒。
                    // 不给 → 默认取授权集中首个 (非 admin 通常单租户)。
                    match wire_tenant {
                        Some(t) => {
                            if !identity.tenant_allowed(t) {
                                tracing::warn!(
                                    method = "guard.audit.verify",
                                    uid = identity.uid,
                                    tenant = t,
                                    "cross-tenant audit.verify denied (P0-1)"
                                );
                                return Err(GuardError::Unauthorized(
                                    "tenant not authorized for caller".into(),
                                ));
                            }
                            Some(t)
                        }
                        None => identity.tenants.first().map(|s| s.as_str()),
                    }
                };
                let v = self
                    .audit
                    .verify_all_chains(scope)
                    .map_err(|e| GuardError::Engine(e.to_string()))?;
                tracing::info!(
                    scope = ?scope,
                    audit_total = v.audit.total_rows,
                    audit_tampered = v.audit.tampered,
                    tcc_tampered = v.tcc.tampered,
                    rules_tampered = v.rules.tampered,
                    dead_letter_tampered = v.dead_letter.tampered,
                    tampered = v.tampered,
                    "guard.audit.verify handled (PRD §13.3 全链聚合: audit+tcc+rules+dead_letter, P0-5)"
                );
                Ok(serde_json::to_value(&v)?)
            }
            // P0-7 (audit §2.8): ES 监控经 IPC 暴露 (非 dead-code)。无 entitlement →
            // degraded 状态如实回 (state=degraded, source=es-bridge:stub, entitlement=false),
            // 非假装 Active。运维据此知 ES 未生效, 退回 TCC (PRD Q#3)。
            "guard.es.status" => {
                let status = self.engine.es_status();
                tracing::info!(
                    state = ?status.state,
                    source = %status.source,
                    entitlement = status.entitlement,
                    "guard.es.status handled (P0-7 honest degraded)"
                );
                Ok(serde_json::to_value(&status)?)
            }
            "guard.es.events" => {
                let events = self.engine.es_events();
                tracing::info!(count = events.len(), "guard.es.events handled (P0-7)");
                Ok(serde_json::json!({ "events": events }))
            }
            // issue #4 / multi-nodes#52 — 跨节点消费方 3 原语 (guard.cluster.*)。
            // 多节点定义 TRANSPORT+KEY SCHEME, guard 消费: federated 链验证 / epoch reconcile / confirm 中继。
            // 无 cluster_token (单节点模式) → -32011 cluster-not-configured, 非静默。
            "guard.cluster.audit.fetch" => {
                let cfg = cluster_cfg_or_err()?;
                let client = ClusterClient::new(cfg)
                    .map_err(|e| GuardError::Engine(format!("cluster client: {e}")))?;
                let since_seq = u_param(&req.params, "since_seq", 0).unwrap_or(0);
                let chain_resp = client
                    .fetch_audit_chain(since_seq)
                    .map_err(|e| GuardError::Engine(format!("cluster audit fetch: {e}")))?;
                // federated 链验证 — MAC + prev_hash 双重篡改检出。
                let chain_key = derive_audit_chain_key(&client.cfg_ref().cluster_token);
                let verify =
                    verify_chain_segment(&chain_resp.node_id, &chain_resp.records, &chain_key);
                tracing::info!(
                    node_id = %chain_resp.node_id,
                    total = verify.total_records,
                    verified = verify.verified_links,
                    broken = verify.broken_links,
                    tampered = verify.tampered,
                    "guard.cluster.audit.fetch handled (issue #4 federated chain verify)"
                );
                Ok(serde_json::json!({
                    "node_id": chain_resp.node_id,
                    "fetched_at": chain_resp.fetched_at,
                    "records": chain_resp.records,
                    "verify": verify,
                }))
            }
            "guard.cluster.epoch.sync" => {
                let cfg = cluster_cfg_or_err()?;
                let client = ClusterClient::new(cfg)
                    .map_err(|e| GuardError::Engine(format!("cluster client: {e}")))?;
                let cluster_epoch = client
                    .get_rule_epoch()
                    .map_err(|e| GuardError::Engine(format!("cluster epoch get: {e}")))?;
                let local_epoch = self.engine.epoch();
                // reconcile: local < cluster → 本地落后 (caller 须 refetch rules, stale);
                //             local > cluster → 推进集群纪元对齐 (leader-only, 非 leader 409 可接受);
                //             equal → 一致。
                let mut advanced_to: Option<u64> = None;
                let mut action = "in_sync".to_string();
                if local_epoch > cluster_epoch.epoch {
                    match client.advance_rule_epoch("guard local epoch ahead") {
                        Ok(r) => {
                            advanced_to = Some(r.epoch);
                            action = "advanced_cluster".to_string();
                        }
                        Err(e) => {
                            // 非 leader 409 或网络错 — 记 warn, 不阻断 (best-effort 对齐)。
                            tracing::warn!(error = %e, "cluster epoch advance failed (非 leader 或网络), best-effort 跳过");
                            action = "advance_failed".to_string();
                        }
                    }
                } else if local_epoch < cluster_epoch.epoch {
                    action = "local_behind".to_string();
                }
                tracing::info!(
                    local_epoch, cluster_epoch = cluster_epoch.epoch,
                    action = %action, advanced_to = ?advanced_to,
                    "guard.cluster.epoch.sync handled (issue #4 cluster epoch reconcile, Checkpoint 2 SSOT 扩展集群域)"
                );
                Ok(serde_json::json!({
                    "local_epoch": local_epoch,
                    "cluster_epoch": cluster_epoch.epoch,
                    "advanced_at": cluster_epoch.advanced_at,
                    "action": action,
                    "advanced_to": advanced_to,
                }))
            }
            "guard.cluster.confirm.relay" => {
                let cfg = cluster_cfg_or_err()?;
                let client = ClusterClient::new(cfg)
                    .map_err(|e| GuardError::Engine(format!("cluster client: {e}")))?;
                let confirm_id = s_param(&req.params, "confirm_id", 0)
                    .ok_or(GuardError::InvalidParams)?
                    .to_string();
                let node_id = s_param(&req.params, "node_id", 1)
                    .ok_or(GuardError::InvalidParams)?
                    .to_string();
                let action = s_param(&req.params, "action", 2)
                    .ok_or(GuardError::InvalidParams)?
                    .to_string();
                let epoch = u_param(&req.params, "epoch", 3).ok_or(GuardError::InvalidParams)?;
                let ts = s_param(&req.params, "ts", 4)
                    .ok_or(GuardError::InvalidParams)?
                    .to_string();
                let result = client
                    .relay_confirm(&confirm_id, &node_id, &action, epoch, &ts)
                    .map_err(|e| GuardError::Engine(format!("cluster confirm relay: {e}")))?;
                tracing::info!(
                    confirm_id = %confirm_id, node_id = %node_id,
                    status = %result.status,
                    "guard.cluster.confirm.relay handled (issue #4 cross-node confirm 中继, MAC 鉴集群成员)"
                );
                Ok(serde_json::to_value(&result)?)
            }
            "guard.cluster.confirm.list" => {
                let cfg = cluster_cfg_or_err()?;
                let client = ClusterClient::new(cfg)
                    .map_err(|e| GuardError::Engine(format!("cluster client: {e}")))?;
                let epoch = u_param(&req.params, "epoch", 0);
                let resp = client
                    .list_confirms(epoch)
                    .map_err(|e| GuardError::Engine(format!("cluster confirm list: {e}")))?;
                tracing::info!(
                    count = resp.count,
                    epoch_filter = ?epoch,
                    "guard.cluster.confirm.list handled (issue #4 confirm 聚合查询)"
                );
                Ok(serde_json::to_value(&resp)?)
            }
            // M2/P1: 未知方法 → -32601 (MethodNotFound), 不泄露方法名 (Display 通用)。
            _ => Err(GuardError::MethodNotFound),
        }
    }
}

// issue #4 / multi-nodes#52 — 从 env 构 cluster 配置。无 cluster_token (单节点模式) → -32011,
// 非静默: 调用方据此知未配置跨节点消费, 不误以为已 federated。
fn cluster_cfg_or_err() -> Result<ClusterConfig> {
    ClusterConfig::from_env()
        .ok_or_else(|| GuardError::Engine("cluster not configured: FUSION_GUARD_CLUSTER_TOKEN env 未设 (单节点模式, 跨节点原语不可用)".into()))
}

// L8/P1: JSON-RPC params 既可对象 (named) 也可数组 (positional)。
// 旧码 `params.get("key")` 对 Value::Array 返 None → 所有字段缺省 → content 空 → L1 pass 绕过。
// 统一取参: 先按名取 (named), 缺则按位置 idx 取 (positional)。两者都无 → None (调用方转 -32602)。
fn s_param<'a>(p: &'a Value, name: &str, idx: usize) -> Option<&'a str> {
    match p {
        Value::Object(_) => p.get(name).and_then(Value::as_str),
        Value::Array(_) => p.get(idx).and_then(Value::as_str),
        _ => None,
    }
}

fn b_param(p: &Value, name: &str, idx: usize) -> Option<bool> {
    match p {
        Value::Object(_) => p.get(name).and_then(Value::as_bool),
        Value::Array(_) => p.get(idx).and_then(Value::as_bool),
        _ => None,
    }
}

fn u_param(p: &Value, name: &str, idx: usize) -> Option<u64> {
    match p {
        Value::Object(_) => p.get(name).and_then(Value::as_u64),
        Value::Array(_) => p.get(idx).and_then(Value::as_u64),
        _ => None,
    }
}

fn v_param(p: &Value, name: &str, idx: usize) -> Option<Value> {
    match p {
        Value::Object(_) => p.get(name).cloned(),
        Value::Array(_) => p.get(idx).cloned(),
        _ => None,
    }
}

// P3/P1: limit 硬上限。防 caller 传 u64::MAX → list 全表扫 OOM。上限 10000, 下限保 1。
const AUDIT_LIST_LIMIT_CAP: usize = 10000;
fn cap_limit(n: u64) -> usize {
    let n = n.max(1) as usize;
    n.min(AUDIT_LIST_LIMIT_CAP)
}

// M8/P1: 截断自由文本字段 (requester/result/reason), 防超长入审计库。
fn truncate_field(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max).collect();
        cut
    }
}

fn err_code(e: &GuardError) -> i32 {
    match e {
        GuardError::Unauthorized(_) => -32001,
        GuardError::RateLimited => -32002,
        GuardError::StaleEpoch { .. } => -32003,
        GuardError::Engine(_) => -32010,
        GuardError::InvalidParams => -32602,
        GuardError::MethodNotFound => -32601,
        _ => -32603,
    }
}

// M1/P1: wire 只回 code + 泄露安全的通用消息 (不含 SQLite schema/路径/方法名/内部细节)。
// 服务端日志记完整 Display (dispatch 处已 tracing), 客户端只见通用串。
// StaleEpoch 是唯一需回 guard epoch 给 caller 重拉规则的场景, 保留 caller/guard 数字 (非敏感)。
fn err_wire_msg(e: &GuardError) -> String {
    match e {
        GuardError::Unauthorized(_) => "unauthorized".into(),
        GuardError::RateLimited => "rate limited".into(),
        GuardError::StaleEpoch { caller, guard } => {
            format!("stale epoch: caller={caller} guard={guard}")
        }
        GuardError::InvalidParams => "invalid params".into(),
        GuardError::MethodNotFound => "method not found".into(),
        GuardError::Engine(_) => "guard engine error".into(),
        GuardError::Serde(_) => "serialization error".into(),
        GuardError::Io(_) => "io error".into(),
    }
}

// P0-9 (audit §2.2): conn_sem 满时拒绝帧。conn 拒绝前发通知帧 (id=null, JSON-RPC notification),
// 让 caller 知是限流非崩溃, fail-closed 重试而非静默卡死。发完即断连。
// id=null 因 server 未读 request (拒绝发生在 dispatch 前), 不伪造 id。
async fn reject_conn(stream: UnixStream, code: i32, msg: &str) {
    let frame = format!(
        r#"{{"jsonrpc":"2.0","id":null,"error":{{"code":{code},"message":"{msg}"}}}}{FRAMING_BYTE}"#
    );
    let mut wr = stream;
    let _ = tokio::io::AsyncWriteExt::write_all(&mut wr, frame.as_bytes()).await;
    let _ = tokio::io::AsyncWriteExt::flush(&mut wr).await;
    // drop wr → 断连释放 fd (conn_sem 槽未占, accept 循环继续)。
}

fn ok_resp_bytes(id: Value, result: Value) -> Vec<u8> {
    // P2-2: id 保留备份 (clone) 供序列化失败兜底用 — serde_json::to_vec 移动 resp 不影响 fallback。
    let id_bak = id.clone();
    let resp = RpcResponse {
        jsonrpc: "2.0".into(),
        id,
        result: Some(result),
        error: None,
    };
    // 序列化失败不再 unwrap_or_default() → 空 Vec → 裸 \n (客户端 JSON-RPC 解析失败/
    // id 不匹配, 无法区分拒绝/崩溃/断连)。改: 失败返固定错误帧 (含 id + -32603 internal error)。
    match serde_json::to_vec(&resp) {
        Ok(mut bytes) => {
            bytes.push(FRAMING_BYTE);
            bytes
        }
        Err(e) => {
            tracing::error!(error = %e, "ok_resp serialization failed — sending fallback error frame (P2-2)");
            fallback_err_bytes(id_bak)
        }
    }
}

fn err_resp_bytes(id: Value, code: i32, msg: &str) -> Vec<u8> {
    let id_bak = id.clone();
    let resp = RpcResponse {
        jsonrpc: "2.0".into(),
        id,
        result: None,
        error: Some(RpcError {
            code,
            message: msg.into(),
        }),
    };
    match serde_json::to_vec(&resp) {
        Ok(mut bytes) => {
            bytes.push(FRAMING_BYTE);
            bytes
        }
        Err(e) => {
            tracing::error!(error = %e, "err_resp serialization failed — sending fallback error frame (P2-2)");
            fallback_err_bytes(id_bak)
        }
    }
}

// P2-2: 序列化失败的兜底帧。手拼最小合法 JSON-RPC error 帧 (不经 serde, 避二次失败)。
// 含 id + code -32603 (InternalError) + 通用消息, 客户端至少能识别为 guard 错误而非裸 \n。
fn fallback_err_bytes(id: Value) -> Vec<u8> {
    let id_str = match &id {
        Value::Null => "null".to_string(),
        other => other.to_string(),
    };
    let frame = format!(
        r#"{{"jsonrpc":"2.0","id":{id_str},"error":{{"code":-32603,"message":"guard internal serialization error"}}}}"#
    );
    let mut bytes = frame.into_bytes();
    bytes.push(FRAMING_BYTE);
    bytes
}

// P0-8: 从 panic payload 提取可读消息用于日志。payload 可能是 &str / String / 任意类型。
// 仅记日志诊断, 不入 wire (wire 永远通用 -32010)。
fn panic_msg(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        return (*s).to_string();
    }
    if let Some(s) = payload.downcast_ref::<String>() {
        return s.clone();
    }
    "<non-string panic payload>".to_string()
}
