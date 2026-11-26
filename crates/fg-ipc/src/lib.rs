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
pub use authorizer::{
    require_shared_secret_for_release, AuthDecision, Authorizer, PeerAuthorizer, TenantLookup,
};
// P2-3: PeerUid three-state peer credential (distinguishes syscall failure vs cross-UID denial).
pub use fg_peercred::PeerUid;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;

const MAX_CONNECTIONS: usize = 64;
const MAX_CONCURRENT_REQS: usize = 16;
const MAX_LINE_BYTES: usize = 1024 * 1024;
const REQ_TIMEOUT_SECS: u64 = 2;
// P1-7 (audit §P1-7): dedicated rate-limit slots for slow tasks. Slow methods (large-table verify_chain / federated
// network calls) cannot cancel an in-flight spawn_blocking task within the 2s timeout — slow requests can
// saturate the blocking thread pool (max_blocking_threads=64) and starve the interception path (guard.evaluate).
// Separate slow_sem (≤ fast req_sem): slow tasks take a slow permit moved into the spawn_blocking closure and
// hold it until the task actually completes (not released on timeout), hard-capping concurrent slow tasks so fast slots stay available for interception.
const MAX_CONCURRENT_SLOW: usize = 4;
// P1-4 (audit §2.3): dedicated short timeout for permit waits. The old code nested req_sem.acquire_owned().await
// inside the 2s handler timeout → permit queueing time ate into the business budget, leaving handlers < 2s
// under high concurrency. Split it: permit gets its own 500ms wait; failure → -32002 rate limit immediately;
const PERMIT_TIMEOUT_MS: u64 = 500;
// C17/A6 (P0-G8): connection-level total deadline, covering the read phase against slowloris.
// A single connection lives at most this long from accept; on timeout it is disconnected and the conn_sem slot freed.
// Slow-rate attacks in the read phase (one byte per 1.9s, no newline) no longer hold slots indefinitely.
const CONN_DEADLINE_SECS: u64 = 30;
// C17: chunked incremental reads. read_until may still buffer many bytes at once; use take() cap +
// cumulative byte check as double protection. Disconnect immediately on exceeding MAX_LINE_BYTES (no response).
const READ_CHUNK_BYTES: usize = 64 * 1024;
const FRAMING_BYTE: u8 = 0x0A;

pub const DEFAULT_SOCK: &str = "/tmp/fusion-guard.sock";

// P0-1 (audit §1.1): shared secret env var (§12.1 P2). Prod deployments set this; every caller is compared
// constant-time on non-request paths. Unset = dev mode (skips secret check with a warning).
pub const SHARED_SECRET_ENV: &str = "FUSION_GUARD_SHARED_SECRET";

// P0-1 (audit §1.1): caller identity resolved from the connection. peercred uid → authorized tenant set (from tenant_bindings).
// admin = root (uid 0) → all tenants + global verify. Non-admin → wire tenant_id must be within the tenants set.
#[derive(Debug, Clone)]
pub struct CallerIdentity {
    pub uid: u32,
    pub auth_ok: bool,
    pub is_admin: bool,
    pub tenants: Vec<String>,
}

impl CallerIdentity {
    // Whether the wire tenant_id is within this caller's authorized set. Admin allows any tenant (root is
    // all-powerful). Non-admin: the tenant must be explicitly bound. An unbound uid (empty set) only passes
    // when it is the daemon itself with tenant=default (bootstrap binds the daemon; otherwise empty = deny).
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
    // P1-7 (audit §P1-7): dedicated slow-task rate-limit slots — prevent large-table verify / federated network calls from saturating the blocking pool and starving interception.
    slow_sem: Arc<Semaphore>,
    // P1-5 (audit §3.1): extract the auth layer as a trait — identity resolution + per-method authorization as pure logic, independently unit-testable.
    // The old shared_secret field moved down into PeerAuthorizer (the Authorizer trait impl); the server no longer holds it.
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
        // P0-1 (audit §1.1): daemon uid bootstrap → default tenant binding (idempotent). Prevents locking itself out with an empty binding set.
        let daemon_uid = our_uid();
        if let Err(e) = audit.bind_tenant(daemon_uid, fg_store::DEFAULT_TENANT) {
            tracing::warn!(error = %e, uid = daemon_uid, "daemon tenant bootstrap failed (P0-1)");
        }
        // P1-5: the auth layer uses the PeerAuthorizer trait impl (identity resolution + shared secret, §12.1).
        // secret env reading + warn logging moved down into PeerAuthorizer::new, no longer duplicated in the server.
        let auth: Arc<dyn Authorizer> = Arc::new(PeerAuthorizer::new(audit.clone()));
        Self {
            engine: Arc::new(engine),
            audit,
            conn_sem: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            req_sem: Arc::new(Semaphore::new(MAX_CONCURRENT_REQS)),
            slow_sem: Arc::new(Semaphore::new(MAX_CONCURRENT_SLOW)),
            auth,
        }
    }

    // P1-4 test-helpers: custom req_sem slot count + exposed handle. Tests pre-take all permits, forcing
    // subsequent requests into the permit wait → 500ms timeout → -32002 (deterministic, no real slow handler needed).
    // Compiled only under the test-helpers feature; production paths unaffected.
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
            slow_sem: Arc::new(Semaphore::new(MAX_CONCURRENT_SLOW)),
            auth,
        }
    }

    // P1-7 test-helpers: custom slow_sem slot count (req_sem stays at default 16, so only the slow path is limited).
    // Tests pre-take all slow permits → slow methods wait on slow_sem → 500ms timeout → -32002;
    // fast methods (ping) still work (req_sem untouched, unaffected by slow_sem), proving the two limiters are independent.
    #[cfg(feature = "test-helpers")]
    pub fn new_with_slow_permits(
        engine: AuditEngine,
        audit: Arc<AuditStore>,
        slow_permits: usize,
    ) -> Self {
        let auth: Arc<dyn Authorizer> = Arc::new(PeerAuthorizer::new(audit.clone()));
        Self {
            engine: Arc::new(engine),
            audit,
            conn_sem: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            req_sem: Arc::new(Semaphore::new(MAX_CONCURRENT_REQS)),
            slow_sem: Arc::new(Semaphore::new(slow_permits)),
            auth,
        }
    }

    #[cfg(feature = "test-helpers")]
    pub fn req_sem_handle(&self) -> Arc<Semaphore> {
        self.req_sem.clone()
    }

    // P1-7 test-helpers: expose the slow_sem handle. Tests pre-take and hold all slow permits,
    // forcing slow methods into the slow_sem wait → 500ms timeout → -32002 (deterministic; verifies slow limiting is independent of fast).
    #[cfg(feature = "test-helpers")]
    pub fn slow_sem_handle(&self) -> Arc<Semaphore> {
        self.slow_sem.clone()
    }

    pub async fn serve(self, sock: PathBuf) -> Result<()> {
        // A5 (P0-G9): socket TOCTOU + /tmp squatting defense.
        // remove_file only removes regular files/sockets and fails on directories/symlinks; the old code swallowed the error with `let _` → bind failure exits at startup.
        // Fix: after remove_file, check symlink_metadata; if the path still exists (directory/malicious squatter) → refuse to bind with a loud error.
        let _ = std::fs::remove_file(&sock);
        if let Ok(meta) = std::fs::symlink_metadata(&sock) {
            // Path still exists after remove_file → directory/symlink/unremovable entity → refuse to bind (anti-startup DoS).
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

            // P0-9 (audit §2.2): decouple conn_sem from the accept loop. try_acquire decides immediately,
            // rejecting on failure (never blocking the main accept loop). The old acquire_owned().await blocked accept →
            // 64 slow connections filled the slots; connection 65 was accepted yet stuck in acquire, freezing all authorization for 30s.
            // try_acquire_owned() never suspends: when full, send a rejection frame + disconnect, and the accept loop keeps serving new connections,
            // so urgent evaluate calls are not starved behind the slow-connection queue.
            let conn_sem = arc.conn_sem.clone();
            let permit = match conn_sem.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    tracing::warn!(
                        peer = ?peer_addr,
                        "conn_sem full ({} slots) — rejecting connection (P0-9 fail-fast, not freezing accept)",
                        MAX_CONNECTIONS
                    );
                    // Do not drop silently: send a rejection frame so the caller knows it is rate limiting, not a crash, and fast-closes to retry.
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
        // E6 (PRD §6.2): LOCAL_PEERCRED validates peer uid == daemon uid (or root).
        // The fd must be taken before into_split (the stream moves after the split).
        let fd = stream.as_raw_fd();
        // P2-4 (audit §3.4): the peer_uid syscall goes through the bridge (fg-peercred) and may panic. Like the conn_loop
        // read path, wrap it in catch_unwind to prevent silent death of a spawned task. Hence peer_uid + resolve_identity +
        // conn_loop are all inside the catch block (resolve_identity is pure logic but does dyn dispatch on self.auth).
        let deadline = std::time::Duration::from_secs(CONN_DEADLINE_SECS);
        let conn_fut = async {
            let peer = peer_uid(fd);
            let our = our_uid();
            // P1-5: identity resolution moved down into Authorizer::resolve_identity (E6 + P0-1 pure logic).
            let identity = self.auth.resolve_identity(peer, our);

            let (rd, mut wr) = stream.into_split();
            let mut reader = BufReader::with_capacity(READ_CHUNK_BYTES, rd);
            let mut line: Vec<u8> = Vec::new();
            self.conn_loop(&mut reader, &mut wr, &mut line, identity)
                .await
        };
        let conn_with_guard = AssertUnwindSafe(conn_fut).catch_unwind();
        match tokio::time::timeout(deadline, conn_with_guard).await {
            Ok(Ok(inner)) => inner,
            Ok(Err(panic_payload)) => {
                let msg = panic_msg(&panic_payload);
                tracing::error!(
                    panic = %msg,
                    "handle_conn PANIC caught (P2-4 catch_unwind) — disconnecting, no silent task death"
                );
                Err(std::io::Error::other("connection handler panic"))
            }
            Err(_) => {
                tracing::warn!(
                    "connection total deadline exceeded (C17/A6 slowloris guard) — disconnect"
                );
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "conn deadline",
                ))
            }
        }
    }

    // C17: chunked rate-limited reads + cumulative cap disconnection. read_until is wrapped in take(MAX_LINE_BYTES+1) to truncate;
    // disconnect immediately when over the limit (no response, preventing a 500MB no-newline OOM). take hitting the cap = no newline found = oversized.
    async fn conn_loop(
        self: &Arc<Self>,
        reader: &mut tokio::io::BufReader<tokio::net::unix::OwnedReadHalf>,
        wr: &mut tokio::net::unix::OwnedWriteHalf,
        line: &mut Vec<u8>,
        identity: CallerIdentity,
    ) -> std::io::Result<()> {
        loop {
            line.clear();
            // take(MAX_LINE_BYTES + 1): reading exactly MAX_LINE_BYTES+1 bytes without a newline = oversized.
            // Normal requests are ≤ MAX_LINE_BYTES and contain a newline, so take never triggers.
            let n = reader
                .take((MAX_LINE_BYTES + 1) as u64)
                .read_until(FRAMING_BYTE, line)
                .await?;
            if n == 0 {
                break;
            }
            if line.len() > MAX_LINE_BYTES {
                // C17: disconnect on over-limit (no response, no continue) — caps memory spikes + slowloris.
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

        // P2-3 (audit §3.4): the JSON-RPC protocol version must be "2.0". The old code parsed the jsonrpc field but never checked its value —
        // a caller could send {"jsonrpc":"1.0",...} or omit the field and still traverse the full dispatch/audit path, polluting the audit
        // trail with a non-standard protocol / bypassing client-side version assertions. Protocol-level validation precedes method
        // authorization (JSON-RPC spec: Invalid Request comes before method dispatch), returning -32600. A missing field (serde default empty string) is rejected too.
        if req.jsonrpc != "2.0" {
            tracing::warn!(
                jsonrpc = %req.jsonrpc,
                method = %method,
                "invalid request: jsonrpc field must be \"2.0\" (P2-3) — rejecting with -32600"
            );
            return err_resp_bytes(id, -32600, "invalid request: jsonrpc must be \"2.0\"");
        }

        // P1-5: the E6 authorization gate + §12.1 shared-secret check moved down into Authorizer::authorize_method.
        // The old inline pair (peercred gate + constant-time secret compare) lived on the dispatch_arc I/O path with no standalone unit tests.
        // Now the trait decision → deny_resp emits the -32001 response directly; Allow continues into business handling.
        let provided_secret = authorizer::extract_secret(&req);
        let decision = self
            .auth
            .authorize_method(&identity, &method, provided_secret);
        if let Some(deny) = decision.deny_resp(&id) {
            return deny;
        }

        let timeout = std::time::Duration::from_secs(REQ_TIMEOUT_SECS);
        let permit_timeout = std::time::Duration::from_millis(PERMIT_TIMEOUT_MS);

        // P1-7 (audit §P1-7): dedicated slow-task limiting. Slow methods = full-table rehash or federated network calls,
        // where the 2s timeout cannot cancel an in-flight blocking task and slow requests can saturate the blocking pool, starving interception.
        // On is_slow hit → additionally take a slow_sem permit (moved into the fut, held until the task completes), hard-capping concurrent slow tasks.
        // Fast methods (evaluate/redact/confirm/tcc/es/rule.*) are not constrained by slow_sem and use the original req_sem path.
        let is_slow = is_slow_method(&method);
        let slow_sem = self.slow_sem.clone();

        let req_sem = self.req_sem.clone();
        let arc = self.clone();
        let identity_owned = identity.clone();
        let req_owned = req.clone();

        // P1-4 (audit §2.3): permit wait gets its own short timeout, not counted against the 2s handler budget.
        // The old acquire_owned().await was nested inside the handler timeout future; queueing time stole business time,
        // and under high concurrency the handler effectively got < 2s, compressing the interception deadline. Two separate phases:
        //   1) permit waits alone for 500ms — failure → -32002 rate limit (fail-fast, does not consume the handler window).
        //   2) with the permit in hand, the 2s timeout wraps only spawn_blocking(handle_method), giving the full window to business.
        // P1-7: slow methods first take a slow_sem permit (independent 500ms timeout; failure → -32002).
        // When the slow pool is full → reject immediately; slow requests must not queue up and steal fast req_sem slots (protecting interception concurrency).
        // _slow_permit lives as long as _permit (held until the fut await returns = task done/timed out), not released early on timeout.
        let _slow_permit: Option<tokio::sync::OwnedSemaphorePermit> = if is_slow {
            match tokio::time::timeout(permit_timeout, slow_sem.acquire_owned()).await {
                Ok(Ok(owned)) => Some(owned),
                Ok(Err(_)) => {
                    tracing::warn!(
                        method = %method,
                        "slow_sem closed — slow task rate limit (P1-7)"
                    );
                    return err_resp_bytes(id, -32002, "guard rate limited");
                }
                Err(_) => {
                    tracing::warn!(
                        method = %method,
                        limit_ms = PERMIT_TIMEOUT_MS,
                        "slow task permit wait timeout — rate limit (P1-7)"
                    );
                    return err_resp_bytes(id, -32002, "guard rate limited");
                }
            }
        } else {
            // Not slow: no slow permit held; a None placeholder keeps the _slow_permit lifetime uniform.
            None
        };

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

        // P0-6 (audit §2.1): handle_method is synchronous blocking (SQLite Mutex + chain hash computation);
        // the old code awaited it directly on a tokio worker → a confirm burst live-locked the 8-worker pool;
        // the 2s timeout cannot cancel a blocking call, so the interception path (guard.evaluate) became unschedulable.
        // spawn_blocking moves blocking work to a dedicated blocking thread pool (default 512 threads); tokio workers
        // only await the JoinHandle (cancellable), freeing workers for accept / urgent interception.
        // P0-8/P2-2: wrap all handlers in catch_unwind. Any panic inside a handler (CJK last4 residue,
        // tokenizer index out of bounds, span invariant violations) no longer unwinds out of the worker task causing a silent disconnect.
        // On catch, log the stack + return -32010 (same code as internal errors; the wire never leaks panic details).
        // P1-4: this fut contains only the handler; the permit was taken earlier — the 2s timeout covers the full business window.
        let fut = async move {
            // spawn_blocking holds Arc<engine>/Arc<audit>/'static data and runs handle_method on the blocking pool.
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
                // M1/P1: full Display goes into the server log; the wire returns only code + a leak-safe generic message.
                tracing::warn!(method = %method, error = %e, "method error");
                err_resp_bytes(id, err_code(&e), &err_wire_msg(&e))
            }
            Ok(Err(panic_payload)) => {
                // P0-8: panic captured. Log the panic location (source string or type name) + a generic wire error.
                // Non-ASCII content (CJK last4) or internal invariant violations fall through here, no silent disconnect.
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
                // pong: bool — cross-repo consumer contract (fusion-cli #9 / fusion-studio #344 read Bool).
                // The old "ok" string broke consumer `as? Bool` / `pong:bool` deserialization → false unreachable reports.
                "pong": true,
                "version": env!("CARGO_PKG_VERSION"),
                "rules_epoch": self.engine.epoch(),
            })),
            "guard.evaluate" => {
                // L8/P1: content is required; missing/wrong type → -32602 (no longer silently treated as empty → L1 pass bypass).
                let content =
                    s_param(&req.params, "content", 0).ok_or(GuardError::InvalidParams)?;
                let action = s_param(&req.params, "action", 4).unwrap_or("");
                let requester = s_param(&req.params, "requester", 3)
                    .unwrap_or("unknown")
                    .to_string();
                let tenant_id = s_param(&req.params, "tenant_id", 2)
                    .unwrap_or(fg_store::DEFAULT_TENANT)
                    .to_string();
                // P0-1 (audit §1.1): the wire tenant_id must be within the caller's authorized set, otherwise -32001.
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
                // P0-2 (audit §1.7): content_type selects the scan stage (shell/code/json/yaml/text).
                // Default → Shell (backward compatible). Unknown value → ContentType::parse falls back to Shell.
                let content_type_str = s_param(&req.params, "content_type", 5).unwrap_or("shell");
                let content_type = fg_core::ContentType::parse(content_type_str);
                // P2-6 (audit §3.2/F6, PRD §12.2): optional category_hint? caller hint.
                // Default None (backward compatible). Guard infers the category from content as the authority (H9);
                // the hint only acts as a risk floor (max(inferred, hits, hint)), raising the level but never lowering it.
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
                    // C23/P0-G4 (H7 fail-closed): high-risk verdict audit persist failure → refuse to deliver the verdict
                    // (the gatekeeper must not allow high-risk actions without an audit credential). Losing a low-risk (L1/L2)
                    // async-queue append is non-fatal, warn only (append_event already warns on queue shutdown).
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
            // Issue #1/#3 (PRD §6.7 / D-10, fusion-event frozen contract): guard.audit inbound RPC.
            // fusion-event calls this before dispatching an Agent Task trigger for authorization/injection audit.
            // Params: trigger_id/event_type/target_path/target_agent/payload{}/node_id.
            // Response: {decision: pass|block|challenge, reason, risk_level:int, audit_id, trigger_id}.
            // Block goes through result.decision="block" (not an RPC error) — fusion-event accepts both states and uses result uniformly,
            // avoiding callers treating -32010 as a fault and degrading (issue #3: the S0 error code applies only when guard chooses the RPC error path).
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
                // requester = target_agent (the agent that triggered the action), the audit-visible source.
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
            // Issue #1 (PRD §6.7): guard.audit_result reverse-callback contract — after a challenge decision,
            // fusion-guard calls back fusion-event @ /tmp/fusion-event.sock with the resolved decision.
            // This is an outbound connection (guard→fusion-event) requiring the fusion-event daemon online + its sock contract.
            // Currently: guard is the inbound server with no proactive outbound client; fusion-event is not landed (upstream issue pending).
            // So this method accepts the audit_result pushed back by the caller (fusion-event) and records it in the audit as a receipt,
            // not a guard outbound call. The contract shape is reserved + audited; the real outbound call awaits the frozen fusion-event sock contract.
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
                    "guard.audit_result received (fusion-event challenge callback receipt, issue #1)"
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
                // H-B (product-audit §5): rule mutations (add/update/remove) are admin (root) only.
                // Non-admin → Forbidden (-32001, same wire code as Unauthorized to prevent admin enumeration; logs distinguish).
                // PRD rule SSOT protection: prevent ordinary tenant users from altering the blocklist themselves, breaking interception or planting malicious rules.
                if !identity.is_admin {
                    tracing::warn!(
                        method = "guard.rule.add",
                        uid = identity.uid,
                        "rule mutation by non-admin rejected (H-B admin gate)"
                    );
                    return Err(GuardError::Forbidden);
                }
                // L7/P1: stale-epoch check before mutation (non-0 and == current), otherwise -32003.
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
                if !identity.is_admin {
                    tracing::warn!(
                        method = "guard.rule.update",
                        uid = identity.uid,
                        "rule mutation by non-admin rejected (H-B admin gate)"
                    );
                    return Err(GuardError::Forbidden);
                }
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
                if !identity.is_admin {
                    tracing::warn!(
                        method = "guard.rule.remove",
                        uid = identity.uid,
                        "rule mutation by non-admin rejected (H-B admin gate)"
                    );
                    return Err(GuardError::Forbidden);
                }
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
                // issue #7: expose the 15 redaction pattern definitions (name+regex+validator tag), read-only dump.
                // Patterns are global (not tenant-scoped), no tenant check — any authorized caller can pull them; consumers
                // re-implement validators from the tag (fusion-gateway PII SSOT subscription, removing manual lockstep).
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
                // M8/P1: permission must be a known TCC service (TccService::parse validates),
                // rejecting arbitrary strings into the audit store (anti-injection noise + canonical enum). requester/result/reason truncated to 1024.
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
                // P3/P1: hard limit cap of 10000, preventing u64::MAX → full-table scan OOM.
                let limit = cap_limit(u_param(&req.params, "limit", 0).unwrap_or(50));
                let events = self.engine.list_tcc_events(limit)?;
                Ok(serde_json::json!({ "events": events }))
            }
            "guard.audit.list" => {
                // P0-1 (audit §1.1): genuinely enforce filtering by the caller's authorized tenant (the old comment self-declared the wire as false).
                // The wire tenant_id must be in the authorized set; non-admin cross-tenant → -32001. P3: hard limit cap 10000.
                // P1-6 (audit §3.2): adds since/until/event_type/level_min filters + cursor pagination.
                //   Monitoring passes since=<last row ts> to pull increments only, no longer brute-force polling all 10000 rows.
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
                // level_min: 'l1'..'l4' (case-insensitive, lowercased internally to match json_extract output).
                let level_min = s_param(&req.params, "level_min", 5).map(|s| s.to_lowercase());
                // Cursor: the client passes back the previous next_cursor ("ts\x1faudit_id"). Both keys are parsed to fetch older rows.
                let cursor = s_param(&req.params, "cursor", 6);
                let (cursor_ts, cursor_id) = match cursor {
                    Some(c) if c.contains('\x1f') => {
                        let mut parts = c.splitn(2, '\x1f');
                        let ts = parts.next().filter(|s| !s.is_empty());
                        let id = parts.next().filter(|s| !s.is_empty());
                        match (ts, id) {
                            (Some(ts), Some(id)) => (Some(ts), Some(id)),
                            _ => (None, None), // Malformed cursor ignored; degrade to first page.
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
                // P0-1 (audit §1.1): verify is tenant-scoped. Non-admin → forced to its authorized tenant
                // (cutting off cross-tenant row-count leakage). Admin → accepts the wire tenant_id or None (global).
                let wire_tenant = s_param(&req.params, "tenant_id", 0);
                let scope: Option<&str> = if identity.is_admin {
                    wire_tenant
                } else {
                    // Non-admin: the scope must be one of its authorized tenants. The wire naming another tenant → reject.
                    // Absent → default to the first authorized tenant (non-admin usually single-tenant).
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
                    "guard.audit.verify handled (PRD §13.3 full-chain aggregation: audit+tcc+rules+dead_letter, P0-5)"
                );
                Ok(serde_json::to_value(&v)?)
            }
            // P0-7 (audit §2.8): ES monitoring exposed via IPC (not dead-code). Without an entitlement →
            // report the degraded state honestly (state=degraded, source=es-bridge:stub, entitlement=false),
            // not fake Active. Operators thus know ES is not in effect and fall back to TCC (PRD Q#3).
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
            // issue #4 / multi-nodes#52 — three cross-node consumer primitives (guard.cluster.*).
            // Multi-nodes defines TRANSPORT+KEY SCHEME; guard consumes: federated chain verify / epoch reconcile / confirm relay.
            // Without cluster_token (single-node mode) → -32011 cluster-not-configured, not silent.
            "guard.cluster.audit.fetch" => {
                let cfg = cluster_cfg_or_err()?;
                let client = ClusterClient::new(cfg)
                    .map_err(|e| GuardError::Engine(format!("cluster client: {e}")))?;
                let since_seq = u_param(&req.params, "since_seq", 0).unwrap_or(0);
                let chain_resp = client
                    .fetch_audit_chain(since_seq)
                    .map_err(|e| GuardError::Engine(format!("cluster audit fetch: {e}")))?;
                // Federated chain verification — MAC + prev_hash double tamper detection.
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
                // reconcile: local < cluster → local is behind (caller must refetch rules, stale);
                //             local > cluster → advance the cluster epoch to align (leader-only; a non-leader 409 is acceptable);
                //             equal → in sync.
                let mut advanced_to: Option<u64> = None;
                let mut action = "in_sync".to_string();
                if local_epoch > cluster_epoch.epoch {
                    match client.advance_rule_epoch("guard local epoch ahead") {
                        Ok(r) => {
                            advanced_to = Some(r.epoch);
                            action = "advanced_cluster".to_string();
                        }
                        Err(e) => {
                            // Non-leader 409 or network error — log a warn, do not block (best-effort alignment).
                            tracing::warn!(error = %e, "cluster epoch advance failed (non-leader or network), best-effort skip");
                            action = "advance_failed".to_string();
                        }
                    }
                } else if local_epoch < cluster_epoch.epoch {
                    action = "local_behind".to_string();
                }
                tracing::info!(
                    local_epoch, cluster_epoch = cluster_epoch.epoch,
                    action = %action, advanced_to = ?advanced_to,
                    "guard.cluster.epoch.sync handled (issue #4 cluster epoch reconcile, Checkpoint 2 SSOT extended to the cluster domain)"
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
                    "guard.cluster.confirm.relay handled (issue #4 cross-node confirm relay, MAC-authenticated cluster membership)"
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
                    "guard.cluster.confirm.list handled (issue #4 confirm aggregate query)"
                );
                Ok(serde_json::to_value(&resp)?)
            }
            // M2/P1: unknown method → -32601 (MethodNotFound), no method-name leak (generic Display).
            _ => Err(GuardError::MethodNotFound),
        }
    }
}

// issue #4 / multi-nodes#52 — build the cluster config from env. Without cluster_token (single-node mode) → -32011,
// not silent: the caller learns cross-node consumption is unconfigured and does not assume it is federated.
fn cluster_cfg_or_err() -> Result<ClusterConfig> {
    ClusterConfig::from_env()
        .ok_or_else(|| GuardError::Engine("cluster not configured: FUSION_GUARD_CLUSTER_TOKEN env not set (single-node mode, cross-node primitives unavailable)".into()))
}

// P1-7 (audit §P1-7): slow-method determination — full-table rehash or federated network calls, where the 2s timeout cannot cancel a blocking task.
// Such methods occupy the blocking pool for a long time and need their own slow_sem limiting (≤ fast) to avoid saturating the pool and starving interception.
// guard.audit.verify: verify_all_chains rehashes the full table across 4 chains (audit+tcc+rules+dead_letter), slow on large tables.
// guard.cluster.*: federated HTTP calls (5s timeout), occupying blocking slots long under network latency.
// Fast methods (evaluate/redact/reveal/confirm/tcc.*/es.*/rule.*/audit.list/ping) return immediately via the original req_sem.
fn is_slow_method(method: &str) -> bool {
    matches!(
        method,
        "guard.audit.verify"
            | "guard.cluster.audit.fetch"
            | "guard.cluster.epoch.sync"
            | "guard.cluster.confirm.relay"
            | "guard.cluster.confirm.list"
    )
}

// L8/P1: JSON-RPC params can be either an object (named) or an array (positional).
// The old `params.get("key")` returned None for Value::Array → all fields defaulted → empty content → L1 pass bypass.
// Unified param access: by name first (named), falling back to positional idx. Neither → None (caller turns it into -32602).
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

// P3/P1: hard limit cap. Prevents a caller passing u64::MAX → full-table scan OOM. Cap 10000, floor 1.
const AUDIT_LIST_LIMIT_CAP: usize = 10000;
fn cap_limit(n: u64) -> usize {
    let n = n.max(1) as usize;
    n.min(AUDIT_LIST_LIMIT_CAP)
}

// M8/P1: truncate free-text fields (requester/result/reason) to keep oversized input out of the audit store.
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
        // H-B: rule-mutation non-admin denial shares the Unauthorized code (-32001) — the wire does not distinguish
        // (anti-side-channel admin enumeration), logs do (Display contains "forbidden: rule mutation requires admin").
        GuardError::Forbidden => -32001,
        GuardError::RateLimited => -32002,
        GuardError::StaleEpoch { .. } => -32003,
        GuardError::Engine(_) => -32010,
        GuardError::InvalidParams => -32602,
        GuardError::MethodNotFound => -32601,
        // P2-3: JSON-RPC protocol version not "2.0" → -32600 Invalid Request (JSON-RPC spec code).
        GuardError::InvalidRequest => -32600,
        _ => -32603,
    }
}

// M1/P1: the wire returns only code + a leak-safe generic message (no SQLite schema/paths/method names/internal details).
// The server logs the full Display (traced at dispatch); clients only ever see the generic string.
// StaleEpoch is the only case that must return the guard epoch so the caller can refetch rules; caller/guard numbers kept (non-sensitive).
fn err_wire_msg(e: &GuardError) -> String {
    match e {
        GuardError::Unauthorized(_) => "unauthorized".into(),
        GuardError::RateLimited => "rate limited".into(),
        GuardError::StaleEpoch { caller, guard } => {
            format!("stale epoch: caller={caller} guard={guard}")
        }
        GuardError::InvalidParams => "invalid params".into(),
        GuardError::MethodNotFound => "method not found".into(),
        // H-B: wire stays generic (no admin enumeration), logs record the forbidden detail.
        GuardError::Forbidden => "unauthorized".into(),
        // P2-3: generic message for an invalid protocol version.
        GuardError::InvalidRequest => "invalid request: jsonrpc must be 2.0".into(),
        GuardError::Engine(_) => "guard engine error".into(),
        GuardError::Serde(_) => "serialization error".into(),
        GuardError::Io(_) => "io error".into(),
    }
}

// P0-9 (audit §2.2): rejection frame when conn_sem is full. A notification frame (id=null, JSON-RPC notification) is sent before disconnecting,
// letting the caller know it is rate limiting, not a crash, so it can fail-closed retry instead of hanging silently. Disconnect right after sending.
// id=null because the server never read the request (the rejection happens before dispatch); do not fabricate an id.
async fn reject_conn(stream: UnixStream, code: i32, msg: &str) {
    let frame = format!(
        r#"{{"jsonrpc":"2.0","id":null,"error":{{"code":{code},"message":"{msg}"}}}}{FRAMING_BYTE}"#
    );
    let mut wr = stream;
    let _ = tokio::io::AsyncWriteExt::write_all(&mut wr, frame.as_bytes()).await;
    let _ = tokio::io::AsyncWriteExt::flush(&mut wr).await;
    // drop wr → disconnect frees the fd (the conn_sem slot is not held; the accept loop continues).
}

fn ok_resp_bytes(id: Value, result: Value) -> Vec<u8> {
    // P2-2: keep an id backup (clone) for the serialization-failure fallback — serde_json::to_vec moves resp but does not affect the fallback.
    let id_bak = id.clone();
    let resp = RpcResponse {
        jsonrpc: "2.0".into(),
        id,
        result: Some(result),
        error: None,
    };
    // Serialization failure no longer unwrap_or_default() → empty Vec → bare \n (client JSON-RPC parse failure /
    // id mismatch, unable to distinguish rejection/crash/disconnect). Instead: return a fixed error frame (with id + -32603 internal error).
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

// P2-2: fallback frame on serialization failure. Hand-assemble a minimal valid JSON-RPC error frame (bypassing serde to avoid a second failure).
// Contains id + code -32603 (InternalError) + a generic message so the client at least recognizes a guard error instead of a bare \n.
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

// P0-8: extract a readable message from the panic payload for logging. The payload may be &str / String / any type.
// Log-only diagnostics, never into the wire (the wire is always the generic -32010).
fn panic_msg(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        return (*s).to_string();
    }
    if let Some(s) = payload.downcast_ref::<String>() {
        return s.clone();
    }
    "<non-string panic payload>".to_string()
}
