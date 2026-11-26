// P1-5 (audit §3.1): split the IpcServer monolith into a trait — the Authorizer layer.
// The old code scattered peercred→identity resolution (handle_conn) and shared-secret validation (dispatch_arc) across the I/O path
// with no standalone unit tests; only real-socket integration tests could cover them. Extract the Authorizer trait + a PeerAuthorizer default impl,
// stripping the authorization pure logic (no I/O) so unit tests can feed uid/secret directly and assert decisions without sockets.
//
// Scope trimming (rules 2/7): the audit lists 4 traits (Transport/Authorizer/Dispatcher/Policy). Only Authorizer becomes a trait —
// it is the only layer holding "untested pure logic + no need to replicate the engine interface". Transport is an I/O shell (trait-izing adds abstraction with no test gain),
// Dispatcher is a thin dispatch over the engine (trait-izing would require a facade covering every engine method — replicating the interface for no benefit),
// and Policy (tenant/limit) already sank into the CallerIdentity::tenant_allowed pure method + cap_limit free function (already testable pure logic).
// One trait + a documented trimming rationale, avoiding dual modes (rule 7).

use std::sync::Arc;

use fg_peercred::{peer_allowed, PeerUid};
use fg_store::AuditStore;
// H-C secret-side fix (product-audit §5): shared secret Keychain source (same root flaw as token-key:
// env-only meant any same-UID process, e.g. a compromised subagent, could read it). The prod source moves to the macOS Keychain (service fusion-guard,
// account shared-secret). env remains an escape hatch (requires an explicit flag). fg-store::secret_store provides helpers.
// The release-only helpers (Keychain I/O + decision) are unused in debug builds → allow(unused_imports).
#[allow(unused_imports)]
use fg_store::secret_store::{
    allow_insecure_secret_flag_set, generate_shared_secret, keychain_secret_get,
    keychain_secret_store, resolve_shared_secret, shared_secret_env_present, SharedSecretSource,
};

use crate::{err_resp_bytes, CallerIdentity, RpcRequest, SHARED_SECRET_ENV};
use serde_json::Value;

// P1-5: minimal trait for tenant resolution. AuditStore implements it (tenants_for_uid); tests use FakeLookup.
// No direct dependency on AuditStore → unit tests need neither a real DB nor a Keychain key.
pub trait TenantLookup: Send + Sync {
    fn tenants_for_uid(&self, uid: u32) -> Vec<String>;
}

// AuditStore satisfies TenantLookup (tenants_for_uid already exists, pub in fg-store::lib).
impl TenantLookup for AuditStore {
    fn tenants_for_uid(&self, uid: u32) -> Vec<String> {
        AuditStore::tenants_for_uid(self, uid)
    }
}

// P1-5: authorization decisions. Allow / DenyPeercred (E6 non-peer same-uid) / DenySecret (§12.1 shared secret).
// All three Denys map to -32001, but the distinct reasons aid auditing + unit-test assertions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthDecision {
    Allow,
    DenyPeercred,
    DenySecret,
}

impl AuthDecision {
    // Decision → wire error response bytes (Deny paths). Allow continues into business handling; does not go through this.
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

// P1-5: the Authorizer trait — identity resolution + per-method authorization, pure logic with no I/O.
// resolve_identity: peercred uid → CallerIdentity (with the authorized tenant set).
// authorize_method: identity + method name + request-carried secret → decision (ping open to any peer; non-ping requires same uid + secret).
pub trait Authorizer: Send + Sync {
    fn resolve_identity(&self, peer_uid: PeerUid, our_uid: u32) -> CallerIdentity;

    fn authorize_method(
        &self,
        identity: &CallerIdentity,
        method: &str,
        provided_secret: Option<&str>,
    ) -> AuthDecision;
}

// P1-5: default implementation. Holds Arc<AuditStore> (tenant resolution) + Option<shared_secret> (§12.1).
// Secret source (H-C secret-side fix): macOS Keychain (account shared-secret, prod recommended) takes priority;
// env is an escape hatch (release requires FUSION_GUARD_ALLOW_INSECURE_SECRET=1 explicit opt-in, with a warn).
// None = dev mode skipping the secret check (release startup is refused by require_shared_secret_for_release).
pub struct PeerAuthorizer {
    tenants: Arc<dyn TenantLookup>,
    shared_secret: Option<String>,
}

// H-C secret-side: resolve the shared secret source → actually load it (Keychain I/O). Returns (secret, source).
// Resolution order: Keychain (macOS) → env (escape hatch) → none.
// - Keychain has it → use Keychain (prod path, key never enters environment variables).
// - Keychain missing + env present and authorized (debug or FUSION_GUARD_ALLOW_INSECURE_SECRET=1) → use env.
// - Keychain missing + env present but release not authorized → do not silently use env (prevents flag-less downgrade); treat as no secret.
// - Neither present → None (release startup refuses; dev skips the check).
//
// First start with no Keychain secret + no env + macOS → generate a strong random secret and store it in the Keychain (allow_mint).
// Note: generation happens only when env is also absent (an explicit env = operator-managed, not overridden); release generation is the prod default
// (the operator may also pre-provision via security add-generic-password and go pure-Keychain without generation).
#[allow(clippy::needless_return)]
pub fn load_shared_secret() -> (Option<String>, SharedSecretSource) {
    let env_present = shared_secret_env_present();
    // FUSION_GUARD_ALLOW_NO_SECRET=1: emergency/CI opt-in = peercred-only auth, skipping the secret check
    // (same opt-in semantics as require_shared_secret_for_release: non-prod, operator aware).
    // soak/CI spawning a release daemon sets this flag → clients without a secret still pass (the old env-only behavior).
    // Otherwise, release without env → the Keychain path auto-generates a secret → clients without a secret all get DenySecret.
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
    // dev builds: env only (old behavior), never touches the Keychain — avoids concurrent test-spawned servers all calling
    // get_generic_password, which serially blocks in non-interactive environments (the Keychain hang risk is documented in CLAUDE.md).
    // dev without an env secret → None (skips the secret check; test clients without a secret still pass), preserving backward compatibility.
    // release builds: use the Keychain (prod path), with the gate as the backstop refusing startup.
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
                        // Keychain has no secret. env present but not authorized (release missing the flag) lands here — do not silently use env.
                        if env_present {
                            tracing::warn!(
                            env = SHARED_SECRET_ENV,
                            "PeerAuthorizer: shared secret env present but NOT authorized in release \
                             (set FUSION_GUARD_ALLOW_INSECURE_SECRET=1 or --insecure-secret-env to use env, \
                             or provision Keychain); falling back — secret check skipped"
                        );
                            return (None, SharedSecretSource::None);
                        }
                        // env absent + Keychain absent: release first start on macOS generates and stores in the Keychain (allow_mint).
                        // dev builds do not auto-generate (backward compatibility: existing test clients carry no secret; in dev no secret = skip check;
                        // generating in dev would make all non-ping requests DenySecret and break tests).
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
                        // dev builds / non-macOS: no secret → dev mode skips the check (the gate refuses release startup).
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
                // P2-1 secret-side mirror warning: using env in prod puts the second factor into the process environment, readable by any same-UID process.
                tracing::warn!(
                    "INSECURE (H-C secret): shared secret loaded from env in release build — \
                 visible to any same-UID process; prod MUST use Keychain \
                 (FUSION_GUARD_ALLOW_INSECURE_SECRET=1 or --insecure-secret-env was set)"
                );
                (s, SharedSecretSource::EnvInsecure)
            }
            SharedSecretSource::None => {
                // Unreachable under the release resolution order (resolve without env always returns Keychain); kept for exhaustiveness.
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

    // test-helpers: inject a custom tenant table + secret; unit tests construct without AuditStore/env.
    #[cfg(feature = "test-helpers")]
    pub fn new_with_lookup(tenants: Arc<dyn TenantLookup>, shared_secret: Option<String>) -> Self {
        Self {
            tenants,
            shared_secret,
        }
    }
}

// H-C (product-audit §5): release-build startup gate — refuse to start when both shared-secret sources (Keychain / env) are absent.
// Root cause: PeerAuthorizer::new only warned on a missing secret (dev tolerance), but if a release deployment also omitted it,
// the daemon started anyway with the secret check skipped → peercred (same uid) as the only factor, no second factor; any same-uid process
// (including a compromised subagent) could fully call rule mutations / reversible redact reveal. Prod MUST set the secret explicitly.
// Secret-side fix: the source extends to the Keychain (account shared-secret). env requires FUSION_GUARD_ALLOW_INSECURE_SECRET=1
// opt-in (otherwise treated as unauthorized, no silent downgrade). A present Keychain secret is allowed (the prod-recommended path).
// fg-bin run_server calls this after IpcServer::new: release with both sources missing → Err.
// Dev tests do not call this (tolerating a missing secret avoids changing every test's signature); explicit FUSION_GUARD_ALLOW_NO_SECRET=1 opts in (emergency ops).
// Rule 5: decide with code (Keychain read + env read), not token inference.
pub fn require_shared_secret_for_release() -> std::result::Result<(), String> {
    // dev builds skip (debug_assertions = true) — tolerating a missing secret.
    if cfg!(debug_assertions) {
        return Ok(());
    }
    // Emergency opt-in flag checked first (CI/soak set it): skips the Keychain read — get_generic_password
    // can serially block in non-interactive environments (the CLAUDE.md-documented Keychain hang risk), and CI neither needs nor can read a Keychain secret.
    // Setting this flag = operator-aware peercred-only auth (INSECURE, non-prod), consistent with the load_shared_secret bypass.
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
    // Source 1: env (escape hatch; release requires an explicit flag). Must short-circuit before the Keychain read —
    // SecItemCopyMatching serially blocks under headless/CI (issue #17 class); env+flag is already explicit authorization,
    // yet reading the Keychain first would make the flag useless. Matches resolve_shared_secret semantics (env+flag takes priority over Keychain).
    let env_authorized = shared_secret_env_present() && allow_insecure_secret_flag_set();
    if env_authorized {
        return Ok(());
    }
    // Source 2: Keychain (the macOS prod-recommended path).
    let keychain_has = matches!(keychain_secret_get(), Ok(Some(_)));
    if keychain_has {
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
    // Corresponds to the old handle_conn identity resolution (E6 + P0-1).
    // P2-3 (§3.4): peer_uid is now the three-state PeerUid — separating "syscall failed" from "cross-UID denied" log classes.
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
            // P2-3 (§3.4): distinguish the two denial causes. SyscallFail = syscall failed (not the peer's fault, needs ops diagnosis);
            // Resolved(other_uid) = cross-UID attack/misconnect. Both fail-closed identically, but with distinct logs.
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

    // Corresponds to the old dispatch_arc E6 gate + §12.1 secret check. ping is open to any peer (health probe).
    fn authorize_method(
        &self,
        identity: &CallerIdentity,
        method: &str,
        provided_secret: Option<&str>,
    ) -> AuthDecision {
        // E6: non-ping requires same uid / root.
        if !identity.auth_ok && method != "guard.ping" {
            return AuthDecision::DenyPeercred;
        }
        // §12.1: non-ping validates the shared secret (constant time). Unset secret (dev) skips.
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

// P1-5: extract the secret param from the RpcRequest (the old inline s_param(params, "secret", 99)).
pub fn extract_secret(req: &RpcRequest) -> Option<&str> {
    req.params.get("secret").and_then(|v| v.as_str())
}

// Constant-time byte comparison (prevents timing side-channel leaking secret length/prefix differences). Runs to completion even on length mismatch (no early return).
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
