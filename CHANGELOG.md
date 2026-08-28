# Changelog

All notable changes to fusion-guard are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/), semver versioning.

## [0.1.2] — 2026-08-28 (minor)

Cross-node cluster consumer — closes issue #4 (was upstream-blocked on fusion-multi-node#52, now MERGED via PR #54 commit fa2cb41). fusion-guard implements the **consumer** side of the multi-node contract: multi-node defines TRANSPORT + IDENTITY + KEY SCHEME; guard consumes it. Per-host by PRD design (guard is NOT a cluster broker).

### Added
- **`fg-cluster` crate** (14th crate) — cross-node transport primitives, 100% local/LAN, no cloud:
  - **Key scheme** (`key.rs`): HKDF-SHA256 from `cluster_token` (env `FUSION_GUARD_CLUSTER_TOKEN`) → 3 domain-separated MAC keys, info labels `b"fusion-multinode-audit-chain-v1"` / `b"fusion-multinode-rule-epoch-v1"` / `b"fusion-multinode-confirm-relay-v1"` (KEY_LEN=32, salt=None). `canonical_json` (sorted-keys, compact, `ensure_ascii=False`) for deterministic MAC input. `mac_payload` (HMAC-SHA256→hex), `verify_mac` (constant-time, empty→false). 7 unit tests.
  - **Federated audit-chain verify** (`verify.rs`): each record carries `seq` / `prev_hash` (= sha256 of canonical-full of prior record INCLUDING mac) / `mac` (= HMAC over record MINUS mac). Double tamper detection: field flip → MAC mismatch + next `prev_hash` breaks. Degraded records (missing chain fields) → baseline, skip chain check. `verify_chain_segment` returns `{total_records, verified_links, broken_links, baseline_records, tampered, first_broken_at}`. 4 unit tests.
  - **Multi-node HTTP client** (`client.rs`, `reqwest::blocking` — safe inside `spawn_blocking`): `GET /api/v1/audit/chain?since_seq=N`, `GET /api/v1/rules/epoch`, `POST /api/v1/rules/epoch/advance` (leader-only, non-leader→409 best-effort), `POST /api/confirm` (MAC-verified relay), `GET /api/v1/confirms?epoch=N`. Bearer `cluster_token` auth, 5s timeout, fail-closed on non-2xx.
- **`guard.cluster.*` IPC** (4 methods, `fg-ipc`):
  - `guard.cluster.audit.fetch {since_seq}` — fetch remote chain segment + local federated verify (MAC + prev_hash), returns `{node_id, fetched_at, records, verify}`.
  - `guard.cluster.epoch.sync` — reconcile local vs cluster rule epoch (local>cluster → advance cluster best-effort; local<cluster → `local_behind`; equal → `in_sync`), Checkpoint 2 SSOT extended to cluster domain.
  - `guard.cluster.confirm.relay {confirm_id, node_id, action, epoch, ts}` — relay confirm to master aggregation (builds MAC).
  - `guard.cluster.confirm.list {epoch?}` — query confirm aggregation.
  - Missing `FUSION_GUARD_CLUSTER_TOKEN` (single-node mode) → `-32011` cluster-not-configured, non-silent.
- **Integration tests** (`tests/cluster_integration.rs`, 8 tests) — std-only HTTP mock (no tokio/wiremock, avoids `reqwest::blocking` runtime-drop panic in async context): clean chain verifies, tampered record detected, epoch get/advance, confirm relay MAC interop (bidirectional self-verify), confirm list, single-node-mode `None`, HTTP-error fail-closed.

### Changed
- Workspace version 0.1.1 → 0.1.2 (all 14 crates inherit). `pyproject.toml`, `python/fusion_guard/__init__.py` synced. Workspace members + deps add `fg-cluster`.
- `fg-ipc` depends on `fg-cluster`; `handle_method` (sync, `spawn_blocking`) calls blocking client directly.

### Tests
- 172 tests pass (153 prior + 11 fg-cluster unit + 8 fg-cluster integration), clippy clean, fmt green.

## [0.1.1] — 2026-08-28 (patch)

Patch release: fusion-event audit contract + PII redaction expansion + Python wheel packaging, plus the full P0-P2 audit hardening sweep (22 fixes) that landed between v0.1.0 and this release.

### Added
- **`guard.audit` / `guard.audit_result` IPC** (issues #1/#3, PRD §6.7 / D-10) — frozen fusion-event contract:
  - `guard.audit {trigger_id, event_type, target_path, target_agent, payload, node_id, tenant_id?}` → `{decision: pass|block|challenge, reason, risk_level:int, audit_id, trigger_id}`.
  - Decision mapping: Allow/Redact/Preview → `pass`; Block → `block`; L3 `requires_approval` → `challenge`. `risk_level` = `RiskLevel::rank()` (0..3 int, not enum string).
  - `audit_id` = audit chain row primary key (Uuid); `trigger_id` echoed for request↔reply correlation.
  - `guard.audit_result {audit_id, trigger_id, decision, reason}` — challenge callback receipt (inbound stub, fusion-event not yet running).
  - `AuditEngine::audit_event` method + 4 tests (`audit_event_test.rs`). Live UDS smoke verified.
- **PII redaction expansion** (issue #2) — fg-redact 13→15 patterns: `email` + `ipv4` (+ `valid_ipv4` validator). Placed after credential patterns to preserve conn_string overlap semantics (first-to-reject wins).
- **Python wheel packaging** (issue #5) — `pyproject.toml` (maturin build-backend, `manifest-path = "crates/fg-pyo3/Cargo.toml"`, `module-name = "fusion_guard._native"`) + `python/fusion_guard/__init__.py` re-export wrapper exposing `NativeGuardClient`, `version_info`, etc.

### Changed
- Workspace version 0.1.0 → 0.1.1 (all 13 crates inherit). `Cargo.lock`, `pyproject.toml`, `python/fusion_guard/__init__.py` synced.

### P0-P2 audit hardening sweep (landed pre-v0.1.1, summarized)
- **P0 (release-blockers, G1-G9):** audit chain tamper-evidence single serialized insert path; `fg-es`/`fg-es-bridge` honest degraded Endpoint Security report (no entitlement → TCC fall back); accept-loop decouple (`conn_sem` try_acquire immediate reject, no freeze); peercred tenant binding (wire tenant forced via `tenant_bindings` + `getpeereid`); audit rotation (100MB/30d archive NDJSON + 180d retention + incremental verify with checkpoint anchor); chain coverage (dead-letter HMAC/reimport + `tcc_events` independent chain + `rule_mutations` mutation chain + `verify_all_chains` four-chain aggregate); `spawn_blocking` around handler + confirm double-lock elimination + 4 write connections `busy_timeout=5000`.
- **P1:** DLP pattern expansion 4→13 (JWT/bearer/AWS Secret/credit-card Luhn/phone/GCP/Azure/Stripe/conn-string/.env/.netrc); HKDF key separation (chain-HMAC ≠ token-AES-GCM, versioned rotation, `Arc<AtomicI64>` active version); evaluate `actions().put()` fail-closed (not warn-continue); request-semaphore independent 500ms permit timeout (distinct from 2s handler timeout) + `test-helpers` feature; `Authorizer` trait + `PeerAuthorizer` + minimal `TenantLookup` trait; `guard.audit.list` filters (since/until/event_type/level_min + cursor pagination) + notify channel trimming.
- **P2:** env-key gating (release ignores `FUSION_GUARD_TOKEN_KEY` unless `--insecure-env-key` flag or `FUSION_GUARD_ALLOW_ENV_KEY=1`); peercred three-state `PeerUid` (Resolved/SyscallFail/Unsupported) with syscall-failure → warn; UDS client connection pool (lazy connect + IO-error reconnect retry); `category_hint` param (H9 caller hint as risk floor, `max(inferred,hit,hint)`, L2 cap) + `GuardVerdict.category_hint` serde default; write-path split DB (`audit.db`/`token.db`/`action.db` separate files + own WAL + `ATTACH` confirm_atomic cross-DB transaction).

### Test status
153 tests pass (default features). +11 `feature=semantic` tests. clippy clean (0 warnings). `cargo fmt --all -- --check` green. debug + release build green.

## [0.1.0] — 2026-08-27

Initial release: zero-trust action authorization + DLP firewall daemon.

### Added
- 13-crate Cargo workspace (fg-core/fg-rules/fg-audit-engine/fg-redact/fg-tcc/fg-tcc-bridge/fg-es/fg-es-bridge/fg-peercred/fg-ipc/fg-store/fg-pyo3/fg-bin).
- UDS JSON-RPC daemon (`fusion-guard start`) at `/tmp/fusion-guard.sock`, NDJSON-framed, 2s timeout (H4), 64-conn cap, rate limit.
- Phase 1 Checkpoint 1: SQLite WAL audit store — L3+/Block sync gate (H7, fail-closed), L1-L2 async batch (E4), multi-tenant isolation.
- Phase 1 Checkpoint 2: Rule SSOT + epoch — guard is rule authority, epoch monotonic + persisted, stale-epoch → `-32003`.
- Phase 1 Checkpoint 3: Encrypted token store — AES-GCM reversible redact, Keychain or `FUSION_GUARD_TOKEN_KEY` env key, cross-restart durable.
- Phase 1 Checkpoint 4: `guard.confirm` + action_id — L4 `AbsoluteBlock` (H8, no confirm path), one-time consume (H4), 30s TTL.
- Phase 2 Checkpoint 5: Stage 2 tokenizer (shell-words MVP) + category inference (H9) + seatbelt flag (E7). Two-level校验 (regex + AST).
- Phase 5: TCC audit aggregation (H1) + Swift bridge (`fg-tcc-bridge`, sole `unsafe_code=allow`) + C stub fallback.
- Phase 7: audit chain hash tamper-evidence (PRD §13.3, single serialized insert path); Endpoint Security (`fg-es`/`fg-es-bridge`, entitlement-gated, degrade to TCC); PyO3 binding (`fg-pyo3`, UDS client wrapper, `pyo3 0.29`); tree-sitter Stage 3 semantic (PRD §7.4 R5, `feature=semantic` default off, versions locked to fusion-executor).
