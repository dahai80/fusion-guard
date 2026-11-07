---
doc_id: fusion-guard/architecture
product: fusion-guard
class: platform
entry: service
doc_type: architecture
title: {zh: "fusion-guard 架构", en: "fusion-guard Architecture"}
audience: engineer
status: draft
version: 0.2.0-rc.10
updated: 2026-11-07
owner: "@dahai"
source_of_truth:
  - CLAUDE.md
  - Cargo.toml
  - README.md
---

# fusion-guard 架构 / Architecture

## Overview

A 14-crate Cargo workspace behind a single UDS JSON-RPC daemon, plus a PyO3 binding that exposes the same IPC surface to Python. Layout (aligned with fusion-executor):

```
crates/
├── fg-core           # Core types: RiskLevel / SafetyAction / GuardVerdict / CheckStage(Regex|Ast|Semantic)
├── fg-rules          # Regex stage + AST tokenizer stage + tree-sitter semantic stage (feature=semantic) + epoch + RuleSet
├── fg-audit-engine   # Verdict synthesis + redact coordination + TCC aggregation orchestration
├── fg-redact         # Dynamic masking + reversible/irreversible token store
├── fg-tcc            # TCC status aggregation (status-only) + event types
├── fg-tcc-bridge     # Swift bridge for TCC reads
├── fg-es             # Endpoint Security (stub without entitlement, degrades to TCC)
├── fg-es-bridge      # ES bridge
├── fg-peercred       # UDS peer-credential checks (SO_PEERCRED / LOCAL_PEERCRED)
├── fg-ipc            # UDS JSON-RPC server: 2s timeout fail-closed, 64-conn cap, slow/fast semaphores
├── fg-store          # SQLite WAL stores: guard.db / token.db / action.db + rotation + retention
├── fg-pyo3           # PyO3 binding -> fusion_guard._native / NativeGuardClient
├── fg-cluster        # Cross-node consumer: HKDF key scheme + federated chain verify + HTTP client
└── fg-bin            # Daemon binary (fusion-guard)
```

## Request flow / 请求流

```
caller (agent / service / PyO3 client)
   │  JSON-RPC over UDS (/tmp/fusion-guard.sock)
   ▼
fg-ipc ── peercred check ── rate limit ── slow/fast semaphore split
   ▼
fg-audit-engine
   ├─ fg-rules     stage 1 regex → stage 2 AST tokenizer → stage 3 tree-sitter (feature=semantic)
   ├─ fg-redact    masking coordination for content that carries secrets
   └─ fg-tcc       status aggregation (via fg-tcc-bridge, Swift)
   ▼
verdict { pass | challenge(action_id, TTL) | block }     L4: block, no confirm path
   ▼
fg-store  audit record + sha256 chain hash → guard.db (SQLite WAL)
```

Key properties:

- **Fail-closed**: 2s call timeout; internal errors map to a block verdict, never a pass.
- **Epoch SSOT**: rule mutations advance a persisted epoch; callers pass `caller_epoch` with every evaluate; `0` = unknown. Stale epoch is rejected with `-32003`.
- **Honest degradation**: Endpoint Security without the Apple entitlement reports degraded via `guard.es.status` instead of pretending; TCC is status-only (no brokering, H1).
- **Non-bypassable param handling**: JSON-RPC params are accepted as object or array, and both shapes extract identically — a positional-params caller cannot fall through to empty content and get an L1 pass (fg-ipc §L8/P1).

## Storage / 存储

Physical split into three SQLite WAL databases under `~/.fusion-guard/` (fg-store §A2/P1-7): `guard.db` (audit + chain + rules + tcc + tenant bindings), `token.db` (masking tokens + key versions), `action.db` (pending confirms). The audit chain is sha256 over canonical records; rotation (100 MB / 30 d) archives NDJSON segments; retention deletes archives at 180 days. A dead-letter file beside `guard.db` catches audit events when the queue is full or the store is closing.

## Secrets / 密钥

Master keys come from macOS Keychain on desktop sessions; headless sessions (SSH / CI / no tty, auto-detected or `FUSION_GUARD_HEADLESS=1`) use keyfiles in `~/.fusion-guard/`. Release gate H-C requires an explicit escape hatch (`ALLOW_INSECURE_SECRET` / `--insecure-secret-env`, or `ALLOW_NO_SECRET` for emergency) to run with a weaker source. Cluster tokens are HKDF-SHA256-expanded into 3 domain-separated HMAC keys (audit chain / rule epoch / confirm relay) — never reused across purposes.

## Cluster / 跨节点

fusion-guard is the **consumer** side of the fusion-multi-node contract (fusion-guard issue #4, multi-node#52 → PR #54): multi-node defines transport + identity + key scheme; guard consumes them. Per-host by PRD design — each node evaluates locally and is never a cluster broker. `fg-cluster` fetches remote chain segments and verifies them federated (MAC + prev_hash double tamper detection), syncs rule epochs with the leader, and relays MAC-verified confirms. All transport is local/LAN HTTP with 5s timeout, fail-closed.

## Integration points / 集成点

- **fusion-event**: frozen audit contract D-10 (`guard.audit` tri-state + `guard.audit_result` receipt).
- **fusion-multi-node**: cluster contract consumer (above).
- **fusion-core**: Python-side dependency (`httpx` + fusion-core) for tests and tooling.
- **PyO3 consumers**: `fusion_guard.NativeGuardClient` exposes the IPC surface in-process; shared-secret auth with the daemon since v0.2.0-rc.10 (issue #36).

## Platform notes / 平台约束

- macOS-first: TCC aggregation and Keychain are macOS-specific; the headless keyfile path exists precisely because Keychain serially blocks in non-GUI sessions.
- Rust version >= 1.87 (`Cargo.toml` `rust-version`).
- The semantic stage is compile-time feature-gated (`--features semantic`) because it pulls tree-sitter grammars.
