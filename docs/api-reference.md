---
doc_id: fusion-guard/api-reference
product: fusion-guard
class: platform
entry: service
doc_type: api-reference
title: {zh: "fusion-guard IPC API 参考", en: "fusion-guard IPC API Reference"}
audience: engineer
status: draft
version: 0.2.0-rc.10
updated: 2026-11-07
owner: "@dahai"
source_of_truth:
  - crates/fg-ipc/src/lib.rs
  - crates/fg-core/src/lib.rs
---

# fusion-guard IPC API 参考 / IPC API Reference

Transport: JSON-RPC 2.0 over Unix domain socket. Default socket `/tmp/fusion-guard.sock` (override: `FUSION_GUARD_SOCK`). There is no TCP listener. Params may be passed as a JSON object (named) or a JSON array (positional); named form is shown here. Source of truth for every field below is `crates/fg-ipc/src/lib.rs`.

JSON-RPC framing: 2s call timeout, fail-closed; connection cap 64. Slow methods (`guard.audit.verify`, `guard.cluster.*`) run on a dedicated semaphore so a federated HTTP call cannot starve fast methods (`guard/fg-ipc` — `is_slow_method`).

## Connection / lifecycle

| Method | Params | Returns | Notes |
|---|---|---|---|
| `guard.ping` | — | `{pong: true, ...}` | Liveness roundtrip |

## Action evaluation

### guard.evaluate

Evaluate an action against the rule engine. Returns the serialized `GuardVerdict` (`crates/fg-core`): `action` (`allow` | `preview` | `redact` | `block`), `risk_level`, `reason`, `stage`, `requires_approval`, `redacted_content`, `seatbelt_required`, `action_id`, `verdict_epoch`, `verdict_ttl_secs`, `inferred_category`.

Params:

| Name | Type | Default | Meaning |
|---|---|---|---|
| `content` | string | required | The command / text to evaluate |
| `action` | string | `""` | Action label for audit |
| `requester` | string | required | Calling agent identifier |
| `tenant_id` | string | default tenant | Tenant scope |
| `caller_epoch` | u64 | 0 | Rule epoch the caller holds; `0` = unknown |
| `content_type` | string | `"shell"` | Content type for stage selection |
| `category_hint` | string | — | Optional category hint; inference runs otherwise |

Behavior: stages run in order Regex → AST tokenizer → Semantic (tree-sitter, feature-gated `semantic`). Category is inferred from argv[0] when no hint is given (`shell_exec` / `network` / `file_write`); a caller `category_hint` only raises the risk floor, never lowers it. Verdicts with `requires_approval` carry a one-time `action_id` (UUID v4) with TTL — consume it via `guard.confirm`. L4 risk levels block absolutely — no confirm path. Stale epoch → error `-32003`; pass `caller_epoch: 0` if you do not track epochs. High-risk verdict audit persistence is fail-closed: if the audit write fails, the verdict is refused (C23/H7).

### guard.confirm

Consume a challenge. Params: `action_id` (required), `approved` (bool, default false), `approved_by`, `tenant_id`. One-time consume: a second call with the same `action_id` fails. Both approved and rejected outcomes are audited.

## Rule management

Rules are the SSOT, persisted with an epoch that survives restarts.

| Method | Params | Notes |
|---|---|---|
| `guard.rule.add` | `caller_epoch`, `rule` (object) | Advances epoch |
| `guard.rule.update` | `caller_epoch`, `name`, `rule` | Advances epoch |
| `guard.rule.remove` | `caller_epoch`, `name` | Advances epoch |
| `guard.rule.list` | `caller_epoch` | Current rules + epoch |
| `guard.rules.dump` | — | `{rules, epoch}` snapshot |

Epoch semantics: callers pass their held epoch to `guard.evaluate`; `0` = unknown (accepted, no check). Rule mutation requires admin authorization; non-admin mutations are rejected with `-32001` (same code as unauthorized — the wire does not distinguish, logs do).

## Masking / redaction

| Method | Params | Notes |
|---|---|---|
| `guard.redact` | `content` (required), `reversible` (bool, default false), `tenant_id` | Masks api_key / password / id_number / private_key / email / ipv4 / bank-card |
| `guard.reveal` | `content` (required), `token_map_id`, `tenant_id` | Restores originals from the encrypted token store |
| `guard.redact.patterns.dump` | — | Current masking pattern set |

Irreversible masking cannot be revealed. Reversible masks persist AES-GCM-encrypted in `token.db`; cross-restart reveal works when the master key is available (Keychain on desktop, keyfile in headless mode). If the token store is unreadable, reveal falls back fault-tolerantly (mask remains in place — it does not fail open).

## Audit

| Method | Params | Notes |
|---|---|---|
| `guard.audit` | `trigger_id` (req), `event_type` (req), `target_path`, `target_agent`, `payload`, `node_id`, `tenant_id` | Frozen fusion-event contract (D-10); tri-state pass/block/challenge |
| `guard.audit_result` | `audit_id` (req), `trigger_id`, `decision`, `reason` | Challenge callback receipt |
| `guard.audit.list` | `limit` (default 50, capped 10000), `tenant_id`, `since`, `until`, `event_type`, `level_min`, `cursor` | Paginated query |
| `guard.audit.verify` | — | Hash-chain integrity check (incremental P0-4 + all-chain aggregation P0-5) |

Free-text fields (`requester` / `result` / `reason`) are truncated before persisting; `limit` is hard-capped to prevent full-table scans. Audit records are written to SQLite WAL (`guard.db`) with a sha256 hash chain; rotation archives to NDJSON at 100 MB / 30 days, retention deletes archives after 180 days.

## TCC aggregation

| Method | Params | Notes |
|---|---|---|
| `guard.tcc.status` | — | Aggregated macOS TCC permission status (via Swift bridge) |
| `guard.tcc.report` | `permission` (req), `requester`, `result`, `reason` | Persist an audit record |
| `guard.tcc.events` | `limit` | Query persisted TCC events |

Status-only by design (H1): fusion-guard reads and aggregates, it never brokers or grants TCC permissions.

## Endpoint Security

| Method | Params | Notes |
|---|---|---|
| `guard.es.status` | — | ES subsystem status; honest degraded report without the entitlement |
| `guard.es.events` | `limit` | ES events when active |

Without the Apple ES entitlement the fg-es crate runs as a stub and degrades to TCC-based reporting (Q#3) — `guard.es.status` reports this honestly rather than pretending to be active.

## Cross-node cluster (LAN-only)

All four methods are slow-path (federated HTTP, 5s timeout, fail-closed on non-2xx) and require `FUSION_GUARD_CLUSTER_TOKEN` on both nodes. Fusion-guard is a consumer of the fusion-multi-node contract, not a broker; each host evaluates locally.

| Method | Params | Notes |
|---|---|---|
| `guard.cluster.audit.fetch` | `since_seq` (default 0) | Fetch remote chain segment + local federated verify (HMAC-SHA256 MAC + prev_hash) |
| `guard.cluster.epoch.sync` | — | Compare rule epochs with the leader |
| `guard.cluster.confirm.relay` | `confirm_id` (req), `node_id`, `action`, `epoch` (req), `ts` | MAC-verified confirm relay |
| `guard.cluster.confirm.list` | `epoch` | List relayed confirms |

## Errors

JSON-RPC error codes mapped in `crates/fg-ipc/src/lib.rs` (`err_code`):

| Code | Meaning |
|---|---|
| `-32001` | Unauthorized / forbidden (rule mutation without admin shares this code by design) |
| `-32002` | Rate limited |
| `-32003` | Stale epoch — refresh rules and retry |
| `-32010` | Engine failure |
| `-32600` | Invalid request (JSON-RPC version not 2.0) |
| `-32601` | Method not found |
| `-32602` | Invalid params |
| `-32603` | Internal error |

Error responses follow the JSON-RPC `error` object; the daemon fails closed — on internal failure the verdict is block, not pass.

## Python binding

`crates/fg-pyo3` exposes the same surface in-process: `fusion_guard.NativeGuardClient` (UDS client). Build via `pip install -e .` (maturin, module `fusion_guard._native`). Shared-secret auth between the PyO3 binding and the daemon is the v0.2.0-rc.10 addition (issue #36); see [config-reference.md](config-reference.md) for `FUSION_GUARD_SHARED_SECRET`.
