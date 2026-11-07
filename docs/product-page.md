---
doc_id: fusion-guard/product-page
product: fusion-guard
class: platform
entry: service
doc_type: product-page
title: {zh: "fusion-guard 产品页", en: "fusion-guard Product Page"}
audience: engineer
status: draft
version: 0.2.0-rc.10
updated: 2026-11-07
owner: "@dahai"
source_of_truth:
  - README.md
  - CLAUDE.md
  - crates/fg-bin/src/main.rs
---

# fusion-guard 产品页 / Product Page

| | |
|---|---|
| Product | fusion-guard |
| Class | platform |
| Entry | service (UDS JSON-RPC daemon) |
| Version | 0.2.0-rc.10 |
| Language | Rust (14-crate workspace) + Python binding (PyO3) |

## What it is / 它是什么

fusion-guard is a zero-trust action authorization daemon for the Fusion local AI OS. It runs as a local daemon exposing JSON-RPC over a Unix domain socket, and answers three questions for any agent side-effect:

1. May this action run? (rule evaluation, risk levels, confirm/block)
2. Does its output leak secrets? (dynamic field masking)
3. Which macOS permissions were touched? (TCC audit aggregation)

fusion-guard 是 Fusion 本地 AI OS 的零信任动作授权守护进程，以本地 daemon 形式运行，通过 Unix domain socket 暴露 JSON-RPC，回答三个问题：该动作是否允许执行（规则评估/风险分级/确认拦截）、输出是否泄露敏感字段（动态脱敏）、触发了哪些 macOS 权限（TCC 审计聚合）。

## What consumers no longer have to do / 消费方不再需要做什么

Before fusion-guard, every agent or tool executor had to implement its own ad-hoc blocklist, redact sensitive strings with hand-written regexes, and hope someone audited macOS permission prompts. With fusion-guard as the platform service, consumers call one IPC surface and get all three:

- **No per-agent blocklists.** Consumers send `guard.evaluate` with the command; the daemon returns a verdict (`allow` / `preview` / `redact` / `block`, with a confirmation path for approval-required cases) from the shared rule set. Consumers no longer maintain their own risky-command lists. Constraint: the rule set is per-host by design — fusion-guard is not a cluster broker, multi-node deployments sync epochs via `guard.cluster.*` but each node evaluates locally.
- **No hand-rolled redaction.** `guard.redact` masks api_key / password / id_number / private_key / email / ipv4 / bank-card values with reversible or irreversible placeholders; `guard.reveal` restores them for authorized callers. Consumers no longer write or audit their own masking regexes. Constraint: masking is string-level; it does not parse arbitrary binary formats.
- **No silent exfiltration path.** L4 risk levels are absolutely blocked with no confirm path, and audit records are written to a hash-chained SQLite WAL store so tampering is detectable via `guard.audit.verify`. Consumers no longer need to invent their own audit trails. Constraint: audit chain verification is per-host; federated verification of remote segments requires the cluster token.
- **No bespoke permission polling.** TCC status aggregation and the event log are queryable over IPC (`guard.tcc.status`, `guard.tcc.events`), so consumers no longer shell out to `sqlite3` against the TCC database themselves. Constraint: TCC access is status-only via a Swift bridge — fusion-guard does not broker or grant permissions.

## Key capabilities / 核心能力

| Capability | IPC | Consumer benefit | Constraint |
|---|---|---|---|
| Action verdicts | `guard.evaluate`, `guard.confirm` | Tri-state pass/challenge/block with one-time action_id | Requires confirmation within TTL; stale epoch rejected |
| Rule management | `guard.rule.add/list/remove/update`, `guard.rules.dump` | Epoch-persisted rule SSOT, no restart needed | Epoch must be refreshed by callers |
| Dynamic masking | `guard.redact`, `guard.reveal`, `guard.redact.patterns.dump` | Encrypted token store, cross-restart reveal | Reveal needs the token key (Keychain or keyfile) |
| Audit chain | `guard.audit`, `guard.audit.list`, `guard.audit.verify` | Tamper-evident hash chain, rotation + retention | Chain is append-only; archive is NDJSON |
| TCC aggregation | `guard.tcc.status`, `guard.tcc.report`, `guard.tcc.events` | One query instead of per-app polling | Status-only, no brokering |
| Endpoint Security | `guard.es.status`, `guard.es.events` | Honest degraded reporting without entitlement | Stub without ES entitlement; degrades to TCC |
| Cross-node cluster | `guard.cluster.audit.fetch`, `guard.cluster.epoch.sync`, `guard.cluster.confirm.relay`, `guard.cluster.confirm.list` | LAN-only federated verify + relay | HMAC-keyed via `FUSION_GUARD_CLUSTER_TOKEN`; no cloud |

## Interfaces / 接入方式

- **UDS JSON-RPC**: default socket `/tmp/fusion-guard.sock` (override with `FUSION_GUARD_SOCK`). See [api-reference.md](api-reference.md).
- **Python binding**: `pip install -e .` builds `fusion_guard._native` (PyO3); `NativeGuardClient` exposes the same methods in-process. See [guides/agent-integration.md](guides/agent-integration.md).
- **Lifecycle**: `./start.sh start|stop|status|log|doctor`. There is no TCP listener — the daemon is UDS-only.

## What it is not / 边界

- Not a sandbox: it advises and audits; OS-level enforcement (seatbelt) is flagged via `seatbelt_required` for the caller to apply.
- Not a cluster broker: per-host by design; cluster methods only relay and verify.
- Not a TCC broker: it aggregates status, it does not grant permissions.

## Status / 状态

Phase 2 / 5 / 7 complete; current release v0.2.0-rc.10 (release candidate, 2026-11-03). Acceptance matrix and per-phase history live in [README.md](../README.md); release history in [CHANGELOG.md](../CHANGELOG.md).
