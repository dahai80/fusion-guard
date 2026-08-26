# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Status

**Phase 1 in progress (2026-08-26).** Phase 0 + Phase 1 checkpoints 1-2 landed on `main`, pushed to dahai80/fusion-guard.

Landed so far:
- Phase 0: 8-crate Cargo workspace + UDS JSON-RPC daemon + `start.sh` + CI + launchd plist (commit c9cf3cc).
- Phase 1 Checkpoint 1: SQLite WAL audit store — L3+/Block sync gate (H7, fail-closed), L1-L2 async batch (E4), multi-tenant isolation. Cross-restart durable.
- Phase 1 Checkpoint 2: Rule SSOT + epoch — guard is rule authority; epoch monotonically bumps on add/update/remove; rules + epoch persisted to SQLite, survive restart; `caller_epoch != 0 && != guard epoch` → `-32003` stale epoch. IPC: `guard.rule.list/add/update/remove`, `guard.rules.dump`. `guard.evaluate` takes `caller_epoch`.
- Phase 1 Checkpoint 3: Encrypted token store — reversible redact stores original AES-GCM-encrypted to `tokens` table in guard.db; key from macOS Keychain (service `fusion-guard`/account `token-key`) or `FUSION_GUARD_TOKEN_KEY` env hex (32 bytes) for dev/CI. in-flight flag (R3) protects token during reveal; TTL 300s, in-flight exempt. `guard.redact {content, reversible}` → `{redacted_content, token_map_id?}`; `guard.reveal {content, token_map_id}` → `{content}` (restores all `[REDACTED:type#tok_id]` placeholders). H6 fallback: missing/decrypt-failed token → `[REDACTED:unrecoverable#...]`, non-fatal. Cross-restart reveal works (encrypted落盘, key persistent).

Verification: `cargo build` (debug+release) pass, `cargo test` 25 pass (10 rule + 3 store + 6 token + 6 redact), clippy clean. Runtime smoke: redact reversible → reveal restores original; cross-restart reveal (stop → start → reveal) restores; H6 fallback on missing token.

The product contract lives in the monorepo PRD: `/Users/dahai/fusion/fusion-guard-prd-plan-v2-0826.md` (v0.2 — the implementation spec; supersedes the v0.1 audit target at `architecture/fusion-guard-prd-0826.md`). Read it before any implementation work; it is the single source of truth for scope, mechanism, and API shape.

## Crate Layout (landed)

```
crates/
├── fg-core           # RiskLevel/SafetyAction/CheckStage/RuleScope/GuardVerdict/GuardError (core types)
├── fg-rules          # regex-stage rule engine: mutable add/update/remove + epoch bump + stale-epoch check + RuleSet
├── fg-audit-engine   # verdict synthesis + redact联动 + rule persistence (owns Arc<AuditStore>)
├── fg-redact         # dynamic masking: api_key/password/id_number/private_key, reversible/irreversible, placeholder extraction
├── fg-tcc            # TCC status aggregation (status-only, no brokering — H1)
├── fg-ipc            # UDS JSON-RPC server: 2s timeout fail-closed, 64 conn, rate limit; guard.evaluate/rule.*/tcc/audit/redact/reveal
├── fg-store          # SQLite WAL: audit_events append-only + rules/rule_meta persistence + encrypted token store (AES-GCM, Keychain/env key)
└── fg-bin            # fusion-guard binary: start/ping subcommands
```

Workspace lint: `unsafe_code = "deny"` (peercred impl deferred to Phase 1 via nix crate with scoped allow).

## Rule SSOT + Epoch (Checkpoint 2 contract)

- guard holds the authoritative `RuleSet` (epoch + compiled rules). `RuleEngine` is `Arc<RwLock<Inner>>` (cloneable, shared across IPC conns).
- Epoch starts at 1 (default ruleset) and **monotonically increments** on every `add_rule`/`update_rule`/`remove_rule`. Never resets on restart — persisted to `rule_meta.epoch`.
- Rules persist to `rules` table (name PK, rule_json). `AuditEngine::new` bootstraps from store if rules exist, else seeds default + saves.
- Callers pass `caller_epoch` to `guard.evaluate`. Semantics: `0` = unknown (skip check); any other value must equal guard's current epoch or → `GuardError::StaleEpoch` → IPC `-32003`. This forces callers to refetch rules after any change.
- `guard.rule.list` / `guard.rules.dump` return `{rules, epoch}`. Mutation methods return `{new_epoch}` — callers must store the returned epoch for subsequent calls.

## Encrypted Token Store (Checkpoint 3 contract)

- Reversible redact (`guard.redact {content, reversible:true}`): each sensitive match → `[REDACTED:type#tok_<uuid>]` placeholder; original AES-256-GCM encrypted + stored in `tokens` table (guard.db). Returns `token_map_id` = first token id.
- Irreversible redact (`reversible:false`): `[REDACTED:type#last4]`, original discarded.
- `guard.reveal {content, token_map_id}` → `{content}`: scans content for all `[REDACTED:type#tok_id]` placeholders, decrypts each, restores. **H6 fallback**: token missing/decrypt-fail → `[REDACTED:unrecoverable#<prefix>]`, non-fatal (never blocks flow).
- **R3 in-flight**: token marked in_flight during reveal, LRU/TTL evict skips in-flight. TTL 300s default.
- Key: macOS Keychain `get_generic_password("fusion-guard","token-key")` (prod); `FUSION_GUARD_TOKEN_KEY` env (hex, 32 bytes) for dev/CI (skips Keychain prompt). Key auto-generated on first start if absent.
- Cross-restart: tokens encrypted to guard.db (not memory), survive restart as long as key persists (Keychain/env).
- Token store is its own Connection to guard.db (avoids lock contention with audit writer).

## What This Is

`fusion-guard` is the security firewall and Data Loss Prevention (DLP) engine of the Fusion local AI OS. It enforces **zero-trust action authorization** on the Agent side: intercepts high-risk side-effects (e.g. `rm -rf`, silent network exfiltration), dynamically masks sensitive fields (API keys, passwords, ID numbers, private keys), and brokers macOS TCC permission requests (Accessibility, Screen Recording, Full Disk Access) with unified audit.

It sits in the **Governance & Context layer** of the monorepo alongside `fusion-memory` and `fusion-rag`, sitting above the Infrastructure Engine (`fusion-core`/`fusion-store`/`fusion-gateway`/`fusion-mlx`) and below the Agent/event layer (`fusion-event`/`fusion-executor`).

## Business Boundaries (from PRD)

**In-Scope:**
- Agent high-risk instruction / CLI command interception with secondary human confirmation
- Dynamic masking of sensitive fields (API Key, password, ID number, private key)
- macOS TCC permission request brokering (Accessibility, Screen Recording, Disk Access) and unified audit

**Out-of-Scope** (belong to other projects — do not pull into fusion-guard):
- DOM hidden injection filtering → `fusion-browser`
- LLM hallucination alignment → `fusion-mlx` inference sampling control

## Planned Tech Stack

| Module | Choice | Reason |
|--------|--------|--------|
| Core language | Rust + Swift Bridge | Safe memory + native macOS TCC/Security API calls |
| Sandbox | macOS App Sandbox + Seatbelt `sandbox.sb` policy | OS-level process isolation, hard constraints |
| Rule engine | Regular Expressions + AST Pattern Matcher | High-speed scan of sensitive chars/tokens in commands and context |

This is a **Rust + Swift** project (not a Python one). Nearest monorepo patterns to mirror when scaffolding: `fusion-cli` (Rust single-binary build via `cargo build --release`) and `fusion-studio`'s Swift `Services/env-daemon` (Swift/Rust bridge, SPM). When code lands, prefer the `fusion-cli` build layout for the Rust audit engine and a small Swift crate/binary for the TCC bridge.

## Core Mechanism (from PRD)

```
Agent Side-Effect Execution
        │  intercept via UDS (Unix Domain Socket)
        ▼
fusion-guard Audit Engine
        ├── Risk Level 1-2 (Normal/Read, e.g. read non-sensitive file) → direct Pass
        └── Risk Level 3-4 (High Risk, e.g. delete file, HTTP request) → User Challenge (modal re-auth)
```

Key contract points future code must honor:
- **Interception transport:** UDS — same IPC family as `fusion-studio` ↔ Python services (JSON-RPC 2.0 over UDS). Keep the wire format consistent with the rest of the monorepo unless the PRD dictates otherwise.
- **Risk levels:** 4-tier (1-2 pass-through, 3-4 human challenge). The rule engine (regex + AST pattern matcher) assigns levels.
- **Masking is dynamic:** sensitive fields are redacted in-transit, not at rest.

## When Code Lands

Since this is greenfield, the first implementation task should establish the build/test skeleton. Use the monorepo conventions from the root `CLAUDE.md`:
- Rust: `cargo build --release`, `cargo test`, single binary named `fusion-guard` (follow `fusion-cli`'s `[project.scripts]`-equivalent — a `[[bin]]` target).
- Activate the shared venv before any mixed Rust+Swift tooling that shells out to Python: `cd /Users/dahai/fusion && source .venv/bin/activate`.
- Code style per root rules: 4-space-multiple indentation, **no docstrings**, always include logging.
- IPC between fusion-guard and the rest of Fusion uses JSON-RPC 2.0 over Unix Domain Socket — match the existing monorepo wire contract.

## Monorepo Context

This project is one of 27 `fusion-*` sub-projects sharing a single `.venv/` at `/Users/dahai/fusion/.venv`. There is no top-level build system; each sub-project is built and tested independently. See `/Users/dahai/fusion/CLAUDE.md` for the full monorepo layout, environment setup, and cross-project relationships (`architecture/Architecture.md`, `architecture/PROJECT_RELATIONSHIPS.md`).

When fusion-guard must call into the inference engine or other services, do so over the monorepo's standard transports — never vendor a copy of another project's code. Run fusion-mlx via `~/claude-home/fusion-mlx/start.sh start|stop` if integration tests need a live model server.
