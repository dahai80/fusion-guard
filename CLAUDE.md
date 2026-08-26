# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Status

**Phase 5 complete (2026-08-27).** Phase 0 + Phase 1 (checkpoints 1-4) + Phase 2 Checkpoint 5 + Phase 5 (TCC audit aggregation + Swift bridge) landed on `main`, pushed to dahai80/fusion-guard. Phases 3/4/6 blocked-on-upstream-PR (E2 — executor/agent-studio/studio integration, issue→PR→land flow). Phase 7 optional.

Landed so far:
- Phase 0: 8-crate Cargo workspace + UDS JSON-RPC daemon + `start.sh` + CI + launchd plist (commit c9cf3cc).
- Phase 1 Checkpoint 1: SQLite WAL audit store — L3+/Block sync gate (H7, fail-closed), L1-L2 async batch (E4), multi-tenant isolation. Cross-restart durable.
- Phase 1 Checkpoint 2: Rule SSOT + epoch — guard is rule authority; epoch monotonically bumps on add/update/remove; rules + epoch persisted to SQLite, survive restart; `caller_epoch != 0 && != guard epoch` → `-32003` stale epoch. IPC: `guard.rule.list/add/update/remove`, `guard.rules.dump`. `guard.evaluate` takes `caller_epoch`.
- Phase 1 Checkpoint 3: Encrypted token store — reversible redact stores original AES-GCM-encrypted to `tokens` table in guard.db; key from macOS Keychain (service `fusion-guard`/account `token-key`) or `FUSION_GUARD_TOKEN_KEY` env hex (32 bytes) for dev/CI. in-flight flag (R3) protects token during reveal; TTL 300s, in-flight exempt. `guard.redact {content, reversible}` → `{redacted_content, token_map_id?}`; `guard.reveal {content, token_map_id}` → `{content}` (restores all `[REDACTED:type#tok_id]` placeholders). H6 fallback: missing/decrypt-failed token → `[REDACTED:unrecoverable#...]`, non-fatal. Cross-restart reveal works (encrypted落盘, key persistent).
- Phase 1 Checkpoint 4: `guard.confirm` + action_id — `guard.evaluate` assigns action_id to L3 (requires_approval) and L4 (Block) verdicts, persists pending action to `pending_actions` table (verdict_json, risk_level, created_ts, consumed, ttl_secs=30). `guard.confirm {action_id, approved, approved_by, tenant_id}` validates: L4 → reject `AbsoluteBlock` (H8, no confirm path); consumed → reject `Consumed` (one-time, H4); expired (created+ttl<now) → reject `Expired`. On valid: mark consumed, approve→`action:Allow`/reason "approved by X", reject→`action:Block`/reason "rejected by X"; appends `confirm` audit event (sync H7, outcome approved/rejected). Returns `{verdict: GuardVerdict}`. H8: L4 `requires_approval` 恒 false, no confirm path.
- Phase 2 Checkpoint 5: Stage 2 tokenizer + category inference + seatbelt flag — `fg-rules::tokenizer` module: `tokenize_check` (CheckStage::Ast) runs after regex; `split_chain` (&&/||/;/|/换行, quote-aware) + `shell_words::split` per segment → argv[0] basename → WHITELIST check → non-whitelist binary → Block L3; argv SENSITIVE_PATHS target check (mv/cp dest, cat/grep read-source, tee/chmod/cd, redirect `>`/`>>` target) → Block L4; credential filename (id_rsa/.pem/.key/.p12/.pfx/.keystore/.htpasswd) → Block L4; `..` escape → Block L4; shell substitution `$(...)`/backtick/process-sub `<(...)`/`<<<` → Block L3; `sed -i`/`find -exec`/`git config`-`-c`-`alias.` → Block L4. `RuleEngine::evaluate_full` merges regex + tokenizer hits (regex-only `evaluate` preserved for unit tests). `RuleEngine::infer_category` (H9): argv[0]=rm/sh/dd/diskutil→`shell_exec`, curl/wget/scp/ssh→`network`, redirect-to-sensitive→`file_write`; guard infers from content, caller is hint only. `verdict_from_hits` sets `seatbelt_required=true` for L3/L4 or Block (E7 — flag not profile text). SENSITIVE_PATHS extended with `~/.config`/`~/.fusion` (PRD §7.5). Convergence source: `fusion-executor/crates/fe-security` (read-only copy). tree-sitter DEFERRED per PRD §7.4 R5 (MVP = shell-words).
- Phase 5: TCC audit aggregation (H1, PRD §9) + Swift bridge — guard does NOT broker TCC (macOS per-app model; each subproject self-requests). guard does two things: (1) `guard.tcc.status` queries 6 services (Accessibility/ScreenRecording/FullDiskAccess/Microphone/Camera/AppleEvents) via Swift bridge `@_cdecl` FFI compiled to static lib (`fg-tcc-bridge`, the workspace's only `unsafe_code = "allow"` crate; `fg-tcc` stays `deny`); Swift unavailable → C stub fallback (`cfg(tcc_bridge_stub)`, build.rs emits via `cargo:rustc-cfg`). `source` field tags `swift-bridge:live` vs `tccutil:stub`. (2) `guard.tcc.report {permission, requester, result, reason}` persists TCC request result to `tcc_events` table (audit aggregation only, not authorization) → `{audit_id}`; `guard.tcc.events {limit?}` queries. fg-store adds `report_tcc_event`/`list_tcc_events` + `TccEventRecord` + `tcc_events` table + indexes. fg-tcc adds `TccService` enum (`as_str`/`parse`), `TccStatus`, `TccEvent`, `query_status`. build.rs uses `std::env::var` (runtime, not `env!` compile-time); links ApplicationServices/CoreGraphics/AVFoundation/Foundation frameworks on live path. **CRITICAL**: tests must set `FUSION_GUARD_TOKEN_KEY` env (hex, 32 bytes) or `AuditStore::open` → `TokenStore::load_or_create_key` → macOS Keychain `SecItemCopyMatching` BLOCKS (hangs 60s+ in non-interactive env). `ensure_env_key()` helper in store_test.rs/tcc_store_test.rs.

Verification: `cargo build` (debug+release) pass, `cargo test` 60 pass (10 rule + 21 tokenizer + 3 store + 2 tcc_store + 6 token + 6 redact + 6 action + 6 tcc), clippy clean (0 warning). Runtime smoke (isolated FUSION_GUARD_DATA_DIR+SOCK+TOKEN_KEY): `guard.tcc.status`→6 services, source `swift-bridge:live`, real authorized states (Camera/AppleEvents=false, rest=true); `guard.tcc.report`→audit_id persisted; `guard.tcc.events`→retrieves by audit_id, all fields intact.

The product contract lives in the monorepo PRD: `/Users/dahai/fusion/fusion-guard-prd-plan-v2-0826.md` (v0.2 — the implementation spec; supersedes the v0.1 audit target at `architecture/fusion-guard-prd-0826.md`). Read it before any implementation work; it is the single source of truth for scope, mechanism, and API shape.

## Crate Layout (landed)

```
crates/
├── fg-core           # RiskLevel/SafetyAction/CheckStage/RuleScope/GuardVerdict/GuardError (core types)
├── fg-rules          # regex-stage rule engine + Stage 2 tokenizer (AST): mutable add/update/remove + epoch bump + stale-epoch check + RuleSet + category inference
├── fg-audit-engine   # verdict synthesis + redact联动 + rule persistence + TCC audit aggregation orchestration (owns Arc<AuditStore>)
├── fg-redact         # dynamic masking: api_key/password/id_number/private_key, reversible/irreversible, placeholder extraction
├── fg-tcc            # TCC status aggregation (status-only, no brokering — H1) + TccService/TccStatus/TccEvent types
├── fg-tcc-bridge     # Swift FFI: @_cdecl TCC status queries, compiled to static lib via build.rs, C stub fallback (only crate with unsafe_code=allow)
├── fg-ipc            # UDS JSON-RPC server: 2s timeout fail-closed, 64 conn, rate limit; guard.evaluate/rule.*/tcc.status/tcc.report/tcc.events/audit/redact/reveal/confirm
├── fg-store          # SQLite WAL: audit_events append-only + rules/rule_meta + encrypted token store (AES-GCM) + pending action store (H4) + tcc_events table
└── fg-bin            # fusion-guard binary: start/ping subcommands
```

Workspace lint: `unsafe_code = "deny"` (fg-tcc-bridge is the sole `allow` — FFI requires it; fg-tcc stays deny). Workspace-level `[workspace.lints.rust] unexpected_cfgs = { level = "allow", check-cfg = ['cfg(tcc_bridge_stub)'] }` for the stub cfg.

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

## Confirm + action_id (Checkpoint 4 contract)

- `guard.evaluate` assigns `action_id` (Uuid v4) to verdicts where `requires_approval || action==Block` (i.e. L3 and L4), and persists the verdict to `pending_actions` table (action_id PK, verdict_json, risk_level, created_ts, consumed=0, ttl_secs=30).
- `guard.confirm {action_id, approved:bool, approved_by, tenant_id?}` → `{verdict: GuardVerdict}`:
  - **H8**: L4 verdict → reject `AbsoluteBlock` (L4 = absolute BLOCK, `requires_approval` 恒 false, no confirm path).
  - **H4 one-time**: already-consumed action_id → reject `Consumed` (no replay).
  - **H4 TTL**: `created_ts + ttl_secs < now` → reject `Expired` (verdict valid 30s, re-evaluate after).
  - Valid: mark `consumed=1`, mutate verdict — `approved` → `action:Allow`, reason "approved by X"; `!approved` → `action:Block`, reason "rejected by X"; `requires_approval=false`.
  - Appends `confirm` audit event (event_type="confirm", sync gate H7, outcome approved/rejected).
- Pending action store is its own Connection to guard.db. `evict_expired` called on each confirm.
- L4 confirm rejection is the **only** path that errors (other rejections also surface as `-32010` but with distinct messages); callers parse the returned verdict's `action` for allow/block (E5).

## Stage 2 Tokenizer + Category Inference + seatbelt (Checkpoint 5 contract)

- Two-level校验 (PRD §7.1): Stage 1 = regex blocklist (fast BLOCK, `RuleEngine::evaluate`, CheckStage::Regex); Stage 2 = tokenizer (AST, `tokenize_check`, CheckStage::Ast) runs after. `RuleEngine::evaluate_full` merges both → `verdict_from_hits` picks max risk.
- Tokenizer (PRD §7.4 R5, MVP = shell-words; tree-sitter DEFERRED):
  - `check_shell_substitution`: `$(...)`/backtick/`<(...)`/`<<<` → Block L3.
  - `split_chain` splits on `&&`/`||`/`;`/`|`/`\n`/`\r` quote-aware (single/double). Each segment → `shell_words::split`.
  - Skip env-var prefix (`FOO=bar`), basename(argv[0]) → `WHITELIST` check. Non-whitelist binary (`nc`/`scp`/`rm`/...) → Block L3 (`sensitive_target=false`).
  - `check_argv` per-binary: `mv`/`cp` dest sensitive → L4; `sed -i` → L4; `find -exec`/`-execdir`/`-ok`/`-delete` → L4; `tee`/`chmod`/`cd` arg sensitive → L4; `cat`/`grep`/`head`/`tail`/`less`/`more`/`bat`/`rg` read-source sensitive OR credential-filename OR `..` escape → L4; `git config`/`-c`/`alias.`/`core.` → L4.
  - `check_redirect_target`: `>`/`>>` target in SENSITIVE_PATHS → L4.
  - `is_sensitive_filename`: `id_rsa` (not `.pub`), `.pem`/`.key`/`.p12`/`.pfx`/`.keystore`/`.htpasswd`.
- Category inference (PRD §6.3 H9): guard infers category from **content**, not caller declaration. `RuleEngine::infer_category`: argv[0]=`rm`/`sh`/`bash`/`zsh`/`dd`/`diskutil`/`mkfs`/`chmod`/`chown`/`kill`/`killall`→`shell_exec`; `curl`/`wget`/`scp`/`rsync`/`nc`/`ssh`/`ftp`/`sftp`→`network`; redirect `>`/`>>` to SENSITIVE_PATHS→`file_write`. AuditEngine.evaluate overrides `inferred_category` only when verdict is "clean" (regex/AST hit keeps rule-name category).
- seatbelt_required (PRD E7): `verdict_from_hits` sets `seatbelt_required=true` when `risk_level ∈ {L3,L4}` OR `action==Block`. Flag only — guard does NOT emit seatbelt profile text (that's executor-side Phase 3).
- SENSITIVE_PATHS (PRD §7.5): converged from `fusion-executor/crates/fe-security` (read-only), extended with `~/.config` + `~/.fusion`. WHITELIST (~70 binaries) converged same source. Do NOT modify fe-security — upstream changes flow via issue→PR→land.
- `evaluate` (regex-only) preserved for unit-test stability; production path (`AuditEngine.evaluate` → `evaluate_full`) always runs both stages.

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
