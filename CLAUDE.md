# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Status

**Phase 0 landed (2026-08-26).** 8-crate Cargo workspace + UDS JSON-RPC daemon committed to `main` (commit c9cf3cc), pushed to dahai80/fusion-guard. Verification: `cargo build` (debug+release) pass, `./start.sh start` runs UDS server, `guard.ping` roundtrip returns `{pong, version, rules_epoch}`.

The product contract lives in the monorepo PRD: `/Users/dahai/fusion/fusion-guard-prd-plan-v2-0826.md` (v0.2 — the implementation spec; supersedes the v0.1 audit target at `architecture/fusion-guard-prd-0826.md`). Read it before any implementation work; it is the single source of truth for scope, mechanism, and API shape.

## Crate Layout (landed)

```
crates/
├── fg-core           # RiskLevel/SafetyAction/GuardVerdict/GuardError (core types)
├── fg-rules          # regex-stage rule engine + epoch + RuleSet
├── fg-audit-engine   # verdict synthesis + redact联动
├── fg-redact         # dynamic masking: api_key/password/id_number/private_key
├── fg-tcc            # TCC status aggregation (status-only, no brokering — H1)
├── fg-ipc            # UDS JSON-RPC server: 2s timeout fail-closed, 64 conn, rate limit
├── fg-store          # audit store (Phase 0 in-mem stub; Phase 1 → SQLite WAL)
└── fg-bin            # fusion-guard binary: start/ping subcommands
```

Workspace lint: `unsafe_code = "deny"` (peercred impl deferred to Phase 1 via nix crate with scoped allow).

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
