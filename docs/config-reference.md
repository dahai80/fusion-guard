---
doc_id: fusion-guard/config-reference
product: fusion-guard
class: platform
entry: service
doc_type: config-reference
title: {zh: "fusion-guard 配置参考", en: "fusion-guard Configuration Reference"}
audience: engineer
status: draft
version: 0.2.0-rc.10
updated: 2026-11-07
owner: "@dahai"
source_of_truth:
  - start.sh
  - crates/fg-bin/src/main.rs
  - crates/fg-store/src/lib.rs
---

# fusion-guard 配置参考 / Configuration Reference

fusion-guard has no config file — behavior is controlled by environment variables and command-line flags, with defaults resolved at startup. Everything below is sourced from `start.sh`, `crates/fg-bin/src/main.rs`, and `crates/fg-store/src/lib.rs`.

## Environment variables

### Socket and paths

| Variable | Default | Meaning |
|---|---|---|
| `FUSION_GUARD_SOCK` | `/tmp/fusion-guard.sock` | UDS JSON-RPC socket path (start.sh + daemon both read it) |
| `FUSION_GUARD_DATA_DIR` | `~/.fusion-guard` | Root of the runtime data directory |
| `FUSION_GUARD_LOG_DIR` | `~/.fusion-guard/logs` | Daemon log directory |
| `FUSION_GUARD_ARCHIVE_DIR` | `~/.fusion-guard/audit-archive` | Audit rotation archive (NDJSON) |
| `FUSION_REGISTRY` | `~/fusion/architecture/port-registry.yaml` | Registry file checked by start.sh before serving |

### Secrets and key management

| Variable | Default | Meaning |
|---|---|---|
| `FUSION_GUARD_TOKEN_KEY` | Keychain (desktop) / keyfile | Master key for the reversible-masking token store (AES-GCM). Set only when overriding Keychain |
| `FUSION_GUARD_SHARED_SECRET` | — | Shared secret between the PyO3 binding and the daemon (issue #36); falls back to macOS Keychain |
| `ALLOW_INSECURE_SECRET` | unset | Release-gate escape hatch (H-C): allows an insecure secret source; also `--insecure-secret-env` |
| `ALLOW_NO_SECRET` | unset | Emergency startup with no secret source at all — dev/emergency only |

Headless environments (SSH / CI / no tty) skip the Keychain automatically (issue #17) and use the keyfile path instead. Keyfiles live in `~/.fusion-guard/` (`token-key`, `shared-secret`). Never set real secret values in committed files.

### Operation

| Variable | Default | Meaning |
|---|---|---|
| `FUSION_GUARD_HEADLESS` | auto-detected | `1` forces headless mode (skip Keychain); explicit value wins over heuristics |
| `FUSION_GUARD_CLUSTER_TOKEN` | — | Cross-node cluster token; HKDF-SHA256 derives 3 domain-separated MAC keys from it |
| `FUSION_SKIP_REGISTRY_CHECK` | unset | `1` bypasses the start.sh port-registry self-check (standalone deploys) |

## Daemon flags

From `crates/fg-bin/src/main.rs`: `--sock` / `--log-dir` mirror `FUSION_GUARD_SOCK` / `FUSION_GUARD_LOG_DIR`; `--insecure-secret-env` mirrors `ALLOW_INSECURE_SECRET`.

## start.sh commands

```bash
./start.sh start|stop|status|log|doctor
```

`start` refuses to serve if the socket is not registered in `architecture/port-registry.yaml` (fusion-guard is UDS-only, so its registry entry carries `sock:` not a port). A stale socket left by a crash is cleared before bind. `log` tails `~/.fusion-guard/logs/fusion-guard.log`; `doctor` runs the health check.

## Data layout / 数据布局

All under `~/.fusion-guard/` (physical store split per `crates/fg-store/src/lib.rs`):

| Path | Contents |
|---|---|
| `guard.db` (+ `-wal`/`-shm`) | Audit events, hash chain, rules, TCC records, tenant bindings, checkpoint |
| `token.db` (+ WAL) | Reversible-masking tokens + key versions (TokenStore exclusive) |
| `action.db` (+ WAL) | Pending actions / confirms |
| `token-key`, `shared-secret` | Keyfiles (headless mode) |
| `rules-cache.json` | Rule cache snapshot |
| `logs/` | Daemon logs |
| `audit-archive/` | Rotated audit segments (NDJSON) |
| `run/fusion-guard.pid` | PID file |

Maintenance facts: `guard.db` archives its oldest segment at 100 MB or 30 days (whichever triggers first); archived segments are deleted after 180 days retention. Dead-letter audit events are written next to `guard.db` when the queue is full or the store is closing — check that file if audit counts look short.

## launchd

`com.fusion-mlx.guard.plist` + `install-launchd.sh` register the daemon with launchd for auto-start; use only on desktop sessions with GUI (Keychain path). For SSH/CI nodes, prefer `start.sh` (auto-headless) over launchd.
