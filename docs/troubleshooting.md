---
doc_id: fusion-guard/troubleshooting
product: fusion-guard
class: platform
entry: service
doc_type: troubleshooting
title: {zh: "fusion-guard 故障排查", en: "fusion-guard Troubleshooting"}
audience: engineer
status: draft
version: 0.2.0-rc.10
updated: 2026-11-07
owner: "@dahai"
source_of_truth:
  - start.sh
  - CLAUDE.md
  - crates/fg-ipc/src/lib.rs
---

# fusion-guard 故障排查 / Troubleshooting

## Daemon will not start

**"binary missing, build first"** — `start.sh` looks for `target/release/fusion-guard`. Run `cargo build --release` and retry. Check `./start.sh status` afterwards.

**"socket ... not registered in port-registry.yaml"** — `start.sh` refuses to serve on an unregistered socket (start self-check, issue #33). Either the registry entry for fusion-guard is missing in `architecture/port-registry.yaml`, or `FUSION_GUARD_SOCK` points somewhere other than the registered path. Fix the registry or match the registered socket. Standalone deploys without the fusion tree can set `FUSION_SKIP_REGISTRY_CHECK=1`; the missing-registry case only warns.

**"address already in use" on bind** — a stale socket file from a crash. `start.sh start` clears it automatically when no PID file exists; if a PID file exists but the process is dead, `./start.sh stop` then `./start.sh start`.

**Daemon hangs on startup in SSH / CI** — macOS Keychain reads (`SecItemCopyMatching`) block serially in non-GUI sessions. Headless mode is auto-detected (no tty, or `SSH_CONNECTION` set); if detection is wrong, force it with `FUSION_GUARD_HEADLESS=1`. In headless mode the token store uses the keyfile path (`~/.fusion-guard/token-key`).

**Secret-source release gate refuses startup (H-C)** — the daemon requires a real secret source. For dev/emergency only: `ALLOW_INSECURE_SECRET=1` (or `--insecure-secret-env`) permits an insecure source; `ALLOW_NO_SECRET=1` starts with none. Both are explicit escape hatches — do not bake them into service environments.

## Call fails or returns an error

**`-32003` stale epoch** — your caller holds an old rule epoch. Re-read via `guard.rule.list` / `guard.rules.dump`, pass the returned `epoch` as `caller_epoch`, or pass `0` (unknown) if you do not track epochs.

**`-32001` on `guard.rule.add/update/remove`** — rule mutation requires admin authorization. Non-admin mutations intentionally share the unauthorized code on the wire (anti-enumeration); the log line distinguishes ("forbidden: rule mutation requires admin").

**`-32002` rate limited** — the connection semaphore is exhausted. Slow methods (`guard.audit.verify`, `guard.cluster.*`) hold slots up to 5s; batch cluster calls instead of looping.

**`-32602` invalid params** — params arrived as neither a complete object nor a complete positional array. Named form is recommended; see [api-reference.md](api-reference.md) for each method's field list.

**Call times out (2s)** — the JSON-RPC timeout is 2s, fail-closed. If you see this on `guard.evaluate` with heavy content, reduce content size; the semantic stage is the most expensive and is feature-gated.

## Verdict behavior

**Expected a block but got a pass** — check that `content` actually carries the payload (empty content passes L1 by design), and that `content_type` matches the content (the AST stage only applies to shell-like content). Category inference runs from argv[0]; a wrong `category_hint` changes the rule set applied.

**Got a challenge but the `action_id` is dead** — action_id is one-time with TTL; a second `guard.confirm` with the same id fails even if the first was approved. Re-run `guard.evaluate` for a fresh id.

**`guard.confirm` outcome not visible** — approved and rejected outcomes are both audited; query `guard.audit.list` with the `trigger_id`.

## Masking / reveal

**`guard.reveal` returns the mask instead of the original** — the token store could not be read. On desktop, check Keychain access for the terminal/daemon; in headless mode, check that `~/.fusion-guard/token-key` matches the one used when redacting. Fault-tolerant fallback keeps the mask in place — reveal never fails open.

**Cross-restart reveal fails** — the master key changed between redact and reveal (e.g. different `FUSION_GUARD_TOKEN_KEY`, or desktop Keychain vs headless keyfile across restarts). Keep one source per machine.

**Irreversible mask cannot be restored** — by design: `guard.redact` with `reversible: false` stores nothing to reveal.

## Audit / storage

**Audit counts look short** — check the dead-letter file beside `guard.db` (written when the queue is full or the store is closing) and the daemon log for write errors.

**`guard.db` grew large** — rotation archives the oldest segment at 100 MB or 30 days into `~/.fusion-guard/audit-archive/` as NDJSON; archives are deleted after 180 days. Verify `FUSION_GUARD_ARCHIVE_DIR` points where you expect.

**`guard.audit.verify` reports broken links** — the hash chain detected tampering or a corrupted segment. Investigate before trusting the archive; degraded records (missing chain fields) are counted as baseline and skipped.

## Cluster

**Cluster methods fail immediately** — they need `FUSION_GUARD_CLUSTER_TOKEN` on both nodes and LAN HTTP reachability (5s timeout, fail-closed on non-2xx). Non-leader epoch advance returns 409 by design.

**Federated verify reports tampered** — a record failed both its HMAC and the next record's `prev_hash` check, or only one of the two. Fetch the segment and compare `first_broken_at` with the remote node's audit log.

## Diagnostics checklist

```bash
./start.sh status                 # pid, socket, log path
./start.sh doctor                 # health check
./start.sh log -f                 # tail daemon log
ls -la ~/.fusion-guard/           # data files, keyfiles, dead-letter
echo '{"jsonrpc":"2.0","id":1,"method":"guard.ping"}' | nc -U /tmp/fusion-guard.sock
```

Log location: `~/.fusion-guard/logs/fusion-guard.log` (override: `FUSION_GUARD_LOG_DIR`).
