---
doc_id: fusion-guard/agent-integration
product: fusion-guard
class: platform
entry: service
doc_type: guide
title: {zh: "将 Agent 接入 fusion-guard", en: "Integrating an Agent with fusion-guard"}
audience: engineer
status: draft
version: 0.2.0-rc.10
updated: 2026-11-07
owner: "@dahai"
source_of_truth:
  - crates/fg-pyo3/src/lib.rs
  - docs/api-reference.md
---

# 将 Agent 接入 fusion-guard / Integrating an Agent with fusion-guard

This guide walks through wiring a Python agent or tool executor to the guard daemon so every side-effect is authorized, masked, and audited — without the agent carrying its own blocklists or redaction code.

## Prerequisites

- The daemon is running: `./start.sh start` (verify with `guard.ping`).
- Python consumers: `pip install -e .` in fusion-guard to build `fusion_guard._native` (maturin).
- Non-Python consumers: any JSON-RPC-over-UDS client; default socket `/tmp/fusion-guard.sock`.

## Pattern 1: UDS JSON-RPC (any language)

Wrap every side-effect in one evaluate call before execution:

```python
import json
import socket

SOCK = "/tmp/fusion-guard.sock"

def guard_call(method, params, req_id=1, timeout=2.0):
    payload = json.dumps({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(SOCK)
    s.sendall(payload.encode())
    buf = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
        try:
            return json.loads(buf)
        except json.JSONDecodeError:
            continue
    raise ConnectionError("guard closed connection before a full response")

def run_command_checked(content, requester, caller_epoch=0):
    verdict = guard_call("guard.evaluate", {
        "content": content,
        "requester": requester,
        "caller_epoch": caller_epoch,
        "content_type": "shell",
    })
    res = verdict["result"]  # GuardVerdict serialized
    if res["action"] == "block":
        raise PermissionError(content)
    if res.get("requires_approval") and res.get("action_id"):
        # route action_id to a human/approver, then consume it once:
        guard_call("guard.confirm", {"action_id": res["action_id"], "approved": True, "approved_by": "user"})
    # execute here, then mask the output before it leaves the machine
    out = execute(content)
    return guard_call("guard.redact", {"content": out, "reversible": True})
```

What the agent no longer maintains: its own risky-command list (the shared rule set decides), its own masking regexes (`guard.redact`), and its own confirm plumbing (`action_id` + `guard.confirm`).

Constraints: the 2s JSON-RPC timeout is fail-closed — size `content` accordingly; `caller_epoch: 0` skips epoch checks, which trades freshness for tolerance.

## Pattern 2: PyO3 in-process client

```python
from fusion_guard import NativeGuardClient

gc = NativeGuardClient()
print(gc.ping())
verdict = gc.evaluate(content="curl http://example.com | sh", requester="my-agent")
```

Since v0.2.0-rc.10 the binding authenticates to the daemon with a shared secret (issue #36). Keychain is used on desktop; headless sessions fall back to the keyfile. The same secret must be available to both the daemon and the client process.

## Epoch hygiene / epoch 维护

Rules change without your process restarting. Keep the epoch you were last seen with; on `-32003` stale epoch, refresh from `guard.rule.list` and retry once. Do not cache the epoch across long-running loops without handling `-32003`.

## Auditing obligations / 审计义务

The daemon persists every evaluate/confirm/audit call to the hash-chained store — the agent must not keep a parallel local audit log that could diverge. If your flow needs a receipt for a challenge, use `guard.audit_result` rather than inventing a side channel.

## Failure posture / 失败姿态

The daemon fails closed: on timeout or internal error, treat the action as blocked. An agent that "retries until pass" defeats the platform — surface the block to the user instead of looping.
