---
doc_id: fusion-guard/get-started
product: fusion-guard
class: platform
entry: service
doc_type: get-started
title: {zh: "fusion-guard 快速开始", en: "fusion-guard Get Started"}
audience: engineer
status: draft
version: 0.2.0-rc.10
updated: 2026-11-07
owner: "@dahai"
source_of_truth:
  - README.md
  - start.sh
  - pyproject.toml
---

# fusion-guard 快速开始 / Get Started

Requirements: macOS (Apple Silicon), Rust toolchain (rustup, rust-version >= 1.87 per `Cargo.toml`), Python >= 3.11 for the PyO3 binding and tests.

## 1. Build the daemon / 构建

```bash
cd fusion-guard
cargo build --release
```

The binary lands at `target/release/fusion-guard`.

## 2. Start the daemon / 启动

```bash
./start.sh start     # launches the UDS JSON-RPC server
./start.sh status    # pid, socket, log path
./start.sh log -f    # tail the log
./start.sh doctor    # health check
./start.sh stop
```

Default socket: `/tmp/fusion-guard.sock` (override with `FUSION_GUARD_SOCK`). The daemon is UDS-only — there is no TCP listener. On SSH / CI / no-tty sessions `start.sh` auto-detects headless mode and skips macOS Keychain reads (keyfile path instead); see [troubleshooting.md](troubleshooting.md).

## 3. Verify with a first call / 首次调用验证

```bash
# ping roundtrip over the socket
echo '{"jsonrpc":"2.0","id":1,"method":"guard.ping"}' | nc -U /tmp/fusion-guard.sock
```

Expected: a JSON-RPC response containing `"pong": true`.

## 4. Evaluate an action / 评估一个动作

```bash
echo '{"jsonrpc":"2.0","id":2,"method":"guard.evaluate","params":{"content":"rm -rf /tmp/demo","content_type":"shell","caller_epoch":0}}' | nc -U /tmp/fusion-guard.sock
```

The verdict carries `action` (`allow` | `preview` | `redact` | `block`) plus `requires_approval`; approval-required verdicts are confirmed within TTL via `guard.confirm` + `action_id`. L4 risk levels block absolutely — there is no confirm path.

## 5. Redact and reveal / 脱敏与还原

```bash
echo '{"jsonrpc":"2.0","id":3,"method":"guard.redact","params":{"text":"api_key=sk-abc123"}}' | nc -U /tmp/fusion-guard.sock
```

Use the returned placeholder with `guard.reveal` to restore the original for an authorized caller. Masked values are persisted encrypted (AES-GCM; Keychain master key on desktop, keyfile in headless mode).

## 6. Python binding (optional) / Python 绑定（可选）

```bash
source ~/fusion/.venv/bin/activate
pip install -e ".[test]"
python -c "from fusion_guard import NativeGuardClient; print(NativeGuardClient().ping())"
```

## 7. Run the tests / 运行测试

```bash
cargo test --workspace
source ~/fusion/.venv/bin/activate && pytest tests/
```

## Next steps / 下一步

- IPC method reference: [api-reference.md](api-reference.md)
- Environment variables and data layout: [config-reference.md](config-reference.md)
- Integrating an agent or service: [guides/agent-integration.md](guides/agent-integration.md)
- When something fails: [troubleshooting.md](troubleshooting.md)
