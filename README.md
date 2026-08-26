# fusion-guard

Fusion local AI OS 的零信任动作授权守护进程 (zero-trust action authorization daemon)。拦截 Agent 高风险副作用 (`rm -rf`、静默外发),动态脱敏敏感字段 (API Key、密码、身份证号、私钥),聚合 macOS TCC 权限审计。

**PRD 源**: `/Users/dahai/fusion/architecture/fusion-guard-prd-plan-v2-0826.md` (v0.2)

## 状态

Phase 0 — 工程骨架已落地。8-crate Cargo workspace + UDS JSON-RPC daemon。

| 验收项 | 状态 |
|--------|------|
| `cargo build` (debug + release) | ✅ |
| `./start.sh start` 起 UDS server | ✅ |
| `guard.ping` roundtrip | ✅ |

## 架构

8-crate Rust workspace (对齐 fusion-executor 布局):

```
crates/
├── fg-core           # 核心类型: RiskLevel/SafetyAction/GuardVerdict/GuardError
├── fg-rules          # 规则引擎: regex 阶段 + epoch + RuleSet
├── fg-audit-engine   # 审计引擎: 规则评估 + 脱敏联动 + verdict 合成
├── fg-redact         # 动态脱敏: api_key/password/id_number/private_key
├── fg-tcc            # TCC 状态聚合 (status-only, 不 brokering — H1)
├── fg-ipc            # UDS JSON-RPC server + 2s timeout + 64 conn + rate limit
├── fg-store          # 审计存储 (Phase 0 in-mem stub; Phase 1 SQLite WAL)
└── fg-bin            # fusion-guard 二进制: start/ping 子命令
```

## 风险等级 (4-tier)

| 级别 | 行为 | 示例 |
|------|------|------|
| L1 | Allow (自主) | 读非敏感文件 |
| L2 | Preview/Redact | 含敏感字段内容 |
| L3 | Gateway 人工确认 | 删除文件、HTTP 请求 |
| L4 | **Block (绝对,无确认路径 — H8)** | `rm -rf` 递归删除 |

## IPC 协议

UDS socket: `/tmp/fusion-guard.sock` (env `FUSION_GUARD_SOCK`)
帧格式: JSON-RPC 2.0 + `0x0A` 分隔, 1MiB 上限, 2s 超时 fail-closed

方法:
- `guard.ping` — `{pong, version, rules_epoch}`
- `guard.evaluate` — `{action, content, caller_epoch?, category_hint?}` → GuardVerdict
- `guard.tcc.status` — `{statuses: [TccStatus]}`
- `guard.audit.list` — `{records: [AuditRecord]}`
- `guard.confirm` / `guard.redact` / `guard.reveal` / `guard.rule.*` — Phase 1+

错误码: `-32700` parse / `-32600` invalid / `-32601` not found / `-32001` unauthorized / `-32002` rate limit / `-32010` internal (BLOCK = `result.action="block"`, 非错误码 — E5)

## 使用

```bash
cargo build --release
./start.sh start    # 启动守护进程
./start.sh status
./start.sh stop
./start.sh log
./start.sh doctor

# ping
./target/release/fusion-guard ping
```

## 开发

```bash
make build    # cargo build
make test     # cargo test
make lint     # clippy + fmt
make check    # lint + test
```

代码规范: 4 空格缩进, 无 docstring, 必带日志, `unsafe_code = "deny"` (workspace lint)。

## 路线图 (PRD §17)

- **Phase 0** ✅ 工程骨架: workspace + 7 crate + start.sh + CI + launchd
- **Phase -1** ⏳ 门控: fusion-security A/B/C 决策 (去/留/分段)
- **Phase 1** 规则收敛: SSOT + epoch, SQLite WAL 审计, encrypted token store
- **Phase 2** AST 阶段: tree-sitter (与 executor 同锁), TOCTOU 防护
- **Phase 3** fail-closed 本地缓存 + seatbelt 编译内联
- **Phase 5** Swift tcc-bridge (status query, 独立 CI lane — E1)

## Monorepo 上下文

27 个 `fusion-*` 子项目共享 `/Users/dahai/fusion/.venv`。fusion-guard 是 Rust + Swift 工程, 非 Python。IPC 对齐 monorepo JSON-RPC 2.0 over UDS 契约。详见 `/Users/dahai/fusion/CLAUDE.md`。
