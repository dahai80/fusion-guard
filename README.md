# fusion-guard

Fusion local AI OS 的零信任动作授权守护进程 (zero-trust action authorization daemon)。拦截 Agent 高风险副作用 (`rm -rf`、静默外发),动态脱敏敏感字段 (API Key、密码、身份证号、私钥),聚合 macOS TCC 权限审计。

**PRD 源**: `/Users/dahai/fusion/architecture/fusion-guard-prd-plan-v2-0826.md` (v0.2)

## 状态

Phase 1 进行中。8-crate Cargo workspace + UDS JSON-RPC daemon + SQLite WAL 审计 + 规则 SSOT/epoch 持久化。

| 验收项 | 状态 |
|--------|------|
| `cargo build` (debug + release) | ✅ |
| `./start.sh start` 起 UDS server | ✅ |
| `guard.ping` roundtrip | ✅ |
| SQLite WAL 审计 (L3+ 同步 / L1-L2 异步) | ✅ |
| 规则 SSOT + epoch 持久化 (跨重启) | ✅ |
| stale epoch 拒绝 (-32003) | ✅ |
| 加密 token store (AES-GCM + Keychain/env 密钥) | ✅ |
| guard.redact / guard.reveal 往返还原 | ✅ |
| 跨重启 reveal (加密落盘 H6) | ✅ |
| reveal 容错回退 (H6) | ✅ |
| guard.confirm + action_id 一次性兑现 (H4 TTL) | ✅ |
| L4 绝对拦截无 confirm 路径 (H8) | ✅ |
| confirm 审计 (approved/rejected) | ✅ |

## 架构

8-crate Rust workspace (对齐 fusion-executor 布局):

```
crates/
├── fg-core           # 核心类型: RiskLevel/SafetyAction/GuardVerdict/GuardError
├── fg-rules          # 规则引擎: regex 阶段 + epoch + RuleSet
├── fg-audit-engine   # 审计引擎: 规则评估 + 脱敏联动 + verdict 合成
├── fg-redact         # 动态脱敏: api_key/password/id_number/private_key, 可逆/不可逆, placeholder 提取
├── fg-tcc            # TCC 状态聚合 (status-only, 不 brokering — H1)
├── fg-ipc            # UDS JSON-RPC server + 2s timeout + 64 conn + rate limit
├── fg-store          # SQLite WAL: 审计 append-only + 规则持久化 + 加密 token store (AES-GCM) + pending action store (H4)
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
- `guard.evaluate` — `{action, content, caller_epoch?, tenant_id?, requester?}` → GuardVerdict (caller_epoch != 0 且 != guard epoch → `-32003` stale epoch)
- `guard.rule.list` — `{rules: [GuardRule], epoch}`
- `guard.rules.dump` — `{rules, epoch}` (同 rule.list)
- `guard.rule.add` — `{rule: GuardRule}` → `{new_epoch}`
- `guard.rule.update` — `{name, rule}` → `{new_epoch}`
- `guard.rule.remove` — `{name}` → `{new_epoch}`
- `guard.tcc.status` — `{statuses: [TccStatus]}`
- `guard.audit.list` — `{tenant_id?, limit?}` → `{records: [AuditRecord]}`
- `guard.redact` — `{content, reversible:bool}` → `{redacted_content, token_map_id?}` (可逆: token AES-GCM 加密落盘, in-flight 标记 R3; 不可逆: `[REDACTED:type#last4]`)
- `guard.reveal` — `{content, token_map_id}` → `{content}` (还原; token 丢失回退 `[REDACTED:unrecoverable#...]` H6)
- `guard.confirm` — `{action_id, approved:bool, approved_by?, tenant_id?}` → `{verdict: GuardVerdict}` (L3 人机确认; L4 拒绝 H8; action_id 一次性兑现 H4; TTL 30s 过期拒绝; approve→Allow, reject→Block)

GuardRule 字段: `name, pattern, stage(Regex|Ast|Semantic), action(Allow|Preview|Redact|Block), risk_level(L1-L4), reason, scope(Command|Content|Network|Filesystem)`

规则 SSOT: guard 是规则权威源, epoch 单调递增。caller 持 caller_epoch, 规则变更后 guard 拒绝 stale epoch。规则持久化到 SQLite, 跨重启不丢失。

错误码: `-32700` parse / `-32600` invalid / `-32601` not found / `-32001` unauthorized / `-32002` rate limit / `-32003` stale epoch / `-32010` internal (BLOCK = `result.action="block"`, 非错误码 — E5)

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

- **Phase 0** ✅ 工程骨架: workspace + 8 crate + start.sh + CI + launchd
- **Phase -1** ✅ 门控: fusion-security 决策 A (只收敛重叠能力, SAST 独立保留) — issue #23
- **Phase 1** 规则收敛: ✅ SSOT + epoch + 持久化, ✅ SQLite WAL 审计, ✅ encrypted token store (redact/reveal), ✅ confirm + action_id (H4/H8)
- **Phase 2** AST 阶段: tree-sitter (与 executor 同锁), TOCTOU 防护
- **Phase 3** fail-closed 本地缓存 + seatbelt 编译内联
- **Phase 5** Swift tcc-bridge (status query, 独立 CI lane — E1)

## Monorepo 上下文

27 个 `fusion-*` 子项目共享 `/Users/dahai/fusion/.venv`。fusion-guard 是 Rust + Swift 工程, 非 Python。IPC 对齐 monorepo JSON-RPC 2.0 over UDS 契约。详见 `/Users/dahai/fusion/CLAUDE.md`。
