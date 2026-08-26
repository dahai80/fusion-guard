# fusion-guard

Fusion local AI OS 的零信任动作授权守护进程 (zero-trust action authorization daemon)。拦截 Agent 高风险副作用 (`rm -rf`、静默外发),动态脱敏敏感字段 (API Key、密码、身份证号、私钥),聚合 macOS TCC 权限审计。

**PRD 源**: `/Users/dahai/fusion/architecture/fusion-guard-prd-plan-v2-0826.md` (v0.2)

## 状态

Phase 2 完成, Phase 5 (TCC 审计聚合 + Swift bridge) 完成。9-crate Cargo workspace + UDS JSON-RPC daemon + SQLite WAL 审计 + 规则 SSOT/epoch 持久化。

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
| Stage 2 tokenizer (shell-words, AST 阶段白名单+敏感路径) | ✅ |
| category 推断 (H9: argv[0]→shell_exec/network/file_write) | ✅ |
| seatbelt_required flag (E7: L3+ / Block 标记) | ✅ |
| SENSITIVE_PATHS/WHITELIST 收敛 (含 ~/.config/~/.fusion) | ✅ |
| TCC 状态聚合 (Swift bridge, status-only — H1) | ✅ |
| guard.tcc.report (审计聚合持久化) | ✅ |
| guard.tcc.events (TCC 审计查询) | ✅ |

## 架构

9-crate Rust workspace (对齐 fusion-executor 布局):

```
crates/
├── fg-core           # 核心类型: RiskLevel/SafetyAction/GuardVerdict/GuardError
├── fg-rules          # 规则引擎: regex 阶段 + AST tokenizer 阶段 + epoch + RuleSet + category 推断
├── fg-audit-engine   # 审计引擎: 规则评估 + 脱敏联动 + verdict 合成 + TCC 审计聚合编排
├── fg-redact         # 动态脱敏: api_key/password/id_number/private_key, 可逆/不可逆, placeholder 提取
├── fg-tcc            # TCC 状态聚合 (status-only, 不 brokering — H1) + 事件类型
├── fg-tcc-bridge     # Swift FFI: @_cdecl TCC 状态查询, 编译为 static lib, C stub 兜底 (unsafe allow)
├── fg-ipc            # UDS JSON-RPC server + 2s timeout + 64 conn + rate limit
├── fg-store          # SQLite WAL: 审计 append-only + 规则持久化 + 加密 token store (AES-GCM) + pending action store (H4) + tcc_events
└── fg-bin            # fusion-guard 二进制: start/ping 子命令
```

## 风险等级 (4-tier)

| 级别 | 行为 | 示例 |
|------|------|------|
| L1 | Allow (自主) | 读非敏感文件 |
| L2 | Preview/Redact | 含敏感字段内容 |
| L3 | Gateway 人工确认 | 删除文件、HTTP 请求 |
| L4 | **Block (绝对,无确认路径 — H8)** | `rm -rf` 递归删除 |

## 两级校验 (Stage 1 Regex + Stage 2 Tokenizer)

```
content
  │
  ▼
Stage 1 (Regex, fg-rules::evaluate)
  ├── 命中 blocklist 规则 (rm -rf / curl|sh / sudo / dd / git force-push 等) → 直接 Block (L4)
  └── 未命中 → 进 Stage 2
  │
  ▼
Stage 2 (Tokenizer, fg-rules::tokenizer::tokenize_check, shell-words MVP)
  ├── 命令替换 $(...)/反引号 / 进程替换 <(...) → Block (L3)
  ├── split_chain 按 &&/||/;/|/换行 分段 (尊重单/双引号)
  ├── shell_words::split 每段 → argv[0] basename → WHITELIST 检查
  │     └── 非白名单二进制 (nc/scp/rm 等) → Block (L3, sensitive_target=false)
  ├── argv 敏感路径检查 (mv/cp 目的地 / cat/grep 读源 / tee/chmod/cd 参数 / 重定向目标)
  │     └── 命中 SENSITIVE_PATHS → Block (L4, sensitive_target=true)
  ├── 凭据文件名 (id_rsa / .pem / .key / .p12 / .pfx / .keystore / .htpasswd) → Block (L4)
  ├── .. 路径逃逸 (cat/grep 读源含 .. 组件) → Block (L4)
  └── sed -i / find -exec / git config/-c/alias → Block (L4)
```

**Category 推断 (H9)**: guard 从内容推断 category, 非依赖 caller 声明。argv[0]=rm/sh/dd/diskutil→`shell_exec`, curl/wget/scp/ssh→`network`, 重定向到敏感路径→`file_write`。最终级别 = max(推断, 规则命中, hint)。

**seatbelt_required (E7)**: verdict 对 L3/L4 或 Block 标记 `seatbelt_required:true` (flag, 非 profile 文本)。executor 据此决定是否编译 seatbelt profile。

**收敛源**: SENSITIVE_PATHS/WHITELIST/分词逻辑对齐 `fusion-executor/crates/fe-security` (只读收敛, 扩展 `~/.config`/`~/.fusion` per PRD §7.5)。tree-sitter DEFERRED (PRD §7.4 R5 MVP = shell-words only)。

## TCC 审计聚合 (H1, PRD §9)

guard **不 brokering** TCC — macOS per-app 模型, 各子项目自请求权限。guard 只两件事:
- **状态查询**: `guard.tcc.status` 经 Swift bridge (`@_cdecl` FFI, 编译为 static lib) 查 6 服务 (Accessibility/ScreenRecording/FullDiskAccess/Microphone/Camera/AppleEvents)。Swift 不可用时 C stub 兜底 (`cfg(tcc_bridge_stub)`)。
- **审计聚合**: `guard.tcc.report` 记录各项目 TCC 请求结果到 `tcc_events` 表, `guard.tcc.events` 查询。`source` 字段标记来源 (`swift-bridge:live` / `tccutil:stub`)。

```
子项目自请求 TCC (macOS per-app)
        │  结果上报
        ▼
guard.tcc.report → tcc_events 表 (审计聚合, 非授权)
guard.tcc.status → Swift bridge → 状态 (6 服务)
```

fg-tcc-bridge 是 workspace 唯一 `unsafe_code = "allow"` crate (FFI 必须); fg-tcc 保持 `deny`。Swift 编译失败自动降级 stub, build.rs emit `cargo:rustc-cfg=tcc_bridge_stub`。

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
- `guard.tcc.status` — `{statuses: [TccStatus]}` (Swift bridge, source `swift-bridge:live` 或 `tccutil:stub`)
- `guard.tcc.report` — `{permission, requester, result, reason}` → `{audit_id}` (审计聚合 H1, 各子项目自请求 TCC, guard 只聚合)
- `guard.tcc.events` — `{limit?}` → `{events: [TccEventRecord]}`
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
- **Phase 2** AST 阶段: ✅ Stage 2 tokenizer (shell-words MVP), ✅ category 推断 (H9), ✅ seatbelt_required (E7), ✅ SENSITIVE_PATHS/WHITELIST 收敛
- **Phase 3** fail-closed 本地缓存 + seatbelt 编译内联 (blocked-on-upstream-PR: executor E2)
- **Phase 5** ✅ TCC 审计聚合 (H1) + Swift tcc-bridge (status query, C stub 兜底, 独立 CI lane — E1)
- **Phase 6** agent-studio/studio 集成 (blocked-on-upstream-PR: E2)

## Monorepo 上下文

27 个 `fusion-*` 子项目共享 `/Users/dahai/fusion/.venv`。fusion-guard 是 Rust + Swift 工程, 非 Python。IPC 对齐 monorepo JSON-RPC 2.0 over UDS 契约。详见 `/Users/dahai/fusion/CLAUDE.md`。
