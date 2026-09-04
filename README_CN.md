# fusion-guard

[English](README.md) | 中文

Fusion local AI OS 的零信任动作授权守护进程 (zero-trust action authorization daemon)。拦截 Agent 高风险副作用 (`rm -rf`、静默外发),动态脱敏敏感字段 (API Key、密码、身份证号、私钥),聚合 macOS TCC 权限审计。

**PRD 源**: `/Users/dahai/fusion/architecture/fusion-guard-prd-plan-v2-0826.md` (v0.2)

## 状态

Phase 2 完成, Phase 5 (TCC 审计聚合 + Swift bridge) 完成, Phase 7 (审计链式 hash + PyO3 + Endpoint Security + tree-sitter 语义阶段) 完成。14-crate Cargo workspace + UDS JSON-RPC daemon + SQLite WAL 审计 + 规则 SSOT/epoch 持久化。当前版本 **v0.2.0-rc.2** (H-E 主密钥丢失 vs 真篡改区分 + pong:bool 契约修复 + 7/7 上游集成 issue 全闭合, 代码级 production-ready)。

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
| 审计链式 hash 防篡改 (PRD §13.3) | ✅ |
| guard.audit.verify (链完整性校验, 增量 P0-4 + 全链聚合 P0-5) | ✅ |
| 审计 rotation (100MB/30d 归档 NDJSON) + retention (180d 删归档) | ✅ |
| Stage 3 tree-sitter 语义阶段 (feature=semantic, 多 grammar 代码扫描) | ✅ |
| PyO3 绑定 fg-pyo3 (UDS 客户端暴露 Python, 对齐 fe-pyo3) | ✅ |
| Endpoint Security fg-es (stub 降级, 无 entitlement → TCC — Q#3) | ✅ |
| guard.es.status / guard.es.events (IPC 暴露, 如实回 degraded — P0-7) | ✅ |
| guard.audit (fusion-event 冻结契约 D-10, pass/block/challenge 三态) | ✅ |
| guard.audit_result (challenge 回调回执) | ✅ |
| PII 脱敏扩展 (email/ipv4/银行卡, issue #2) | ✅ |
| Python wheel 打包 (maturin pyproject.toml, issue #5) | ✅ |
| 跨节点集群消费方 fg-cluster (HKDF 域分离 3 MAC key + federated 链验证, issue #4 / multi-nodes#52) | ✅ |
| guard.cluster.audit.fetch / epoch.sync / confirm.relay / confirm.list (4 IPC) | ✅ |
| shared secret macOS Keychain 来源 + release gate H-C (--insecure-secret-env / ALLOW_INSECURE_SECRET, ALLOW_NO_SECRET 应急) | ✅ |

## 架构

14-crate Rust workspace (对齐 fusion-executor 布局):

```
crates/
├── fg-core           # 核心类型: RiskLevel/SafetyAction/GuardVerdict/GuardError/CheckStage(Regex|Ast|Semantic)
├── fg-rules          # 规则引擎: regex 阶段 + AST tokenizer 阶段 + Stage 3 tree-sitter 语义阶段 (feature=semantic) + epoch + RuleSet + category 推断
├── fg-audit-engine   # 审计引擎: 规则评估 + 脱敏联动 + verdict 合成 + TCC 审计聚合编排
├── fg-redact         # 动态脱敏: api_key/password/id_number/private_key, 可逆/不可逆, placeholder 提取
├── fg-tcc            # TCC 状态聚合 (status-only, 不 brokering — H1) + 事件类型
├── fg-tcc-bridge     # Swift FFI: @_cdecl TCC 状态查询, 编译为 static lib, C stub 兜底 (unsafe allow)
├── fg-es             # Endpoint Security 高危系统事件监控 (安全类型 + 降级状态, unsafe deny)
├── fg-es-bridge      # ES C FFI 桥: 无 entitlement → C stub 兜底 (cfg(es_bridge_stub), degraded → TCC — PRD Q#3), unsafe allow
├── fg-ipc            # UDS JSON-RPC server + 2s timeout + 64 conn + rate limit
├── fg-store          # SQLite WAL: 审计 append-only (链式 hash) + 规则持久化 + 加密 token store (AES-GCM) + pending action store (H4) + tcc_events
├── fg-pyo3           # PyO3 绑定: UDS JSON-RPC 客户端暴露 Python (NativeGuardClient), maturin 目标, 对齐 fe-pyo3 (cdylib+rlib)
├── fg-cluster        # 跨节点消费方 (issue #4 / multi-nodes#52): HKDF 域分离 3 MAC key + federated 链验证 (MAC+prev_hash 双重篡改检出) + reqwest::blocking HTTP 客户端 (5s, Bearer, fail-closed); per-host 非 broker
└── fg-bin            # fusion-guard 二进制: start/ping 子命令
```

## 跨节点集群消费方 (issue #4 / multi-nodes#52, PRD §4.1/§8.2)

fusion-multi-node 定义 TRANSPORT + IDENTITY + KEY SCHEME (PR #54 MERGED); fusion-guard 实现**消费方** (per-host, 非 broker)。100% 本地/LAN, 无云。

- **密钥方案** (`fg-cluster::key`): HKDF-SHA256 从 `cluster_token` (env `FUSION_GUARD_CLUSTER_TOKEN`) 域分离派生 3 个 MAC 密钥, info label `b"fusion-multinode-{audit-chain,rule-epoch,confirm-relay}-v1"` (KEY_LEN=32, salt=None)。`canonical_json` (排序键 + compact + `ensure_ascii=False`) 保 MAC 输入确定性。`mac_payload` (HMAC-SHA256→hex), `verify_mac` (常量时间, 空→false)。
- **原语 1 — federated 审计链验证** (`fg-cluster::verify`): 每记录带 `seq` / `prev_hash` (= 含 mac 的完整前序记录 sha256) / `mac` (= HMAC over 记录减 mac)。双重篡改检出: 字段翻转→MAC 不匹配 + 下条 prev_hash 断链。降级记录 (缺链字段) → 基线跳过。`verify_chain_segment` → `{total_records, verified_links, broken_links, baseline_records, tampered, first_broken_at}`。
- **原语 2 — 集群规则纪元 reconcile**: `guard.cluster.epoch.sync` — local>cluster→推进集群纪元对齐 (leader-only, 非 leader 409 best-effort); local<cluster→`local_behind`; equal→`in_sync`。Checkpoint 2 SSOT 扩展集群域。
- **原语 3 — confirm 中继聚合**: `guard.cluster.confirm.relay` 构 MAC 中继到 master; `guard.cluster.confirm.list` 查聚合。
- **IPC**: `guard.cluster.audit.fetch {since_seq}` / `epoch.sync` / `confirm.relay` / `confirm.list`。无 `FUSION_GUARD_CLUSTER_TOKEN` (单节点) → `-32011` cluster-not-configured, 非静默。
- **HTTP 客户端**: `reqwest::blocking` (handle_method 跑 spawn_blocking 独立线程, 非 tokio worker, 阻塞 IO 安全), 5s 超时, Bearer `cluster_token` 鉴权, 非 2xx fail-closed。

## Stage 3 语义阶段 (tree-sitter, PRD §7.4 R5)

`feature = "semantic"` 启用 (默认关, MVP 仅 shell-words — PRD "需时再引且锁版本")。代码内容 (非命令) 经 tree-sitter 多 grammar 扫描危险调用:

```
content (代码)
  │
  ▼
semantic_check (fg-rules::semantic, feature=semantic)
  ├── Python grammar (tree-sitter-python 0.23): os.system/subprocess.*/eval/exec/__import__/pickle.loads → L4/L3
  ├── JavaScript grammar (tree-sitter-javascript 0.23): eval/Function/child_process.exec → L3/L4
  ├── TypeScript grammar (tree-sitter-typescript 0.23): 同 JS
  └── Rust grammar (tree-sitter-rust 0.23): Command::new/remove_dir_all → L4
  │
  ▼
evaluate_full 合并: regex (Stage 1) + tokenizer (Stage 2) + semantic (Stage 3) → max risk verdict
```

- **版本锁**: tree-sitter 0.25 + grammars 0.23, 与 `fusion-executor` workspace 同 Cargo.lock 段 (PRD §7.4 防 grammar 漂移)。
- **默认关**: `default = []`。启用: `cargo build -p fg-bin --features semantic --release`。透传链 fg-bin → fg-audit-engine → fg-rules/semantic。
- **CheckStage::Semantic**: 命中 verdict `stage=Semantic`, `inferred_category=semantic:<lang>:<callee>`, `scope=Content`。

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

**收敛源**: SENSITIVE_PATHS/WHITELIST/分词逻辑对齐 `fusion-executor/crates/fe-security` (只读收敛, 扩展 `~/.config`/`~/.fusion` per PRD §7.5)。tree-sitter Stage 3 语义阶段已落地 (feature=semantic, 见上文 §Stage 3); MVP 命令扫描仍用 shell-words (Stage 2)。

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

## 审计链式 hash 防篡改 (PRD §13.3)

每条审计事件带链式 hash (前一条 `event_hash` 入下一条 `prev_hash`), 防止审计行被事后篡改/删除:

```
event_1: prev_hash=genesis(000…0),  event_hash=SHA256(genesis || payload_1)
event_2: prev_hash=event_hash_1,    event_hash=SHA256(event_hash_1 || payload_2)
event_3: prev_hash=event_hash_2,    event_hash=SHA256(event_hash_2 || payload_3)
```

- **payload** = 11 字段 (`audit_id/ts/event_type/tenant_id/requester/action/inferred_category/verdict_json/approved_by/seatbelt_required/outcome`) 用 `\x1f` 连接。改任一字段 → `event_hash` 对不上 → 检出。
- **单连接序列化**: 所有审计插入 (同步高风险 + 异步低风险) 走同一 `Arc<Mutex<Connection>>`, 插入时锁内读上一条 `event_hash` → 算本条 hash。消除并发读 prev_hash 导致的链分叉。
- **`guard.audit.verify`**: 增量校验 (P0-4) — `chain_checkpoint` 缓存上次校验通过的末行 `audit_id`+`event_hash`, 本调用只验该行之后的新增段, O(新增量) 而非 O(全表)。锚点用 `audit_id` (UUID, VACUUM 后 rowid 重排不失效)。退化条件 (安全起见全表扫): 无 checkpoint; 锚行已被归档删除 (audit_id 缺失); hash 对不上; 检出篡改 (重算全表以定位 `first_broken_at`, 不缓存坏点)。返回 `{total_rows, unhashed_rows, verified_links, broken_links, tampered, first_broken_at, key_version_unknown_rows}` (聚合 `verify_all_chains` 另增 `key_loss` + 各子链结果)。`key_version_unknown_rows`/`key_loss` 见下 §H-E。
- **迁移兼容**: 老 DB 无 `prev_hash`/`event_hash` 列 → `migrate_audit_chain` 幂等 `ALTER TABLE ADD COLUMN`(DEFAULT '')。空 hash 行计为 `unhashed_rows`, 不误报 tamper。append-only, 不回填历史行。
- **依赖**: `sha2 = "0.10"` (workspace dep)。

### Rotation / Retention / 增量校验 (P0-4, PRD §13.3)

审计库体积随事件增长线性膨胀, 无界增长会拖慢 verify + 耗尽磁盘。治理分三段:

- **Rotation (归档触发)**: `enforce_retention` 在每次审计写后调用。触发条件二选一: DB 体积 > `ROTATE_BYTES` (100MB) 或 存在 `ts < now - ROTATE_AGE_DAYS` (30d) 的旧行。触发 → 超龄旧行导出到 NDJSON 归档文件 (`<archive_dir>/audit-YYYYMMDDTHHMMSS.ndjson`, 0o600), 单事务删行 + `VACUUM` 回收页。归档文件含完整链字段 (prev_hash/event_hash), 跨归档可独立重算校验。
- **Retention (冷存到期)**: 同次扫描归档目录, 文件名时间戳超 `RETENTION_DAYS` (180d) 的 `.ndjson` 删除 (按文件名非 mtime — mtime 可被 touch/cp 篡改)。生产归档目录 `~/.fusion-guard/audit-archive/` (env `FUSION_GUARD_ARCHIVE_DIR` 覆盖)。
- **归档边界链连续**: 归档后剩余首行的 `prev_hash` 指向已归档行 (主库内悬空)。全表 verify 会误报 broken → 故归档后写 checkpoint 锚定剩余首行 (走增量, 跳过悬空段)。空库归档态 (全段已归档删): checkpoint 用空 `last_verified_audit_id` 哨兵 + `last_archived_hash`, verify 从归档段末 hash 作 `expected_prev` 续扫; 下次插入也读 `last_archived_hash` 作 `prev_hash` (续链非 genesis)。
- **per-store 归档目录**: 非全局 env — `resolve_archive_dir(db_path)` 从 db 同级 `audit-archive/` 解析 (env 覆盖仍优先)。隔离并发测试 store 不抢同一 env; 生产单守护进程单 DB 单归档目录语义不变。
- **Retention monitor (drain 路径覆盖)**: `enforce_retention` 原只在高风险 `append_event` 同步路径调, drain 线程只插 L1/L2 低风险行不触 rotation → 高频低风险流量下 audit_events 无界增长。守护进程启动 `spawn_retention_monitor(interval_secs=5)` 周期调 `enforce_retention` 覆盖低风险积累 (商用阻塞点 #6 soak 发现)。
- **rotate 锁优化**: `rotate_old_rows` 检查阶段 (COUNT 超龄行 + db_bytes 判阈值) + 选待归档行改用 `read_conn` (query_only, 不抢 `audit_writer` 写锁), 仅删行 + checkpoint + VACUUM mutate 段锁 `audit_writer`。原实现整段持写锁跑空检查 → append_event 高风险同步路径自 DoS + 5s monitor 持锁空查吞吐骤降。30s soak: throughput +24%, p99 −20ms。TOCTOU 安全: rowid 单调增, 删按 rowid 区间, 并发插入不受影响。

### H-E: 主密钥丢失单点致命 (product-audit-0827, 2026-08-29)

master key 丢失 = 全历史审计链 verify 失败 (假报篡改) + 可逆 token 不可解, 与真篡改不可区分。四项修复:

- **(a) 拒绝静默 remint**: Keychain miss + DB 已有历史数据 → `load_keychain_or_err` 拒启动明确报错 (非静默重生成新密钥令历史全不可解), 仅 virgin DB 首次允许生成。
- **(b) 密钥托管 escrow**: 首次生成后立即导 Keychain master 到离线备份, 丢失时恢复**同一**密钥 → 锚点匹配 → 无假篡改 (运维流程, 见 `DEPLOYMENT.md` §主密钥托管, 无 daemon 代码)。
- **(c) `rotate_key` 历史行可验 (无 re-hash)**: `rotate_key` = bump `key_version` (master 不变, HKDF 按 version 派生)。旧行记旧 version, 用旧派生 key 验 (确定性 HKDF 同 master 可重算) → 轮换后历史行可验可解。**re-hash 审计链被刻意拒绝**: hash 不可变 = 防篡改保证, re-sign 等于自废武功且无法区分真篡改与运维 re-hash。
- **(d) 密钥丢失 vs 真篡改区分**: per-version `key_versions.key_anchor` 锚点 (HMAC of 固定消息 under `derive_chain_key(master, version)`)。verify HMAC 不匹配行调 `classify_break`: 锚点与当前 master 重算**匹配** → 真篡改 (`tampered=true`); **不匹配** → 密钥丢失 (`key_version_unknown_rows++`, 不计 tampered); **NULL** (legacy) → fail-closed 篡改 (攻击者清锚点无藏身处)。`guard.audit.verify` 增 `key_version_unknown_rows` (单链) + `key_loss` (聚合) 字段。测试 `he_key_loss_distinguish_test.rs` (4 cases) + `he_key_loss_test.rs` (5 decision-gate cases)。

## 安全审计修复 (audit-0827)

依据 `audit/fusion-guard-audit-0827.md` (静态对抗性审查, 判定 NO-BLOCK → 修复后重审) 分三波落地。所有缺陷 (P0 发版阻断 + P1 第一 sprint + P2 技术债) 已修复, `cargo build`/`cargo test`/`cargo clippy` 全绿。

### P0 — 发版阻断 (9 组)

- **鉴权基线 (E6/C1/C2 + P0-1)**: `accept` 后 `getpeereid` (macOS) / `SO_PEERCRED` (Linux) 取对端 uid, 非 daemon uid 拒所有非 ping 方法; **peercred→tenant 绑定** (`tenant_bindings` 表 uid→授权租户集合): wire `tenant_id` 须在 caller 授权集合内 (非 admin 跨租户 → -32001), `audit.list`/`audit.verify`/`evaluate`/`redact`/`reveal`/`confirm` 全部强制 tenant gate, verify 加 `tenant_id` 作用域 (斩跨租户行数外泄); 非 ping 请求校验共享 secret (`FUSION_GUARD_SHARED_SECRET`, 常量时间比较); macOS 改 `getpeereid` 因 Darwin 25 `LOCAL_PEERCRED` 实测回 len=4 cr_uid=0 (内核不再填 xucred)。
- **fail-closed (D/C16/C23/L1/M10)**: 规则加载失败/返空 → 拒启动非降级; `save_rule`/`save_epoch` 失败回滚内存 + 返错; 高风险审计写失败返错拒 evaluate (非 continue); 种子持久化失败拒启动。
- **审计链 HMAC (C6/C7/C8)**: HMAC-SHA256(key, payload) 替裸 SHA-256, key 与 token-key 同源; 空 event_hash 列为 tampered 非兼容; payload 改 length-prefixed 编码消 `\x1f` 碰撞; 单序列化写入路径防链分叉。
- **审计治理 P0-4 (audit §1.3/§6)**: rotation (DB>100MB 或 旧行>30d → 归档 NDJSON + 删行 + VACUUM) + retention (归档文件名时间戳>180d 删) + 增量 verify (`chain_checkpoint` 缓存 audit_id+hash 锚点, O(新增量) 非全表; VACUUM 稳定 audit_id 锚点; 归档边界 checkpoint 锚剩余首行避悬空误报; 空库归档态空哨兵+last_archived_hash 续链非 genesis)。
- **审计覆盖面 P0-5 (audit §1.4)**: 死信文件加 per-row HMAC 链 (prev_hmac‖hmac, 同 token-key) + reimport 路径 (全量预验签 → 通过则导回 audit_events 续主链 + 清空死信文件, 任一行篡改/断裂 → 中止不部分导入); `tcc_events` 加独立链 (prev_hash+event_hash 直接列, 已 append-only); `rule_mutations` append-only 突变表记每条 add/update/remove/epoch 突变 (rules/rule_meta 用 INSERT OR REPLACE/DELETE 会断链, 故独立突变链); `verify_all_chains` 聚合 audit+tcc+rules+dead_letter 四链, `guard.audit.verify` 返 `{audit, tcc, rules, dead_letter, tampered}` (tampered=任一子链被篡改)。规则篡改 (控 Block 的最高影响面) 现可检出。
- **并发模型 P0-6 (audit §2.1)**: `handle_method` 包 `tokio::task::spawn_blocking` 移阻塞 SQLite/链 hash 计算到独立阻塞线程池 (默认 512 线程), tokio worker 仅 await `JoinHandle` (可取消, 2s 超时能真正打断); 旧码 `async fn handle_method` 零 `.await` 跑在 tokio worker, confirm 突发负载活锁 8 worker 池 → accept/紧急拦截无法调度 → 安全绕过。`confirm_atomic` 双锁消除: `pending_actions`+`audit_events` 同在 guard.db 文件, `audit_writer` Connection 可见两表, 改单 `audit_writer` 锁全程 SELECT+INSERT+UPDATE (无嵌套 `action_db` 锁); `action_db` Mutex 仅留 `put`/`evict_expired` (无审计写路径, 不与 `audit_writer` 竞争)。4 个写连接加 `PRAGMA busy_timeout=5000` 防 WAL 多写者 `SQLITE_BUSY`。
- **密钥管理 (E/C13/C14/C15/A4)**: `zeroize` 依赖, key 存 `Zeroizing<[u8;32]>`; 删 `key_bytes()` 外泄; env key 加门控; Keychain 失败拒启动非临时生成; `Drop` zeroize。
- **解释器 RCE (C3) + tokenizer gap (L3/L4)**: 白名单二进制 `-c`/`-e`/`--command`/`--eval`/`-x` flag 检测 → L4 绝对 Block; `rm -fr`/`--recursive --force` 变体归 L4; `dd of=/dev/*` L4; `diskutil eraseDisk` L4; 多段命令全段扫描取 max。
- **H8 绕过 (C9/L2/A8)**: confirm 从 `verdict_json` 重建 verdict, risk_level 从 verdict_json 读非 action 列; L4 二次校验拒; consume+audit 单事务。
- **E5 大小写漂移 (C11)**: 服务端 serialize 与客户端 parse 端到端 lowercase 对齐 + e2e round-trip 测试。
- **OOM/slowloris (C17/A6)**: `read_until` 分块读 + 累计 > 1MiB 断连; 连接级总 deadline; 限流。
- **文件权限 (C21/A5)**: `AuditStore::open` 后 guard.db `0o600` + 目录 `0o700`; socket 路径 TOCTOU 防护。

### P1 — 第一 sprint

- **语义阶段健壮 (C4/C5)**: `semantic_check` 语法错时不短路清零 (fail-closed L3 hit); Python 专用遍历建 import/别名 map, 别名解析危险调用; 动态调度 `getattr`/`__import__`/`globals` → L3。
- **TTL reveal (C12/P4)**: `reveal` 入口 `evict_expired`; 过期 token → H6 `[REDACTED:unrecoverable#...]` 不还原; `evict_expired` 后台 interval。
- **脱敏 regex 扩展 (C19)**: `password` 覆盖 JSON `"password":`/`"secret":`/`"token":`; API key 加非 sk- 变体; 私钥加单行 `ssh-ed25519`/`ssh-rsa`。
- **DLP 脱敏盲区扩展 P1-1 (audit §1.10)**: 原 4 类窄 pattern (api_key/password/id_number/private_key) 对主流云凭据失明。扩 13 模式: JWT 三段式 (`eyJ…\.eyJ…\.…`)、OAuth bearer (`Bearer <token>` 保留前缀脱敏值)、AWS Secret Access Key (40 字符 base64, 无 AKIA 前缀, validator 字符多样性 ≥6 + base64 边界防假阳性)、GCP `ya29.`/Azure `AIza`/Stripe `sk_live`/`sk_test` (归 api_key)、信用卡 (`\d{13,19}` + Luhn validator + 数字边界防吞 id_number 子段)、连接串内嵌凭据 (`postgres://user:pass@host` 保留协议+host 脱敏 pass)、手机号 (`1[3-9]\d{9}` + 数字边界)、secret/token 通用键值、.env `KEY=value` 泛化、.netrc `password XXX`。**模式顺序关键**: 凭据键值 (带显式标签, 值可含数字) + 长令牌 (PEM/JWT/bearer/api_key) 先于裸数字模式 (credit_card/phone/id_number), 先到先拒重叠 —— 否则 17 位 `id_number` 吞 40 位 AWS Secret 或 password 值内数字。**规则 5**: regex crate 不支持 lookaround, 边界 (前后非同类字符) + Luhn + 字符多样性 用代码 validator (`fn(content, span起, span止) -> bool`) 非 regex 非模型; Luhn 拒非支付 16 位数字, 字符多样性拒全同 40 字符, 边界拒子段吞入。`has_sensitive` 与 `collect_spans` 语义对齐 (validator 拒的候选不计敏感)。
- **密钥分离 + 轮换 P1-2 (audit §1.6)**: 原 master key (Keychain/env 32B) 同时作 HMAC 审计链 key 与 AES-GCM token 加密 key —— 单点泄露 = 审计伪造 + token 解密双失守。改 HKDF (RFC5869) 域分离: master 作 PRK (高熵跳过 Extract), 经不同 `info` label 派生 `chain_key = HKDF(master, "fusion-guard/audit-chain-hmac/v<ver>")` 与 `token_key = HKDF(master, "fusion-guard/token-aes-gcm/v<ver>")` —— chain key 泄不可解 token, token key 泄不可伪造审计链。**版本化轮换**: version 嵌 `info` label, 轮换 = bump version + 落 `key_versions` 表; 派生确定 (master 不变 → 同 version 永同 key), 故 DB 只存 `key_version INT` (audit_events/tcc_events/rule_mutations/tokens 四表) 不存密钥材料, 旧行用旧版本派生 key 验链/解 token, 新行用新版本。`AuditStore::rotate_key()` bump 共享 `Arc<AtomicI64>` (drain 线程 + confirm 同步写实时见, 非 stale 闭包捕获); `current_key_version()` 活版本; `verify_chain`/`verify_tcc_chain`/`verify_rules_chain`/`verify_dead_letter` 按行 `key_version` 派生 key 验 (跨轮换混合链可验); token `get_tenant` 按行版本解 (旧 token 不随轮换失效)。验证: 4 测 (`p12_key_separation_test`) — 域分离 (chain≠token)、版本派生独立 (v1≠v2)、轮换后旧审计行验链、轮换后旧 token 解密。
- **pending action put fail-closed P1-3 (audit §2.5)**: `evaluate` 中 `actions().put()` (落 pending_actions 供 confirm) 失败原仅 `warn` 续返带 action_id 的 verdict —— caller 持 id 调 `guard.confirm` 查无此行 → L3 确认流永久死胡同 (磁盘压力期偶发, 无告警)。改 fail-closed: put 失败 → `evaluate` 返 `Engine` 错, 不下发 action_id (L3 确认流不可建则拒评估)。与 H7 审计写 fail-closed 耐久语义对齐 (两套写同一次 evaluate, 耐久性一致)。L4 Block 同样 fail-closed (H8 无 confirm 路径, 但耐久一致)。验证: 2 测 (`p13_put_failclosed_test`) — L3/L4 故障注入 (DROP pending_actions) 后 evaluate 返 Engine err。
- **req_sem permit 超时分离 P1-4 (audit §2.3)**: 旧码 `req_sem.acquire_owned().await` 嵌在 2s handler timeout future 内 → permit 排队耗时偷占业务预算, 高并发下 handler 实际可用 < 2s, 拦截判定时限被压缩。分离两段: (1) permit 单独短超时 `PERMIT_TIMEOUT_MS=500ms`, 拿不到 → `-32002` rate limit 即拒 (fail-fast, 不占 handler 窗口); (2) 拿到后 2s `REQ_TIMEOUT_SECS` 只包 `spawn_blocking(handle_method)` 全程给业务。`fg-ipc` 加 `test-helpers` feature: `new_with_req_permits(engine, audit, permits)` 自定义槽数 + `req_sem_handle()` 暴露 `Arc<Semaphore>` —— 测试预取并持有全部 permit 强制走 permit 等待 (确定性, 无需真实慢 handler, 无时序竞态)。验证: 2 测 (`p14_req_sem_timeout_test`) — permit 满返 -32002 且拒绝快于 2s (分离生效); permit 空闲 ping 正常返 pong (非误拒)。
- **IpcServer 鉴权层抽 trait P1-5 (audit §3.1)**: 旧码 peercred→身份解析 (`handle_conn`) 与共享 secret 校验 (`dispatch_arc`) 散在套接字 I/O 路径, 无独立单测, 只能起真实 socket 集成测才覆盖。抽 `Authorizer` trait (`authorizer.rs` 模块) + `PeerAuthorizer` 默认实现 —— 身份解析 (`resolve_identity`: peercred uid → `CallerIdentity` 含授权租户集) + 方法级鉴权 (`authorize_method`: ping 对任意对端开放, 非 ping 须同 uid + 共享 secret) 纯逻辑剥离。`AuthDecision` 枚举 (Allow/DenyPeercred/DenySecret) 三 Deny 均映射 `-32001` 但区分原因便于审计断言; `deny_resp` 产 wire 错误字节。`TenantLookup` 最小 trait (`tenants_for_uid`) 解 AuditStore 依赖 —— 单测注入 `FakeLookup` 无需真实 DB/Keychain/env。secret env 读取 + warn 下沉 `PeerAuthorizer::new`, server 不再重复持 `shared_secret` 字段。**范围裁剪 (规则 2/7)**: audit 列 4 trait (Transport/Authorizer/Dispatcher/Policy) 仅 Authorizer 落 trait —— 它是唯一含「未被测纯逻辑 + 不需复刻 engine 接口」的层; Transport 是 I/O 包壳 (trait 化只增抽象无测试增益), Dispatcher 是 engine 薄分派 (trait 须覆盖全方法 facade = 复刻接口), Policy (tenant/limit) 已是 `CallerIdentity::tenant_allowed` 纯方法 + `cap_limit` 自由函数 (已可测)。一处 trait + 文档说明裁剪理由, 避免双模式 (规则 7)。验证: 10 测 (`p15_authorizer_test`, 需 `test-helpers`) — resolve_identity (admin 空租户/非 admin 查表/peercred 拒绝), authorize_method (ping 对拒绝对端放行/非 ping peercred 拒/dev 无 secret 放/secret 错 DenySecret/secret 对 Allow/secret 设但未带 DenySecret), deny_resp wire 错误码。
- **audit.list 过滤 + 游标分页 P1-6 (audit §3.2)**: 旧 `guard.audit.list` 仅 tenant_id + limit —— 监控只能拉全量客户端筛, 量大且无增量能力。补 4 过滤维度 + 游标分页: `since`/`until` (RFC3339 ts 字典序比较, 时间窗), `event_type` (精确匹配, 区分 evaluate/confirm), `level_min` (`l1`..`l4` 经 `json_extract(verdict_json,'$.risk_level') >= ?` 取风险等级下限, NULL 行自然排除; store 层 `.to_lowercase()` 防御大小写 —— json_extract 返小写, 大写 `L3` 因 ASCII < `l3` 会使全行漏过过滤, 误返全量), 游标 `"ts\x1faudit_id"` 续拉 (0x1f 分隔, `LIMIT limit+1` 判 `has_more`, ORDER BY ts DESC+audit_id DESC, 游标条件 `(ts < ? OR (ts = ? AND audit_id < ?))`)。store 层 `AuditListFilter<'a>` + `AuditListPage` + `list_events_filtered` (动态 WHERE, 绑定参数 `?N` 连续递增非 fmt 拼接防注入, 绑定顺序 = 子句 push 顺序) + `list_filtered_page`; handler 解码 cursor 透传 store。监控增量拉取: `since=<上次末行 ts>` 只拉新行。**范围裁剪 (规则 2)**: audit 另提「通知通道 (webhook/SSE/UDS event stream)」但自述「PRD 未定义通知通道」—— 属无 PRD 背书的新外接口, 不引 (产品契约 lives in PRD); 过滤+分页已解暴力轮询根因 (增量 fetch)。新增 `insert_test_event` test-helper (test-helpers gated, 序列化真实 GuardVerdict 含 risk_level 供 level_min 验证, 旧 `insert_event_at_ts` verdict_json 恒 "{}" 无 risk_level 不可用)。验证: 6 测 (`p16_audit_filter_test`, 需 `test-helpers`) — 时间窗 (since+until 截 2 行)、event_type (排除 confirm)、level_min (L3 留 4 行 / L4 留 1 行 / 大写同效)、游标分页 (limit=2 翻 3 页 has_more→末页 false)、组合过滤 (since+event_type+level_min 同时留 2 行)、无过滤全 6 行 DESC。
- **写路径物理分库 P1-7 (audit §3.5)**: 旧码 5+ SQLite 连接 (audit_writer FULL + low_writer NORMAL + read_conn + token_store + action_store) 同开 guard.db —— 共享单 WAL 写锁, 所有写在 SQLite 层串行; app 层 Mutex 是假隔离。H7 audit_writer (synchronous=FULL, per-row fsync) 热路径被 token_store put / action_store put 抢锁阻塞, 评估延迟被旁路写拖累。**物理分文件**: `AuditStore::open(db_path)` 拆 audit.db (db_path, audit_events+chain+rules+tcc+tenant_bindings+checkpoint) / token.db sibling (tokens+key_versions) / action.db sibling (pending_actions), 各持独立 WAL —— evaluate 路径的 action put / token put / audit write 不再争单 WAL。`open(db_path)` 签名不变 (测传单路径), token/action.db 经 `db_path.with_file_name("token.db")`/`"action.db"` 推导。三文件均 `harden_db_perms` 0o600 (C21 三库硬化, perm_test 补断言)。**H4 confirm 原子性保留**: `confirm_atomic` 做 SELECT pending_actions + INSERT audit_events + UPDATE consumed 单事务; 分库后 audit_writer 连接 open 时 `ATTACH DATABASE 'action.db' AS action`, 引用改 `action.pending_actions`, 跨库事务协调提交 (各 ATTACH db 独立 WAL, 原子性保) —— H4 一次性 consume + L2+A8 审计同成同败不破。ActionStore 自身连接 (put/evict_expired) 未 ATTACH, 仍走 main.pending_actions。**旧库迁移**: `drop_legacy_split_tables` 在 open 后 DROP 旧单文件 guard.db main 残留的 pending_actions/tokens/key_versions (sqlite_master 存在性检查幂等, 失败 warn-not-fatal); 三表瞬态 (pending TTL 30s / token TTL 300s) 不拷行 (旧值大概率已过期), 仅清 residual。`tamper_verdict_json` test-helper 改开 action.db sibling (旧开 audit.db 查 pending_actions 已迁 → no such table)。验证: 4 测 (`p17_write_split_test`, 需 `test-helpers`) — 三文件存在+0o600、pending_actions 在 action.db 非 audit.db + put 行落 action.db、confirm 跨库事务原子 (audit.db 有 confirm 行 + action.db consumed=1 + 重 confirm Consumed)、旧库残留表 open 后 DROP。
- **跨租户 confirm (C20)**: `pending_actions` 加 `tenant_id` 列; confirm 校验 `action.tenant_id == caller.tenant_id`。
- **rule 突变 stale-epoch (L7)**: `rule.add/update/remove` 校验 `caller_epoch` (非 0 且 == 当前), 否则 -32003; 种子 fail-open 修复。
- **positional params (L8/M2/M1)**: `RpcRequest` params 必须是 object 拒 array; 未知方法 -32601 不带方法名; wire 错误只码 + 通用消息, 详细记服务端日志。
- **tcc.report 校验 (M8)**: handler 调 `TccService::parse(permission)?`; `requester`/`reason`/`result` 限长 1024。
- **读连接 + limit 上限 (A3/P3)**: `audit.verify`/`list_events` 开专用读连接 (无 mutex); limit 硬上限 10000 + 截断日志。

### P2 — 技术债

- **env key 门控 + 告警 P2-1 (audit §2.6)**: 旧 `load_or_create_key` 先查 `FUSION_GUARD_TOKEN_KEY` env 命中即用跳过 Keychain, 无 dev/prod 门控 —— 误配即主密钥进进程环境 (`/proc` 等价 `ps eww`/lsof/launchctl), 同 UID 进程 (一核九端 9 个 fusion-* 全同 UID) 可读 → AES-GCM token key + HMAC 链 key 双泄露 (§1.6 密钥复用, 已由 P1-2 HKDF 域分离缓解但仍同 master)。测试全局 `ensure_env()` 沿用 env 姿势, operator 易照搬进 launchd plist。**门控**: 抽纯决策函数 `resolve_key_source(is_debug, allow_env_flag, env_present) -> KeySource` (规则 5: 决策用代码非 token) —— `cfg(debug_assertions)` (dev) → `EnvDebug` (info 姿态); release 仅 `FUSION_GUARD_ALLOW_ENV_KEY=1` 或 `--insecure-env-key` CLI flag (fg-bin `start` 子命令置 `FUSION_GUARD_ALLOW_ENV_KEY=1`) 放行 → `EnvInsecure`; env 不放行或缺 → `KeychainRequired` (macOS 走 Keychain, 非 macOS fail-closed 拒启动, 不回退弱密钥)。**告警**: `EnvInsecure` 路径 `tracing::warn!` 级 banner ("INSECURE (P2-1): master key loaded from env in release — visible to any same-UID process; prod MUST use Keychain"), 运维审计可见; `EnvDebug` 仍 `info!` (dev 姿态)。fg-bin flag 置位时额外 warn。`decode_env_key`/`load_keychain_or_err` 拆分 (旧 `load_or_create_key` 内联三路径 → 独立 fn, 可读可测)。**范围**: §1.6 密钥复用本身由 P1-2 HKDF 修复 (master 经 HKDF 派生独立 chain/token key), 本 P2-1 只补 env 门控 + 告警 (防误配泄漏通道), 不改密钥派生。验证: 3 测 (`p21_env_key_gating_test`, 需 `test-helpers`) — 决策矩阵全 7 分支 (debug/release × flag × env_present → EnvDebug/EnvInsecure/KeychainRequired)、debug env 加载不触 Keychain (token put+reveal roundtrip 生效)、release env 无 flag → KeychainRequired 门控回归 (调真实 `resolve_key_source` 非 oracle, 规则 7 不维护两份逻辑)。
- **A1 shell_words fail-closed**: tokenizer 增 `check_unmodeled_shell_features` —— 裸 tilde/brace 展开 `{a,b}`/`{n..m}`/glob `*`/`?`/`[abc]`/heredoc `<<`/`|&`/fd 重定向 `>&N`/`<&N`/`<>`/反斜杠续行 → Block L4 (shell_words 不建模这些特性, 每个是绕过通道, fail-closed 拒非逐文件补 arm)。
- **peercred 瞬态失败升 warn + 区分拒绝类型 P2-3 (audit §3.4)**: 旧 `peer_uid(fd) -> Option<u32>` 把 `getpeereid`/`SO_PEERCRED` 系统调用瞬态失败 (fd 失效/EBADF/ECONNRESET) 仅 `tracing::debug!` 记录, prod info 级不可见, 且与「跨 UID 拒绝」混入同一 `None` 路径 → ghost unauthorized undiagnosable (运维无法区分「系统调用失败须诊断」与「跨 UID 攻击/误连」)。**三态分离**: 抽 `PeerUid` enum (`Resolved(u32)`/`SyscallFail`/`Unsupported`) 替 `Option<u32>` —— `peer_uid` 系统调用失败返 `SyscallFail` 并升 `tracing::warn!` 级 (附 OS errno); 平台不支持返 `Unsupported` (warn); 成功返 `Resolved(uid)` (仍 debug)。`peer_allowed` 三态入参: `Resolved` 走同 uid/root 校验, `SyscallFail`/`Unsupported` 恒拒 (无凭证 = 不可信, fail-closed)。**区分日志**: `PeerAuthorizer::resolve_identity` 拒绝分支按 `is_syscall_fail()` 分两路 warn —— `SyscallFail` 记 "peer credential syscall failed (P2-3 §3.4); fail-closed", `Resolved(other)` 记 "non-peer connection (E6 cross-UID)", 两类同 fail-closed 拒但日志分明。`PeerUid` 经 `fg-ipc` re-export (pub use fg_peercred::PeerUid), `resolve_identity` trait 签名 `Option<u32>` → `PeerUid`。`resolved()`/`is_syscall_fail()` 辅助方法供调用方取 uid + 判类。验证: +2 测 —— `peercred_test` 增 `syscall_fail_peer_denied` (SyscallFail/Unsupported 恒拒, allow_root 也不放行) + `peer_uid_resolved_and_is_syscall_fail` (三态辅助方法); `p15_authorizer_test` 增 `p23_resolve_identity_syscall_fail_distinct_from_cross_uid` (SyscallFail uid 兜底 u32::MAX vs 跨 UID 保留真实 uid 999, 两类 uid 字段可区分)。附带修 `fg-store/src/lib.rs` `CheckStage` import 既有 unused 警告 (test-helpers 默认关时 lib 不用, 拆 `#[cfg(feature="test-helpers")] use`)。全量 178 pass (176→178, +2), clippy clean (0 warning), release green。
- **UDS 连接池 + 持久复用 P2-4 (audit §3.6)**: 旧 `UdsClient::call` 每次 connect+write+read+drop —— 每次调用付 UDS connect 握手开销 (socket 创建+bind+connect+accept 内核态往返), 高频 L1 evaluate P99 被握手主导, 9 端并发下 P99<1ms 不可达。**服务端已支持单连接多请求** (`conn_loop` read→dispatch→write 循环, EOF 才断, `CONN_DEADLINE_SECS=30s` 兜底防 slowloris), 审计原述「处理完即断」不实 → **仅客户端改, 不动服务端** (规则 2 最小化)。`UdsClient` 持 `Mutex<Option<UnixStream>>` 持久连接: `call` 委托 `call_once`, 后者 lazy connect (首次 call 才建流) + 借用流读写 (`BufReader<&UnixStream>` 不消耗/clone, 同 fd 跨调用复用) + 成功保留流供复用 + IO 错 (服务端 30s deadline 断/重启/对端 EOF/EPIPE/超时) 清空流促下次重连。`call` 对 `call_once` 失败重连一次重试 (透明自愈, 仅一次防故障放大), 调用方不感知服务端重启。**不做多路复用** —— Python 单线程阻塞模型一次一请求在途, 连接复用即消除握手开销 (规则 2)。`PyGuardClient` 持 `UdsClient` 直接 (非 `sock: PathBuf` 每次 `UdsClient::new` 新建, 那会架空连接池), `client()` 返 `&UdsClient`。验证: +1 测 `p24_persistent_conn_reuse_and_reconnect` —— (1) 同 client 5 次 ping 复用连接全成功 (复用不损坏 wire); (2) 服务端 abort+重启后, 死流被检测清空+重连, ping 仍 ok (透明自愈)。全量 179 pass (178→179, +1), clippy clean (0 warning, 顺带清 `map_err(|x| x)` identity lint), release green。
- **category_hint 调用方风险地板 P2-6 (audit §3.2/F6, PRD §6.3 H9)**: 旧 `guard.evaluate` 无 `category_hint` 入参, 调用方主张的 category 无审计可见性, 且 v0.1「caller 自证 category」可被降级绕过 (caller 谎报 `read` 压低等级绕过 Block)。**H9 契约**: guard 从 content 推断 category 权威 (`inferred_category`), caller `category_hint` 仅作风险地板 —— `最终等级 = max(推断, 规则命中, hint)`, hint 抬等级永不压低 (双向防绕过)。wire: `guard.evaluate {action, content, context, caller_epoch, category_hint?}` (缺省 None 向后兼容)。IPC 收 `category_hint` (s_param idx 6) → 透传 `AuditEngine::evaluate(content, caller_epoch, tenant_id, content_type, category_hint: Option<&str>)`。engine 落 `verdict.category_hint` (审计可见调用方主张) + 纯 fn `hint_risk_floor(hint)` 算地板: `shell_exec`/`network`/`file_write` → L2 地板, read/clean/未知 → None (无地板)。地板封顶 L2 (L3/L4 始终由真实规则命中驱动, 非 caller 声明), `Allow`→`Redact` 当地板抬等级过 L1。`GuardVerdict` 增 `category_hint: Option<String>` 字段 (`#[serde(default, skip_serializing_if)]` 让旧 verdict JSON 缺此字段仍可解, pending_actions/audit 跨版本兼容), `PyGuardVerdict` 镜像 + `to_dict` 暴露; `fg-pyo3` evaluate pymethod 增 `category_hint: Option<String>` 签名 (default None)。验证: +5 测 `p26_category_hint_test` —— `hint_risk_floor_known_categories` (shell_exec/network/file_write→Some(L2)) + `hint_risk_floor_low_or_unknown_is_none` (read/clean/bogus/""→None) + `hint_raises_floor_from_l1_to_l2` (`ls /tmp` 无命中 L1 Allow + hint "network" → L2 Redact, inferred_category 仍 "read" hint 不覆盖推断) + `hint_never_lowers_l4_block` (`rm -rf /tmp/x` L4 Block + hint "read" → 不降, 仍 L4 Block) + `hint_floor_below_current_no_change` (L4 Block + hint "shell_exec" L2 地板 < L4 → 无变化)。纯决策 fn 可单测 (规则 5)。全量 184 pass (179→184, +5), clippy clean (0 warning), release green。
- **A2 有界队列 + dead-letter**: 低风险审计改 `sync_channel(8192)` + `try_send` 背压; drain 内联跑 batch (非 spawn-per-batch); 队列满/断连 → 持久 dead-letter 文件 (guard.db.deadletter, 0o600), 不静默丢事件。
- **A9 语义 SSOT**: 删死代码 `semantic_default_rules()` (产 6 条 stage=Semantic GuardRule 注入规则集, 但 evaluate 跳非 Regex stage, 从不匹配); 硬编码危险表 (PY_DANGER_L4 等) 为语义执行唯一真相源, 非 admin 可变 (文档化), 恢复 SSOT 诚实。
- **L5 mv/cp 目的地 (M)**: `check_argv` 建模 `-t DIR`/`--target-directory=DIR`/`--target-directory DIR`/`--` 终止符, 正确解析 GNU mv/cp 目的地。
- **L6 span 追踪**: 脱敏改原内容单趟 span 收集 (拒重叠, 首模式优先), 占位符永不写回原内容 → `id_number` 不腐蚀先前 `tok_<uuid>` 占位符 (原顺序 replace_all 在已脱敏文本上跑, id_number 匹配占位符内 17 位数字子串 → 破占位符 → reveal 撞 H6 → 可逆静默降级不可逆)。`id_number` 收紧 `\d{17}[\dXx]`。
- **L9 PyO3 错误显式**: fg-pyo3 客户端删所有 `unwrap_or` 静默回退 —— reveal/redact/confirm/audit_verify/list_rules 缺关键字段即 `PyValueError` (防空串伪装成功 reveal、false 伪造无篡改、epoch 0 永持陈旧)。
- **L10 category 从 hit 派生**: `infer_category` 从实际 hit scope 派生 (Network→network/Filesystem→file_write/非白名单→shell_exec/无 hit→clean), 非固定名表 fallback。
- **L11 verdict 显式 rank**: `verdict_from_hits` 按 `(action_severity, risk_level, stage_rank)` 确定性排序取 head, 非 `max_by_key` 平局任意末 hit 胜。
- **L12 confirm 审计 schema**: confirm 审计事件加专用字段存 outcome/approve-reject, `action` 列不再一列两义。
- **L13 migrate 用 PRAGMA**: `migrate_audit_chain` 改 `PRAGMA table_info` 查列存在 (非 `prepare(SELECT col)` —— 后者在无列 legacy DB 返 Err 致 open 失败, 迁移路径不可达)。
- **M3 poison 显式处理**: `PoisonError` 显式 recover (11 处 `.expect` 改 lock 宏)。
- **M4 Redactor Result**: `Redactor::new` 返 `Result` 传播编译失败 (非 process panic); `OnceLock` 缓存静态 regex。
- **M5/M7 build.rs**: `rerun-if-changed .git/refs` 防 FG_GIT_SHA 过期; build.rs 编译失败显式 `expect` 检查 success。
- **M6 RiskLevel 显式 Ord**: 显式 `Ord` impl 替 `as u8` 隐式。
- **M9 json_to_py 直转**: fg-pyo3 `Value` → Python 递归直转 (非 `to_string` + `json.loads` 往返), f64 精度保真, 零 import。
- **P1/P2 regex 单扫**: `Lazy`/`OnceLock` 静态化 regex; `redact_counted` 单趟返 `(脱敏, 命中数)` 取代 has_sensitive+redact 二扫。

### 产品商用审计修复 sweep (product-audit-0827)

依据 `audit/fusion-guard-audit-result-product-0827.md` (产品商用判定) 落地。与 audit-0827 静态对抗审查不同 wave, 此为商用发布前阻断硬伤修复。详见 CLAUDE.md。

- **shared secret prod 配置缺失 (H-C, audit §5)**: 旧 shared secret 仅 env 来源 (`FUSION_GUARD_SHARED_SECRET`) = 同 UID 进程可读 (`ps eww`/lsof/launchctl), 被攻陷 subagent (一核九端 9 个 fusion-* 同 UID) 可窃第二因子 → 规则突变/可逆脱敏 reveal 全权调用。**prod 来源改 macOS Keychain** (service `fusion-guard`, account `shared-secret`, 与 token-key 同 service 不同 account 域分离)。新增 `fg-store::secret_store` 模块: `resolve_shared_secret(is_debug, allow_insecure_flag, env_present) -> SharedSecretSource` 纯决策函数 (规则 5, 镜像 token-key 的 `resolve_key_source`) + `keychain_secret_get`/`keychain_secret_store` (macOS vs 非 macOS cfg) + `generate_shared_secret` (32 字节 hex 64 字符)。`load_shared_secret` 解析序 Keychain → env → none: Keychain 有即用 (prod 路径, 不入环境变量); Keychain 无 + env 放行 → env (escape hatch); Keychain 无 + env 未放行 → 不静默用 env (防漏 flag 降级) 视为无 secret; 两处皆无 + macOS release 首次启动 → 生成强随机 secret 存 Keychain (allow_mint, operator 也可预置纯 Keychain 不生成)。**Release gate** `require_shared_secret_for_release()`: release 启动检查两来源皆缺 → 拒启动 (防仅 peercred 兜底被同 UID 攻陷进程全权调用); Keychain 有 / env 放行 / `FUSION_GUARD_ALLOW_NO_SECRET=1` (应急运维 peercred-only) 三者任一放行。`ALLOW_NO_SECRET` **优先判** (启动 gate + load 双处), 跳过 Keychain 读 —— 非交互环境 `get_generic_password` 可能串行阻塞 (CLAUDE.md Keychain 挂起风险), CI/soak spawn release daemon 设此 flag 即可, 客户端无需携 secret。dev 构建 (debug) 跳过 gate, 容 secret 缺失 (测试便利)。`fg-bin` `start` 子命令增 `--insecure-secret-env` flag (置 `FUSION_GUARD_ALLOW_INSECURE_SECRET=1`, 镜像 `--insecure-env-key`)。`start.sh` shared-secret 供应块镜像 token-key 块: env 设 → flag; dev keyfile `${GUARD_DIR}/shared-secret` → 读 + flag; 两处皆无 → Keychain 路径。验证: 6 测 (`secret_store_test`) — 决策矩阵 4 分支 (Keychain/env-debug/env-insecure/release-no-flag) + 生成 hex 64 字符 + 随机性。
- **token-test 挂起修复 (环境性)**: `ciphertext_not_plaintext` 原扫整个 `std::env::temp_dir()` (本机被其他进程污染, FIFO/大目录 entry) → `std::fs::read` → `open()` 在某 entry 阻塞, 测试挂 60s+。改 `open_conn_in_dir()` 仅扫测试自建子目录, 断言意图不变 (自建 db 目录下不得出现明文)。env-key 测试前置不变。
- **操作文档**: 新增 `DEPLOYMENT.md` —— 两个密钥信任模型对比表 (token-key vs shared-secret, Keychain account / env 变量 / 泄露影响)、Keychain 安全路径 (首次自动生成 + operator 预置 `security add-generic-password`)、env 不安全路径表 (放行 flag CLI + env)、release gate 行为、快速 prod 部署清单、多节点集群 (shared secret 各节点一致)、launchd 常驻 (用户域 LaunchAgents)、密钥轮换。

### 测试稳健性 (verify 阶段补强)

- **semantic_verdict_block payload 修正**: 原 payload `os.system('rm -rf /')` 同时命中 regex rm-rf (Block L4) + semantic os.system (Block L4), L11 stage_rank Regex>Semantic → verdict.stage=Regex 非 Semantic (测试误报 fail)。后改 `subprocess.run(['ls', '-la'])` 又撞 A1 glob `[...]` Ast L4 平局。终定 `os.system('id')`: Ast 仅非白名单 L3, semantic os.system L4 — L4 risk > L3 → semantic 确定性胜。L11 排序设计正确, 错在 payload 未隔离单一 stage。
- **fg-pyo3 测 flake 消除**: `evaluate_block_returns_verdict` 在 workspace 高并发负载下偶发 `-32010` (server.serve accept 循环未被 worker_threads=2 调度 → 首请求 2s read 超时)。补 `wait_for_sock` 轮询 1s→5s + `call_retry`/`call_retry_err` 瞬态 -32010 重试 3 次 × 200ms, 非 -32010 业务错 (如 -32003 stale epoch) 原样返不重试。

## IPC 协议

UDS socket: `/tmp/fusion-guard.sock` (env `FUSION_GUARD_SOCK`)
帧格式: JSON-RPC 2.0 + `0x0A` 分隔, 1MiB 上限, 2s 超时 fail-closed

方法:
- `guard.ping` — `{pong: bool, version, rules_epoch}` (`pong` 为 boolean —— 跨仓消费方 fusion-cli #9 / fusion-studio #344 按 `Bool` 读; 勿返 string)
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
- `guard.audit.verify` — `{}` → `{audit:{...}, tcc:{...}, rules:{...}, dead_letter:{...}, tampered}` (全链聚合校验, P0-5: audit+tcc+rules+dead_letter 四子链; 各子链 `{total_rows, unhashed_rows, verified_links, broken_links, tampered, first_broken_at?}`; 顶层 `tampered`=任一子链被篡改, PRD §13.3)
- `guard.redact` — `{content, reversible:bool}` → `{redacted_content, token_map_id?}` (可逆: token AES-GCM 加密落盘, in-flight 标记 R3; 不可逆: `[REDACTED:type#last4]`)
- `guard.redact.patterns.dump` — `{}` → `{patterns: [{name, regex, validator}]}` (issue #7: 15 条脱敏 pattern 定义只读 dump, 优先序保留, validator tag `none|ipv4|aws_secret|luhn|phone`; 消费方拉取代 vendoring, 消手动 lockstep)
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

## 生产部署

**两个生产密钥** (token-key 主密钥 + shared-secret 第二因子) 部署方式不同, prod 必须用 macOS Keychain (service `fusion-guard`, account `token-key`/`shared-secret`), env 仅 dev/CI/应急 escape hatch (release 须显式 flag 放行)。

完整部署文档: **`DEPLOYMENT.md`** (Keychain 安全路径 + env 不安全路径 + release gate H-C + 快速 prod 清单 + 多节点集群 + launchd 常驻 + 密钥轮换)。

release 二进制启动前须预置 Keychain secret, 否则 release gate 拒启动 (除非 `FUSION_GUARD_ALLOW_NO_SECRET=1` 应急放行):

```bash
SS=$(python3 -c "import secrets;print(secrets.token_hex(32))")
security add-generic-password -s fusion-guard -a shared-secret -w "${SS}"
./start.sh start    # 客户端非 ping 请求须携 secret
```

### 无头 / CI / SSH (issue #17)

macOS Keychain (`SecItemCopyMatching` / `get_generic_password`) 在非交互会话 (无 WindowServer — SSH、CI、无 GUI 的 launchd) **串行阻塞**。release 守护进程在既无 env 又无 keyfile escape hatch 时启动静默挂死 —— `start.sh` 的 `kill -0` 存活检查可能在进程卡在阻塞 Keychain 调用内时仍通过, 故失败形态为「守护进程看似已启动但永不绑定 socket」。

`start.sh` 自动检测无头环境并**跳过 Keychain**, 回退文件密钥 (保 DLP + 审计链跨重启可验, 不以 `allow-no-key` 削弱安全):

- **无头判定**: `--headless` flag (`./start.sh start --headless`)、`FUSION_GUARD_HEADLESS=1` env、无 tty (stdin 非 tty)、或 SSH 环境 (`SSH_CONNECTION`/`SSH_TTY`/`SSH_CLIENT` 已设)。桌面交互会话默认走 Keychain (prod)。
- **行为**: 无头 + 无 env + 无 keyfile → 自动生成 `~/.fusion-guard/token-key` (32 字节 hex, 600 权限) 和 `~/.fusion-guard/shared-secret` (32 字节 base64, 600 权限), 导入 env + 传 `--insecure-env-key`/`--insecure-secret-env`。keyfile 跨重启持久 (同主密钥 → 审计链可验、token 可解) —— 仅生成一次, 之后复用。
- **强于 `FUSION_GUARD_ALLOW_NO_SECRET=1`**: 保 §12.1 shared-secret 第二因子 (文件密钥, 客户端携带) 而非降级为仅 peercred 鉴权。
- **桌面 prod 回收**: 删除 keyfile (`~/.fusion-guard/token-key`、`~/.fusion-guard/shared-secret`) 后在交互会话重启 → Keychain 路径 (密钥不入 env, 同 UID 不可读)。或预置 Keychain + 跑 `./start.sh start` (不加 `--headless`)。

```bash
# CI / SSH / 无 GUI launchd
./start.sh start --headless
# 或自动检测 (管道 stdin / SSH) —— 无需 flag
FUSION_GUARD_HEADLESS=1 ./start.sh start
```

### 压测 / soak (商用阻塞点 #6)

`crates/fg-ipc/tests/soak_test.rs` — 长跑并发压测, 验生产形态: 持续高并发负载下延迟不退化、子进程内存不泄漏、fail-closed 不破。

```bash
# 先建 release daemon (soak spawn 子进程, 非在进程内)
cargo build --release -p fg-bin

# 跑 soak (需 release binary, 缺失自动 skip 不挂全套 cargo test)
export FUSION_GUARD_TOKEN_KEY=$(python3 -c "import secrets;print(secrets.token_hex(32))")
cargo test -p fg-ipc --test soak_test -- --nocapture
```

模型: spawn `target/release/fusion-guard start` 子进程 (隔离 SOCK+DATA_DIR+TOKEN_KEY+LOG_DIR), 48 并发 UDS 连接循环 `guard.evaluate` 跑 10s, 每 2s 采子进程 RSS (`ps -o rss=`) + DB 磁盘占用。子进程模式 = RSS 量纯 server, 无客户端线程栈/malloc 污染, 无 debug 膨胀。

断言: 吞吐 ≥5000 reqs/10s, 错误率 <1%, p50 ≤25ms, p99 ≤200ms, DB 磁盘 ≤200MB (rotation 有界), daemon RSS ≤1200MB (容 macOS libmalloc 不归还 + tokio 池驻留)。fail-closed 用例 (`rm -rf /`) 验 Block L4 高并发下不误判 allow。

**测试前置**: `cargo test` 必先 `export FUSION_GUARD_TOKEN_KEY=<hex 32B>`, 否则 `AuditStore::open` → macOS Keychain `SecItemCopyMatching` 非交互环境挂 60s+。

## 路线图 (PRD §17)

- **Phase 0** ✅ 工程骨架: workspace + 8 crate + start.sh + CI + launchd
- **Phase -1** ✅ 门控: fusion-security 决策 A (只收敛重叠能力, SAST 独立保留) — issue #23
- **Phase 1** 规则收敛: ✅ SSOT + epoch + 持久化, ✅ SQLite WAL 审计, ✅ encrypted token store (redact/reveal), ✅ confirm + action_id (H4/H8)
- **Phase 2** AST 阶段: ✅ Stage 2 tokenizer (shell-words MVP), ✅ category 推断 (H9), ✅ seatbelt_required (E7), ✅ SENSITIVE_PATHS/WHITELIST 收敛
- **Phase 3** fail-closed 本地缓存 + seatbelt 编译内联 (blocked-on-upstream-PR: executor E2)
- **Phase 5** ✅ TCC 审计聚合 (H1) + Swift tcc-bridge (status query, C stub 兜底, 独立 CI lane — E1)
- **Phase 6** agent-studio/studio 集成 (blocked-on-upstream-PR: E2)
- **Phase 7** 审计链式 hash 防篡改 ✅ (PRD §13.3); Endpoint Security ✅ (fg-es, stub 降级 → TCC, Q#3); PyO3 绑定 ✅ (fg-pyo3, UDS 客户端暴露 Python, Q#4); Stage 3 tree-sitter 语义阶段 ✅ (feature=semantic, PRD §7.4 R5)

## Monorepo 上下文

27 个 `fusion-*` 子项目共享 `/Users/dahai/fusion/.venv`。fusion-guard 是 Rust + Swift 工程, 非 Python。IPC 对齐 monorepo JSON-RPC 2.0 over UDS 契约。详见 `/Users/dahai/fusion/CLAUDE.md`。
