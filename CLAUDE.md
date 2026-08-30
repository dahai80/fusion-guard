# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Status

**Current release: v0.2.0-rc.1 (2026-08-28, release candidate).** Phase 0 + Phase 1 (checkpoints 1-4) + Phase 2 Checkpoint 5 + Phase 5 (TCC audit aggregation + Swift bridge) + Phase 7 (audit chain hash tamper-evidence + ES monitor + PyO3 binding + semantic stage) + P0-P2 audit hardening sweep (22 fixes: G1-G9 release-blockers + P1/P2 waves) + GitHub issues #1/#2/#3/#5/#10 landed on `main` + **issue #4 (cluster/multi-node consumer) landed** in v0.1.2 + **issue #7 (redact pattern dump) landed** v0.1.2 + **PR#12 audit-sweep (P1-5/P1-6/P1-7/P2-1/P2-2/H-G + soak H-C fix) merged** v0.2.0-rc.1, pushed to dahai80/fusion-guard. Phases 3/4/6 blocked-on-upstream-PR (E2 — executor/agent-studio/studio integration, issue→PR→land flow).

**产品商用审计修复 sweep (2026-08-28, audit/fusion-guard-audit-result-product-0827.md):** 全 P0-P2 code-fixable 项落地。242 tests pass (177 baseline + 65 new), clippy clean, fmt green, release green。

**H-E (主密钥丢失单点致命, 2026-08-29):** audit H-E 四项落地 — (a) 拒绝静默 remint + (b) 密钥托管 escrow (DOC) + (c) rotate_key 历史行可验 (无 re-hash, 版本化派生) + (d) 密钥丢失 vs 真篡改区分 (per-version key_anchor 锚点, `guard.audit.verify` 增 `key_version_unknown_rows`/`key_loss` 字段)。详见下 H-E 条目。H-F (零消费者) 上游阻塞 (fusion-executor#23), 非本仓可修。
- **P1-5 (epoch 编排层事务化):** `AuditEngine` 持 `rule_orch_lock: Arc<Mutex<()>>`, add/update/remove_rule 三步 (落盘 rule→内存 add→落盘 epoch) 全程持锁序列化, 防并发 add_rule 丢 epoch bump (两线程同读 epoch=N 各写 N+1)。evaluate 仅取 RuleEngine 读锁不持此 Mutex → 拦截路径不被突变阻塞。2 tests (p15_epoch_tx_test.rs: 16 线程并发 add_rule → epoch 严格增 16 无丢 bump + 16 规则全落盘; 连续 add_rule 严格 +1 对照)。
- **P1-6 (AppleEvents honest source tag):** `fg-tcc` query_status() AppleEvents 项 source 标 `"apple-events:unknown"` (live) / `"tccutil:stub"` (stub), 非 `"swift-bridge:live"` —— guard 是 TCC 审计聚合方非 AppleEvents 自动化发起方, AEDeterminePermissionToAutomateTarget 需 per-target bundle 不可在守护进程给单一布尔值。`fg-tcc-bridge` Swift fn 仍返 0 (honest unknown) + 详细注释。2 tests (fg-tcc/tcc_test.rs: live→apple-events:unknown+authorized=false; stub→tccutil:stub)。
- **P1-7 (慢任务独立限流 slow_sem):** `IpcServer` 增 `slow_sem: Arc<Semaphore>` (MAX_CONCURRENT_SLOW=4), 慢方法 (guard.audit.verify / guard.cluster.*) 额外取 slow_sem permit (独立 500ms 超时), 持到 spawn_blocking 任务真完成, 硬限并发慢任务数, 防大表 verify/联邦网络调用占满 blocking 池饿死拦截路径。`is_slow_method()` + `new_with_slow_permits` (test-helpers)。3 tests (p17_slow_sem_test.rs: slow_sem 满→慢方法 -32002 快于 2s; slow_sem 满不阻塞快方法 ping; slow_sem 空→慢方法正常服务)。
- **P2-1 (Stage3 语义扫描 SLA guard):** `fg-rules::semantic` 两道防线: (1) `SEMANTIC_INPUT_CAP=256KB` 输入硬上限, 超出 fail-open 降级 (regex/tokenizer 仍扫) + L2 提示审计可见 (非静默 clean); (2) `guess_grammars()` 语言启发式门控 —— 按首 2KB 关键字猜源语言 (Rust: fn/::/impl; Python: def/import/elif; JS/TS: require/=>/console), 只试候选 grammar (通常 1 个), 省 3/4 解析。原无脑全试 4 grammar 致 clean Python 源经 3 非原生 grammar 错恢复解析 256KB→27s 突破 2s SLA (PRD R1); 启发式后 1× 解析 <500ms。保 C4 (全错源回退 err+非空命中) + C5 (跨语言裸命中 clean+hits 确证优先)。3 tests (semantic_test.rs: 超上限降级 L2; 上限内正常命中; 256KB clean Python <500ms perf 基线)。
- **P2-2 (start.sh stale socket + Keychain 免 env):** `start()` 主动清 stale socket (无 pid 文件时 `rm -f` sock, 防崩溃残留致 bind 报 address-in-use); 主密钥生产用 Keychain (无 keyfile 不导 env 不传 flag → 走 macOS Keychain), dev keyfile / 已设 env 是 escape hatch 须显式传 `--insecure-env-key` flag 放行 release gate (否则 KeychainRequired 拒启动), 均告警。bash syntax ok。
- **H-G (launchd plist 安装就绪):** `install-launchd.sh` (install/uninstall/status) 渲染 `com.fusion-mlx.guard.plist` 模板占位符 (`__GUARD_BIN__`/`__HOME__`) → 真实绝对路径, chmod 0o600, post-render 残留占位符检测 (中止防半渲染产物), launchctl load + 验启动。域选 LaunchAgents (用户域, guard 读用户 Keychain 须以用户身份跑, 非 LaunchDaemons 系统域)。
- **Soak test H-C 回归修复 (2026-08-28):** `crates/fg-ipc/tests/soak_test.rs` `spawn_daemon` 增 `FUSION_GUARD_ALLOW_NO_SECRET=1` env。原因: H-C (shared-secret release gate) 落地后, release daemon 无 `FUSION_GUARD_SHARED_SECRET`/`FUSION_GUARD_ALLOW_NO_SECRET` 拒启动 (`refusing to start: ... unset in release build`), soak 子进程 spawn 后即退出 → `soak daemon exited before sock appeared` panic (line 101), 3/3 确定性失败。补 bypass env 后 3/3 稳定通过。仅 soak 测试 spawn release daemon, 其他测试 (fg-pyo3 等) 走 in-process 不受影响。
- **H-E (主密钥丢失单点致命, 2026-08-29):** audit H-E (product-audit §5) — master key 丢失 = 全历史审计链 verify 失败 (假报篡改) + 可逆 token 不可解, 且与真篡改不可区分。修复分四项:
  - **(a) 拒绝静默 remint:** `load_keychain_or_err` (`token_store.rs:426-459`) — Keychain miss + DB 已有历史数据 (token.db 非 virgin) → 拒启动明确报错, 仅 virgin DB (首次) 允许生成。`token_db_is_virgin` (无 token 行 + key_versions 仅种子 v1 created_ts=0) 判定。tests `he_key_loss_test.rs` (5 decision-gate cases, 不触真 Keychain)。
  - **(b) 密钥托管 escrow:** DOC only (`DEPLOYMENT.md` §主密钥托管) — 首次生成后立即导 Keychain master 到离线备份 (`security find-generic-password -s fusion-guard -a token-key -w`), 丢失时恢复**同一**密钥 → 锚点匹配 → 无假篡改。无 daemon 代码 (escrow = 运维流程)。
  - **(c) rotate_key 历史行可验 (无 re-hash):** `rotate_key` = bump `key_version` (**master 不变**, HKDF 按 version 派生)。旧行记旧 `key_version`, 用旧派生 key 验 (确定性 HKDF 同 master 可重算) → 轮换后历史行可验可解, **无需 re-hash/re-encrypt**。re-hash 审计链被刻意拒绝 (hash 不可变 = 防篡改保证, re-sign 自废武功)。测试 `he_key_loss_distinguish_test::rotation_all_chains_and_tokens_verify` 覆盖全 4 链 (audit/tcc/rules/dead-letter) + token (扩 p12 原只测 audit 链)。
  - **(d) 密钥丢失 vs 真篡改区分 (核心):** per-version `key_versions.key_anchor TEXT` 锚点 = HMAC(`b"fusion-guard/key-anchor/v1"`, `derive_chain_key(master, version)`)。mint (v1 seed in `open_checked` via `backfill_key_anchors`) + 每次 rotate 写锚点 (IMMUTABLE — backfill only `WHERE key_anchor IS NULL`, 不覆盖)。`verify_chain`/`verify_tcc_chain`/`verify_rules_chain`/`verify_dead_letter` HMAC 不匹配行调 `classify_break(tokens, kv)`: 锚点与当前 master 重算**匹配** → 真篡改 (`tampered=true`); **不匹配** → 密钥丢失 (`key_version_unknown_rows++`, `tampered` 不计); **NULL** (legacy) → fail-closed 篡改 (攻击者清锚点无藏身处)。struct 增 `key_version_unknown_rows: usize` (ChainVerification + SubChainVerification) + `key_loss: bool` (AllChainsVerification, 任一链 unknown>0)。IPC `guard.audit.verify` 薄 `serde_json::to_value` pass-through, 新字段自动透出, 无 handler 改动。tests `he_key_loss_distinguish_test.rs` (4 cases: rotation 全链可验 / 密钥丢失→unknown>0+tampered=false+key_loss=true / 真篡改→tampered=true+unknown=0 / 锚点 NULL→fail-closed tampered)。`key_anchor_for_version` (`token_store.rs`) 复用 `derive_chain_key`; `classify_break` (lib.rs:2313) 复用 `master_key()` 访问器。

**v0.1.2 scope (2026-08-28):**
- **Issue #7 (redact pattern dump, P1-8):** `guard.redact.patterns.dump` IPC exposes 15 redaction pattern definitions read-only → `{patterns: [{name, regex, validator}]}`. `fg-redact::PatternDef` extended with `validator_tag: ValidatorTag` (serde `snake_case` enum `None|Ipv4|AwsSecret|Luhn|Phone` → `"none"|"ipv4"|"aws_secret"|"luhn"|"phone"`) + `pattern_str: &'static str` (Regex not serializable, carry original string). `defs` array 3-tuple → 5-tuple `(name, pat, validator, validator_tag, pattern_str)`. `Redactor::pattern_defs() -> Vec<PatternDefDump>` + `AuditEngine::pattern_defs()` passthrough + IPC handler (NOT tenant-gated — patterns global, not tenant-scoped). Priority order preserved (long credentials before id_number so first-accept wins on overlap). NO behavior change to redaction — dump only. Validator tag enum documented so consumers (fusion-gateway PII SSOT) re-implement validators from tag (algorithms small + documented), no fn-pointer leak. 3 IPC tests (returns_all_definitions / preserves_priority_order / validator_tags_exact). Non-blocking (fusion-gateway has vendored fallback + drift test). 177 tests pass (174 baseline + 3 new), clippy clean, fmt green, release green.
- **Issue #4 (cluster/multi-node consumer, PRD §4.1/§8.2):** upstream fusion-multi-nodes#52 MERGED (PR #54 fa2cb41) — multi-node defines TRANSPORT+IDENTITY+KEY SCHEME; guard implements **consumer** (per-host, NOT broker). New `fg-cluster` crate (14th): HKDF-SHA256 from `cluster_token` → 3 domain-separated MAC keys (info labels `b"fusion-multinode-{audit-chain,rule-epoch,confirm-relay}-v1"`, KEY_LEN=32, salt=None); `canonical_json` (sorted/compact/`ensure_ascii=False`); federated audit-chain verify (MAC + prev_hash double-tamper detect, degraded→baseline skip); `reqwest::blocking` HTTP client (5s timeout, Bearer auth, fail-closed). 4 IPC methods `guard.cluster.{audit.fetch, epoch.sync, confirm.relay, confirm.list}`. Missing token → `-32011` cluster-not-configured (single-node mode, non-silent). 19 tests (11 unit + 8 integration std-mock), 172 total pass, clippy clean.
- Version bump 0.1.1→0.1.2 across workspace + pyproject + __init__.py.

**v0.1.1 patch scope (2026-08-28):**
- **Issue #1/#3 (fusion-event `guard.audit` frozen contract, PRD §6.7 / D-10):** `AuditEngine::audit_event` + IPC `guard.audit`/`guard.audit_result`. Response `{decision: pass|block|challenge, reason, risk_level:int, audit_id, trigger_id}` — Allow/Redact/Preview→pass, Block→block, L3 requires_approval→challenge. risk_level = `RiskLevel::rank()` (0..3 int). audit_id = audit chain row PK (Uuid), trigger_id echoed. 4 tests (audit_event_test.rs). Live UDS smoke verified.
- **Issue #2 (PII 脱敏扩展):** fg-redact 13→15 patterns — email + ipv4 (+ Luhn-free valid_ipv4 validator), placed after credential patterns to avoid conn_string overlap regression.
- **Issue #5 (Python wheel 打包):** pyproject.toml (maturin build-backend, manifest-path → crates/fg-pyo3) + python/fusion_guard/__init__.py re-export wrapper (`NativeGuardClient` etc). `.gitignore` adds `*.whl`/`dist/`/`build/`.
- **Issue #4 (P2-5 cluster/multi-node):** landed in v0.1.2 (consumer side, multi-nodes#52 MERGED).
- Version bump 0.1.0→0.1.1 across workspace + Cargo.lock + pyproject + __init__.py. 153 tests pass (default), +11 semantic feature tests, clippy clean, fmt green.

Landed so far:
- Phase 0: 8-crate Cargo workspace + UDS JSON-RPC daemon + `start.sh` + CI + launchd plist (commit c9cf3cc).
- Phase 1 Checkpoint 1: SQLite WAL audit store — L3+/Block sync gate (H7, fail-closed), L1-L2 async batch (E4), multi-tenant isolation. Cross-restart durable.
- Phase 1 Checkpoint 2: Rule SSOT + epoch — guard is rule authority; epoch monotonically bumps on add/update/remove; rules + epoch persisted to SQLite, survive restart; `caller_epoch != 0 && != guard epoch` → `-32003` stale epoch. IPC: `guard.rule.list/add/update/remove`, `guard.rules.dump`. `guard.evaluate` takes `caller_epoch`.
- Phase 1 Checkpoint 3: Encrypted token store — reversible redact stores original AES-GCM-encrypted to `tokens` table in guard.db; key from macOS Keychain (service `fusion-guard`/account `token-key`) or `FUSION_GUARD_TOKEN_KEY` env hex (32 bytes) for dev/CI. in-flight flag (R3) protects token during reveal; TTL 300s, in-flight exempt. `guard.redact {content, reversible}` → `{redacted_content, token_map_id?}`; `guard.reveal {content, token_map_id}` → `{content}` (restores all `[REDACTED:type#tok_id]` placeholders). H6 fallback: missing/decrypt-failed token → `[REDACTED:unrecoverable#...]`, non-fatal. Cross-restart reveal works (encrypted落盘, key persistent).
- Phase 1 Checkpoint 4: `guard.confirm` + action_id — `guard.evaluate` assigns action_id to L3 (requires_approval) and L4 (Block) verdicts, persists pending action to `pending_actions` table (verdict_json, risk_level, created_ts, consumed, ttl_secs=30). `guard.confirm {action_id, approved, approved_by, tenant_id}` validates: L4 → reject `AbsoluteBlock` (H8, no confirm path); consumed → reject `Consumed` (one-time, H4); expired (created+ttl<now) → reject `Expired`. On valid: mark consumed, approve→`action:Allow`/reason "approved by X", reject→`action:Block`/reason "rejected by X"; appends `confirm` audit event (sync H7, outcome approved/rejected). Returns `{verdict: GuardVerdict}`. H8: L4 `requires_approval` 恒 false, no confirm path.
- Phase 2 Checkpoint 5: Stage 2 tokenizer + category inference + seatbelt flag — `fg-rules::tokenizer` module: `tokenize_check` (CheckStage::Ast) runs after regex; `split_chain` (&&/||/;/|/换行, quote-aware) + `shell_words::split` per segment → argv[0] basename → WHITELIST check → non-whitelist binary → Block L3; argv SENSITIVE_PATHS target check (mv/cp dest, cat/grep read-source, tee/chmod/cd, redirect `>`/`>>` target) → Block L4; credential filename (id_rsa/.pem/.key/.p12/.pfx/.keystore/.htpasswd) → Block L4; `..` escape → Block L4; shell substitution `$(...)`/backtick/process-sub `<(...)`/`<<<` → Block L3; `sed -i`/`find -exec`/`git config`-`-c`-`alias.` → Block L4. `RuleEngine::evaluate_full` merges regex + tokenizer hits (regex-only `evaluate` preserved for unit tests). `RuleEngine::infer_category` (H9): argv[0]=rm/sh/dd/diskutil→`shell_exec`, curl/wget/scp/ssh→`network`, redirect-to-sensitive→`file_write`; guard infers from content, caller is hint only. `verdict_from_hits` sets `seatbelt_required=true` for L3/L4 or Block (E7 — flag not profile text). SENSITIVE_PATHS extended with `~/.config`/`~/.fusion` (PRD §7.5). Convergence source: `fusion-executor/crates/fe-security` (read-only copy). tree-sitter Stage 3 语义阶段 NOW LANDED (feature=semantic, see Phase 7 below); MVP 命令扫描仍用 shell-words (Stage 2).
- Phase 5: TCC audit aggregation (H1, PRD §9) + Swift bridge — guard does NOT broker TCC (macOS per-app model; each subproject self-requests). guard does two things: (1) `guard.tcc.status` queries 6 services (Accessibility/ScreenRecording/FullDiskAccess/Microphone/Camera/AppleEvents) via Swift bridge `@_cdecl` FFI compiled to static lib (`fg-tcc-bridge`, the workspace's only `unsafe_code = "allow"` crate; `fg-tcc` stays `deny`); Swift unavailable → C stub fallback (`cfg(tcc_bridge_stub)`, build.rs emits via `cargo:rustc-cfg`). `source` field tags `swift-bridge:live` vs `tccutil:stub`. (2) `guard.tcc.report {permission, requester, result, reason}` persists TCC request result to `tcc_events` table (audit aggregation only, not authorization) → `{audit_id}`; `guard.tcc.events {limit?}` queries. fg-store adds `report_tcc_event`/`list_tcc_events` + `TccEventRecord` + `tcc_events` table + indexes. fg-tcc adds `TccService` enum (`as_str`/`parse`), `TccStatus`, `TccEvent`, `query_status`. build.rs uses `std::env::var` (runtime, not `env!` compile-time); links ApplicationServices/CoreGraphics/AVFoundation/Foundation frameworks on live path. **CRITICAL**: tests must set `FUSION_GUARD_TOKEN_KEY` env (hex, 32 bytes) or `AuditStore::open` → `TokenStore::load_or_create_key` → macOS Keychain `SecItemCopyMatching` BLOCKS (hangs 60s+ in non-interactive env). `ensure_env_key()` helper in store_test.rs/tcc_store_test.rs.

Verification: `cargo build` (debug+release) pass, `cargo test` 60 pass (10 rule + 21 tokenizer + 3 store + 2 tcc_store + 6 token + 6 redact + 6 action + 6 tcc), clippy clean (0 warning). Runtime smoke (isolated FUSION_GUARD_DATA_DIR+SOCK+TOKEN_KEY): `guard.tcc.status`→6 services, source `swift-bridge:live`, real authorized states (Camera/AppleEvents=false, rest=true); `guard.tcc.report`→audit_id persisted; `guard.tcc.events`→retrieves by audit_id, all fields intact.

- Phase 7 (audit chain hash, PRD §13.3): each `audit_events` row carries `prev_hash` + `event_hash` (SHA-256 of prev_hash ‖ 11-field payload joined by `\x1f`); next row's prev_hash = prior row's event_hash → append-only tamper-evident chain. **Single serialized insert path**: `AuditStore` now owns `audit_writer: Arc<Mutex<Connection>>` (was two-writer split: `self.db` sync + `writer_conn` async → both read same prev_hash → chain fork risk); ALL audit inserts (sync high-risk H7 + async low-risk batch) funnel through it; `insert_audit_event` reads last `event_hash` inside the lock then computes current hash. `guard.audit.verify` re-hashes full table `ORDER BY rowid ASC`, returns `{total_rows, unhashed_rows, verified_links, broken_links, tampered, first_broken_at}`. `migrate_audit_chain` idempotent `ALTER TABLE ADD COLUMN ... DEFAULT ''` for pre-chain DBs; empty-hash legacy rows counted as `unhashed_rows` (not tamper), no backfill (append-only honored). `sha2 = "0.10"` added to workspace + fg-store deps.

Verification: `cargo build` (debug+release) pass, `cargo test` 64 pass (10 rule + 21 tokenizer + 3 store + 4 chain + 2 tcc_store + 6 token + 6 redact + 6 action + 6 tcc), clippy clean (0 warning). Runtime smoke (isolated FUSION_GUARD_DATA_DIR+SOCK+TOKEN_KEY): `guard.evaluate` rm-rf → Block L4 action_id assigned; `guard.evaluate` curl|sh → Block; `guard.audit.verify` → `{total_rows:2, verified_links:2, broken_links:0, tampered:false}`.

- Phase 7 (tree-sitter Stage 3 语义, PRD §7.4 R5): `feature = "semantic"` (default OFF — MVP "需时再引且锁版本") enables code-content scanning via tree-sitter multi-grammar. Versions locked: tree-sitter 0.25 + grammars 0.23 (python/javascript/typescript/rust), aligned to `fusion-executor` workspace Cargo.lock segment (§7.4 grammar drift guard). `fg-rules::semantic` module (`#![cfg(feature = "semantic")]`): `semantic_check(content)` tries Python → JS → TS → Rust grammar (first non-empty wins); each scans for dangerous calls via danger tables (PY_L4: os.system/os.popen/os.exec*/subprocess.*; PY_L3: eval/exec/compile/__import__/pickle.loads/ctypes.CDLL; JS_L4: child_process.exec/spawn/execSync; JS_L3: eval/Function; RS_L4: Command::new/remove_dir_all; RS_L3: unsafe). `SemanticHit` → `RuleHit` with `stage=CheckStage::Semantic`, `scope=RuleScope::Content`, `name=semantic:<lang>:<callee>`. `RuleEngine::evaluate_full` merges Stage 3 hits after regex + AST (Stage 1+2). `semantic_default_rules()` seeds 6 default GuardRules. Feature forwarding chain: fg-bin → fg-audit-engine → fg-rules/semantic. Build runtime: `cargo build -p fg-bin --features semantic --release`.

Verification: `cargo test -p fg-rules --features semantic` 11 pass (python_os_system_blocks_l4, python_subprocess_blocks_l4, python_eval_l3, python_clean_no_hit, js_eval_l3, js_child_process_l4, rust_command_new_l4, rust_clean_no_hit, semantic_verdict_block, semantic_check_python_direct, semantic_check_empty). `cargo build` (debug+release default + semantic) pass, clippy clean. Runtime smoke (feature=semantic): `guard.evaluate` Python content `os.system("rm -rf /")` → Block L4, stage=Semantic, category=semantic:py:os.system.

- Phase 7 (PyO3 binding, Q#4): `fg-pyo3` crate exposes guard to Python as `NativeGuardClient` (`#[pyclass]`). **Design: UDS JSON-RPC CLIENT wrapper, NOT in-process AuditEngine** — in-process = per-Python-process epoch fragmentation → violates Checkpoint 2 SSOT. Client connects to running daemon at `/tmp/fusion-guard.sock` (env `FUSION_GUARD_SOCK`). `UdsClient::call` synchronous blocking (std `UnixStream`, `BufReader::read_until(0x0A)`, 2s read/write timeout, 1MiB cap) — matches Python blocking model. `pyo3 = "0.29"` (Python 3.14 support, aligned to `fusion-executor` fe-pyo3). crate-type = `["cdylib","rlib"]` under `[lib]` (cdylib = maturin target, rlib = in-process tests). Methods: ping, evaluate(content, caller_epoch=0, tenant_id=None, requester=None), list_rules, redact, reveal, confirm, tcc_status, tcc_events, audit_verify. `version_info()` `#[pyfunction]`. `#[pymodule] fn _native`. **Error null handling**: server serializes `Option<RpcError>` → `{"error":null}` on success; client must pattern-match `Value::Object` (not just `resp.get("error")` which returns `Some(Null)`). **Verdict serialization**: `serde_json::to_value(&verdict)` → SafetyAction/RiskLevel serialize PascalCase (`Block`/`L4`), NOT lowercase.

Verification: `cargo test -p fg-pyo3` 4 pass (ping_roundtrip, evaluate_block_returns_verdict, stale_epoch_rejected [-32003], audit_verify_roundtrip). **CRITICAL**: tests use `#[tokio::test(flavor = "multi_thread", worker_threads = 2)]` — default current-thread runtime starved by synchronous blocking `UdsClient::call` (spawned server task never scheduled → 2s timeout EAGAIN). Tests set `FUSION_GUARD_TOKEN_KEY` + temp data dir + unique socket `/tmp/fg-pyo3-<pid>-<8char>.sock`. `cargo build` (debug+release) pass, clippy clean.

- Phase 7 (Endpoint Security, Q#3): `fg-es` + `fg-es-bridge` crates. macOS ES framework monitors high-risk system events (exec/file_write/rename/unlink/socket_open). **Entitlement constraint**: ES client needs `com.apple.developer.endpoint-security.client` entitlement (Apple developer agreement + provisioning). No entitlement → real ES C FFI cannot run (ESNewClient returns permission error) → **degrade to TCC runtime prompt** (Phase 5 covers TCC — PRD Q#3). Build pattern mirrors `fg-tcc-bridge`: `fg-es-bridge` is the sole `unsafe_code = "allow"` ES crate (FFI required); `fg-es` stays `deny` (safe types only). `fg-es-bridge/build.rs` defaults to C stub mode (`compile_stub` writes `int fg_es_new_client(void){return 0;}` + `fg_es_event_count`, compiles via cc → `libfgesbridge.a`, emits `cargo:rustc-cfg=es_bridge_stub`). **cfg propagation**: `cfg!(es_bridge_stub)` only visible in the crate whose build.rs emits it; `fg-es` uses `fg_es_bridge::is_stub() -> bool { cfg!(es_bridge_stub) }` (NOT its own cfg!). `fg-es` types: `EsEventKind` (Exec/FileWrite/Rename/Unlink/SocketOpen) + `as_str`/`parse`, `EsEvent`, `EsMonitorState` (Active/Degraded/Inactive), `EsStatus::degraded()` (state=Degraded, source="es-bridge:stub", entitlement=false), `EsMonitor` (new/start/stop/status/monitor_events — stub returns Degraded + empty events with warn log "fall back to TCC (PRD Q#3)"), `default_kinds()`. Workspace `unexpected_cfgs` check-cfg includes `cfg(es_bridge_stub)`. Real ES binding (ESNewClient/ESSubscribe) deferred until entitlement provisioned.

Verification: `cargo test -p fg-es` 6 pass (event_kind_roundtrip, monitor_degraded_without_entitlement [Degraded, not Active], degraded_monitor_no_events, status_reflects_stub, es_status_degraded_constructor, stop_clears). `cargo build` (debug+release) pass, clippy clean. Stub path verified: `EsMonitor::start()` → `EsStatus::degraded()`, `monitor_events()` → empty.

- **Soak + drain→retention fix (商用阻塞点 #6, 2026-08-28):** `crates/fg-ipc/tests/soak_test.rs` child-process 长跑压测: spawn `target/release/fusion-guard start` 子进程 (隔离 SOCK+DATA_DIR+TOKEN_KEY+LOG_DIR+ALLOW_ENV_KEY), 48 并发 std client 线程循环 `guard.evaluate` 跑 10s, 每 2s 采子进程 RSS (`ps -o rss= -p <pid>`, 量纯 daemon 无客户端污染) + DB 磁盘占用。子进程模式非 in-process (in-process 含客户端线程栈+debug 膨胀)。缺 release binary → 自动 skip 不挂全套 cargo test。断言: 吞吐≥5000/10s, err<1%, p50≤25ms, p99≤200ms, DB≤200MB (rotation 有界), RSS≤1200MB (容 libmalloc 不归还+tokio 池驻留)。fail-closed 用例 (`rm -rf /`) 验 Block L4 高并发不误判 allow。**实测**: 10s `total=43539 err=0 p50=5ms p99=58ms rss=576MB db=23MB`; 30s `total=107k err=48 p50=5ms p99=82ms rss=1171MB db=65MB` (全 PASS, 延迟不退化)。
- **drain→retention 缺口 (REAL BUG FIXED):** `AuditStore::open` 原 `enforce_retention` 只在高风险 `append_event` 同步路径调 (P0-4); drain 线程只插 L1/L2 低风险行 (`low_writer` batch insert), 不触 rotation → 高频低风险流量下 audit_events 无界增长 → 长跑 OOM。Fix: `spawn_retention_monitor(self: &Arc<Self>, interval_secs)` 周期线程调 `enforce_retention` 覆盖低风险积累路径。`fg-bin run_server` wired `audit.spawn_retention_monitor(5)` (5s — drain 高频写入, 60s 太慢突发已超阈值)。
- **rotate 锁优化 (soak 发现的性能退化):** `rotate_old_rows` 原实现整段持 `audit_writer` 锁 (line 953 `let w = audit_writer.lock()` 开头) 跑 COUNT 扫表 + SELECT 选行, 即使无 rotate 也锁住所有审计写 → append_event 高风险同步路径自 DoS + 5s monitor 持锁空查吞吐骤降 (30s soak throughput 86k p99=103ms)。Fix: 检查阶段 (COUNT 超龄行 + `fs::metadata` db_bytes 判阈值) + 选待归档行改用 `read_conn` (query_only=ON, 不抢 `audit_writer` 写锁), 仅删行 + checkpoint 写 + VACUUM mutate 段锁 `audit_writer`。TOCTOU 安全: rowid 单调增, 读到的旧 rowid 不被并发插入删除, 删按 rowid 区间 `[min_rid, last_archived_rowid]`, 新插 rowid>max 不受影响。实测优化后 30s soak: throughput 107k (+24%), p99 82ms (−20ms), RSS 1171MB, DB 65MB。
- **tokio runtime 硬化 (fg-bin):** `main` 从 `#[tokio::main]` (默认 max_blocking_threads=512 × 2MB 栈 = 潜在 1GB) 改显式 `Builder::new_multi_thread().max_blocking_threads(64).thread_stack_size(256*1024)`。实际并发 handler ≤ MAX_CONCURRENT_REQS=16, 512 纯浪费。worker_threads=CPU 核数保持 (异步 IO), blocking 池独立给 spawn_blocking。非 RSS 根因 (实测改后 RSS 不降) 但 sensible 硬化。
- **RSS 根因结论:** RSS 增长 = SQLite B-tree + page cache 跟踪 audit_events 表增长 + macOS libmalloc 不归还小对象页 (MADV_FREE retained), 非 guard 逻辑泄漏 (已证: DB 数据 rotation+VACUUM 有界, 延迟不退化, 错误率低)。drain→retention 缺口是唯一可修真 bug。

The product contract lives in the monorepo PRD: `/Users/dahai/fusion/fusion-guard-prd-plan-v2-0826.md` (v0.2 — the implementation spec; supersedes the v0.1 audit target at `architecture/fusion-guard-prd-0826.md`). Read it before any implementation work; it is the single source of truth for scope, mechanism, and API shape.

## Crate Layout (landed)

```
crates/
├── fg-core           # RiskLevel/SafetyAction/CheckStage(Regex|Ast|Semantic)/RuleScope/GuardVerdict/GuardError (core types)
├── fg-rules          # regex-stage rule engine + Stage 2 tokenizer (AST) + Stage 3 tree-sitter 语义 (feature=semantic): mutable add/update/remove + epoch bump + stale-epoch check + RuleSet + category inference
├── fg-audit-engine   # verdict synthesis + redact联动 + rule persistence + TCC audit aggregation orchestration (owns Arc<AuditStore>)
├── fg-redact         # dynamic masking: api_key/password/id_number/private_key, reversible/irreversible, placeholder extraction
├── fg-tcc            # TCC status aggregation (status-only, no brokering — H1) + TccService/TccStatus/TccEvent types
├── fg-tcc-bridge     # Swift FFI: @_cdecl TCC status queries, compiled to static lib via build.rs, C stub fallback (unsafe_code=allow)
├── fg-es             # Endpoint Security 高危系统事件监控: EsEventKind/EsEvent/EsMonitorState/EsStatus/EsMonitor (safe types, unsafe_code=deny)
├── fg-es-bridge      # ES C FFI 桥: 无 entitlement → C stub 兜底 (cfg(es_bridge_stub), degraded → TCC — Q#3), unsafe_code=allow, is_stub() exposes cfg to fg-es
├── fg-ipc            # UDS JSON-RPC server: 2s timeout fail-closed, 64 conn, rate limit; guard.evaluate/rule.*/tcc.status/tcc.report/tcc.events/audit/redact/reveal/confirm/cluster.* (audit.fetch/epoch.sync/confirm.relay/confirm.list)
├── fg-store          # SQLite WAL: audit_events append-only (链式 hash 防篡改) + rules/rule_meta + encrypted token store (AES-GCM) + pending action store (H4) + tcc_events table
├── fg-pyo3           # PyO3 绑定: NativeGuardClient (UDS JSON-RPC 客户端暴露 Python, 对齐 fe-pyo3, pyo3 0.29, cdylib+rlib)
├── fg-cluster        # 跨节点消费方 (issue #4 / multi-nodes#52): HKDF 域分离 3 MAC key + federated 链验证 (MAC+prev_hash) + reqwest::blocking HTTP 客户端 (5s, Bearer, fail-closed); per-host 非 broker
└── fg-bin            # fusion-guard binary: start/ping subcommands
```

Workspace lint: `unsafe_code = "deny"` (fg-tcc-bridge + fg-es-bridge are the sole `allow` crates — FFI requires it; fg-tcc + fg-es stay deny). Workspace-level `[workspace.lints.rust] unexpected_cfgs = { level = "allow", check-cfg = ['cfg(tcc_bridge_stub)', 'cfg(es_bridge_stub)'] }` for the stub cfgs.

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
