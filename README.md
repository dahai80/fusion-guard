# fusion-guard

English | [中文](README_CN.md)

Zero-trust action authorization daemon for the Fusion local AI OS. Intercepts high-risk Agent side-effects (`rm -rf`, silent exfiltration), dynamically masks sensitive fields (API keys, passwords, ID numbers, private keys), and aggregates macOS TCC permission audit.

**PRD source**: `/Users/dahai/fusion/architecture/fusion-guard-prd-plan-v2-0826.md` (v0.2)

## Status

Phase 2 complete, Phase 5 (TCC audit aggregation + Swift bridge) complete, Phase 7 (audit chain hash + PyO3 + Endpoint Security + tree-sitter semantic stage) complete. 14-crate Cargo workspace + UDS JSON-RPC daemon + SQLite WAL audit + rule SSOT/epoch persistence. Current version **v0.2.0-rc.2** (H-E master-key loss vs real tamper distinction + pong:bool contract fix + 7/7 upstream integration issues all closed, code-level production-ready).

| Acceptance item | Status |
|-----------------|--------|
| `cargo build` (debug + release) | ✅ |
| `./start.sh start` launches UDS server | ✅ |
| `guard.ping` roundtrip | ✅ |
| SQLite WAL audit (L3+ sync / L1-L2 async) | ✅ |
| Rule SSOT + epoch persistence (cross-restart) | ✅ |
| Stale epoch rejected (-32003) | ✅ |
| Encrypted token store (AES-GCM + Keychain/env key) | ✅ |
| guard.redact / guard.reveal roundtrip restore | ✅ |
| Cross-restart reveal (encrypted persisted, H6) | ✅ |
| Reveal fault-tolerant fallback (H6) | ✅ |
| guard.confirm + action_id one-time consume (H4 TTL) | ✅ |
| L4 absolute block, no confirm path (H8) | ✅ |
| Confirm audit (approved/rejected) | ✅ |
| Stage 2 tokenizer (shell-words, AST stage whitelist + sensitive paths) | ✅ |
| Category inference (H9: argv[0]→shell_exec/network/file_write) | ✅ |
| seatbelt_required flag (E7: L3+ / Block marked) | ✅ |
| SENSITIVE_PATHS/WHITELIST converged (incl. ~/.config/~/.fusion) | ✅ |
| TCC status aggregation (Swift bridge, status-only — H1) | ✅ |
| guard.tcc.report (audit aggregation persisted) | ✅ |
| guard.tcc.events (TCC audit query) | ✅ |
| Audit chain hash tamper-evidence (PRD §13.3) | ✅ |
| guard.audit.verify (chain integrity check, incremental P0-4 + all-chain aggregation P0-5) | ✅ |
| Audit rotation (100MB/30d archive NDJSON) + retention (180d delete archive) | ✅ |
| Stage 3 tree-sitter semantic stage (feature=semantic, multi-grammar code scan) | ✅ |
| PyO3 binding fg-pyo3 (UDS client exposed to Python, aligned fe-pyo3) | ✅ |
| Endpoint Security fg-es (stub degraded, no entitlement → TCC — Q#3) | ✅ |
| guard.es.status / guard.es.events (IPC exposed, honest degraded report — P0-7) | ✅ |
| guard.audit (fusion-event frozen contract D-10, pass/block/challenge tri-state) | ✅ |
| guard.audit_result (challenge callback receipt) | ✅ |
| PII masking expansion (email/ipv4/bank-card, issue #2) | ✅ |
| Python wheel packaging (maturin pyproject.toml, issue #5) | ✅ |
| Cross-node cluster consumer fg-cluster (HKDF domain-separated 3 MAC keys + federated chain verify, issue #4 / multi-nodes#52) | ✅ |
| guard.cluster.audit.fetch / epoch.sync / confirm.relay / confirm.list (4 IPC) | ✅ |
| shared secret macOS Keychain source + release gate H-C (--insecure-secret-env / ALLOW_INSECURE_SECRET, ALLOW_NO_SECRET emergency) | ✅ |

## Architecture

14-crate Rust workspace (aligned with fusion-executor layout):

```
crates/
├── fg-core           # Core types: RiskLevel/SafetyAction/GuardVerdict/GuardError/CheckStage(Regex|Ast|Semantic)
├── fg-rules          # Rule engine: regex stage + AST tokenizer stage + Stage 3 tree-sitter semantic stage (feature=semantic) + epoch + RuleSet + category inference
├── fg-audit-engine   # Audit engine: rule evaluation + redact coordination + verdict synthesis + TCC audit aggregation orchestration
├── fg-redact         # Dynamic masking: api_key/password/id_number/private_key, reversible/irreversible, placeholder extraction
├── fg-tcc            # TCC status aggregation (status-only, no brokering — H1) + event types
├── fg-tcc-bridge     # Swift FFI: @_cdecl TCC status queries, compiled to static lib, C stub fallback (unsafe allow)
├── fg-es             # Endpoint Security high-risk system event monitoring (safe types + degraded state, unsafe deny)
├── fg-es-bridge      # ES C FFI bridge: no entitlement → C stub fallback (cfg(es_bridge_stub), degraded → TCC — PRD Q#3), unsafe allow
├── fg-ipc            # UDS JSON-RPC server + 2s timeout + 64 conn + rate limit
├── fg-store          # SQLite WAL: audit append-only (chain hash) + rule persistence + encrypted token store (AES-GCM) + pending action store (H4) + tcc_events
├── fg-pyo3           # PyO3 binding: UDS JSON-RPC client exposed to Python (NativeGuardClient), maturin target, aligned fe-pyo3 (cdylib+rlib)
├── fg-cluster        # Cross-node consumer (issue #4 / multi-nodes#52): HKDF domain-separated 3 MAC keys + federated chain verify (MAC+prev_hash double tamper detection) + reqwest::blocking HTTP client (5s, Bearer, fail-closed); per-host not broker
└── fg-bin            # fusion-guard binary: start/ping subcommands
```

## Cross-node Cluster Consumer (issue #4 / multi-nodes#52, PRD §4.1/§8.2)

fusion-multi-node defines TRANSPORT + IDENTITY + KEY SCHEME (PR #54 MERGED); fusion-guard implements the **consumer** (per-host, not broker). 100% local/LAN, no cloud.

- **Key scheme** (`fg-cluster::key`): HKDF-SHA256 derives 3 MAC keys from `cluster_token` (env `FUSION_GUARD_CLUSTER_TOKEN`) with domain separation, info label `b"fusion-multinode-{audit-chain,rule-epoch,confirm-relay}-v1"` (KEY_LEN=32, salt=None). `canonical_json` (sorted keys + compact + `ensure_ascii=False`) ensures deterministic MAC input. `mac_payload` (HMAC-SHA256→hex), `verify_mac` (constant-time, empty→false).
- **Primitive 1 — federated audit chain verify** (`fg-cluster::verify`): each record carries `seq` / `prev_hash` (= sha256 of the full prior record incl mac) / `mac` (= HMAC over record minus mac). Double tamper detection: field flip → MAC mismatch + next record's prev_hash breaks chain. Degraded records (missing chain fields) → baseline skip. `verify_chain_segment` → `{total_records, verified_links, broken_links, baseline_records, tampered, first_broken_at}`.
- **Primitive 2 — cluster rule epoch reconcile**: `guard.cluster.epoch.sync` — local>cluster → advance cluster epoch to align (leader-only, non-leader 409 best-effort); local<cluster → `local_behind`; equal → `in_sync`. Extends Checkpoint 2 SSOT to the cluster domain.
- **Primitive 3 — confirm relay aggregation**: `guard.cluster.confirm.relay` constructs a MAC and relays to master; `guard.cluster.confirm.list` queries aggregation.
- **IPC**: `guard.cluster.audit.fetch {since_seq}` / `epoch.sync` / `confirm.relay` / `confirm.list`. Missing `FUSION_GUARD_CLUSTER_TOKEN` (single-node) → `-32011` cluster-not-configured, non-silent.
- **HTTP client**: `reqwest::blocking` (handle_method runs in spawn_blocking on an independent thread, not a tokio worker, blocking-IO safe), 5s timeout, Bearer `cluster_token` auth, non-2xx fail-closed.

## Stage 3 Semantic Stage (tree-sitter, PRD §7.4 R5)

Enabled via `feature = "semantic"` (off by default, MVP uses shell-words only — PRD "introduce when needed, lock version"). Code content (not commands) scanned for dangerous calls via tree-sitter multi-grammar:

```
content (code)
  │
  ▼
semantic_check (fg-rules::semantic, feature=semantic)
  ├── Python grammar (tree-sitter-python 0.23): os.system/subprocess.*/eval/exec/__import__/pickle.loads → L4/L3
  ├── JavaScript grammar (tree-sitter-javascript 0.23): eval/Function/child_process.exec → L3/L4
  ├── TypeScript grammar (tree-sitter-typescript 0.23): same as JS
  └── Rust grammar (tree-sitter-rust 0.23): Command::new/remove_dir_all → L4
  │
  ▼
evaluate_full merges: regex (Stage 1) + tokenizer (Stage 2) + semantic (Stage 3) → max risk verdict
```

- **Version lock**: tree-sitter 0.25 + grammars 0.23, aligned with `fusion-executor` workspace Cargo.lock segment (PRD §7.4 grammar drift guard).
- **Off by default**: `default = []`. Enable: `cargo build -p fg-bin --features semantic --release`. Forwarding chain fg-bin → fg-audit-engine → fg-rules/semantic.
- **CheckStage::Semantic**: hit verdict `stage=Semantic`, `inferred_category=semantic:<lang>:<callee>`, `scope=Content`.

## Risk Levels (4-tier)

| Level | Behavior | Example |
|-------|----------|---------|
| L1 | Allow (autonomous) | Read non-sensitive file |
| L2 | Preview/Redact | Content with sensitive fields |
| L3 | Gateway human confirmation | Delete file, HTTP request |
| L4 | **Block (absolute, no confirm path — H8)** | `rm -rf` recursive delete |

## Two-stage Validation (Stage 1 Regex + Stage 2 Tokenizer)

```
content
  │
  ▼
Stage 1 (Regex, fg-rules::evaluate)
  ├── Hits blocklist rule (rm -rf / curl|sh / sudo / dd / git force-push etc.) → direct Block (L4)
  └── No hit → proceed to Stage 2
  │
  ▼
Stage 2 (Tokenizer, fg-rules::tokenizer::tokenize_check, shell-words MVP)
  ├── Command substitution $(...)/backtick / process substitution <(...) → Block (L3)
  ├── split_chain splits on &&/||/;/|/newline (quote-aware single/double)
  ├── shell_words::split per segment → argv[0] basename → WHITELIST check
  │     └── Non-whitelist binary (nc/scp/rm etc.) → Block (L3, sensitive_target=false)
  ├── argv sensitive path check (mv/cp destination / cat/grep read-source / tee/chmod/cd arg / redirect target)
  │     └── Hits SENSITIVE_PATHS → Block (L4, sensitive_target=true)
  ├── Credential filename (id_rsa / .pem / .key / .p12 / .pfx / .keystore / .htpasswd) → Block (L4)
  ├── .. path escape (cat/grep read-source contains .. component) → Block (L4)
  └── sed -i / find -exec / git config/-c/alias → Block (L4)
```

**Category inference (H9)**: guard infers category from content, not caller declaration. argv[0]=rm/sh/dd/diskutil→`shell_exec`, curl/wget/scp/ssh→`network`, redirect to sensitive path→`file_write`. Final level = max(inferred, rule hit, hint).

**seatbelt_required (E7)**: verdict marks `seatbelt_required:true` for L3/L4 or Block (flag, not profile text). executor decides whether to compile a seatbelt profile based on this.

**Convergence source**: SENSITIVE_PATHS/WHITELIST/tokenizer logic aligned with `fusion-executor/crates/fe-security` (read-only convergence, extended `~/.config`/`~/.fusion` per PRD §7.5). tree-sitter Stage 3 semantic stage landed (feature=semantic, see §Stage 3 above); MVP command scan still uses shell-words (Stage 2).

## TCC Audit Aggregation (H1, PRD §9)

guard does **not broker** TCC — macOS per-app model, each subproject requests its own permissions. guard does two things:
- **Status query**: `guard.tcc.status` queries 6 services (Accessibility/ScreenRecording/FullDiskAccess/Microphone/Camera/AppleEvents) via Swift bridge (`@_cdecl` FFI, compiled to static lib). Swift unavailable → C stub fallback (`cfg(tcc_bridge_stub)`).
- **Audit aggregation**: `guard.tcc.report` records each project's TCC request result to `tcc_events` table, `guard.tcc.events` queries. `source` field tags origin (`swift-bridge:live` / `tccutil:stub`).

```
subproject self-requests TCC (macOS per-app)
        │  result reported
        ▼
guard.tcc.report → tcc_events table (audit aggregation, not authorization)
guard.tcc.status → Swift bridge → status (6 services)
```

fg-tcc-bridge is the workspace's only `unsafe_code = "allow"` crate (FFI requires it); fg-tcc stays `deny`. Swift compile failure auto-degrades to stub, build.rs emits `cargo:rustc-cfg=tcc_bridge_stub`.

## Audit Chain Hash Tamper-evidence (PRD §13.3)

Each audit event carries a chain hash (prior row's `event_hash` enters next row's `prev_hash`), preventing post-hoc tampering/deletion of audit rows:

```
event_1: prev_hash=genesis(000…0),  event_hash=SHA256(genesis || payload_1)
event_2: prev_hash=event_hash_1,    event_hash=SHA256(event_hash_1 || payload_2)
event_3: prev_hash=event_hash_2,    event_hash=SHA256(event_hash_2 || payload_3)
```

- **payload** = 11 fields (`audit_id/ts/event_type/tenant_id/requester/action/inferred_category/verdict_json/approved_by/seatbelt_required/outcome`) joined by `\x1f`. Modifying any field → `event_hash` mismatch → detected.
- **Single serialized connection**: all audit inserts (sync high-risk + async low-risk) go through one `Arc<Mutex<Connection>>`; inside the lock, reads the prior row's `event_hash` → computes current hash. Eliminates chain fork from concurrent prev_hash reads.
- **`guard.audit.verify`**: incremental verification (P0-4) — `chain_checkpoint` caches the last verified row's `audit_id`+`event_hash`; this call only verifies the new segment after that row, O(new delta) not O(full table). Anchor uses `audit_id` (UUID, stable after VACUUM reorders rowid). Degradation conditions (full table scan for safety): no checkpoint; anchor row archived/deleted (audit_id missing); hash mismatch; tamper detected (recompute full table to locate `first_broken_at`, no bad-point caching). Returns `{total_rows, unhashed_rows, verified_links, broken_links, tampered, first_broken_at, key_version_unknown_rows}` (aggregated `verify_all_chains` adds `key_loss` + each sub-chain result). `key_version_unknown_rows`/`key_loss` see §H-E below.
- **Migration compat**: legacy DB without `prev_hash`/`event_hash` columns → `migrate_audit_chain` idempotent `ALTER TABLE ADD COLUMN`(DEFAULT ''). Empty-hash rows counted as `unhashed_rows`, not false tamper. Append-only, no backfill of historical rows.
- **Dependency**: `sha2 = "0.10"` (workspace dep).

### Rotation / Retention / Incremental Verification (P0-4, PRD §13.3)

The audit DB grows linearly with events; unbounded growth slows verify + exhausts disk. Governance in three stages:

- **Rotation (archive trigger)**: `enforce_retention` called after each audit write. Trigger when either: DB size > `ROTATE_BYTES` (100MB) OR rows exist with `ts < now - ROTATE_AGE_DAYS` (30d). On trigger → aged rows exported to NDJSON archive file (`<archive_dir>/audit-YYYYMMDDTHHMMSS.ndjson`, 0o600), single-transaction row delete + `VACUUM` reclaims pages. Archive file carries full chain fields (prev_hash/event_hash), independently re-verifiable across archives.
- **Retention (cold-store expiry)**: same scan of archive dir; `.ndjson` files whose filename timestamp exceeds `RETENTION_DAYS` (180d) deleted (by filename not mtime — mtime forgeable via touch/cp). Production archive dir `~/.fusion-guard/audit-archive/` (env `FUSION_GUARD_ARCHIVE_DIR` overrides).
- **Archive-boundary chain continuity**: after archive, the remaining first row's `prev_hash` points to an archived row (dangling within main DB). Full-table verify would false-report broken → so after archive a checkpoint anchors the remaining first row (incremental, skips dangling segment). Empty-DB archived state (entire segment archived+deleted): checkpoint uses an empty `last_verified_audit_id` sentinel + `last_archived_hash`; verify continues from the archive segment's last hash as `expected_prev`; next insert also reads `last_archived_hash` as `prev_hash` (continues chain, not genesis).
- **Per-store archive dir**: not a global env — `resolve_archive_dir(db_path)` resolves from db's sibling `audit-archive/` (env override still takes priority). Isolates concurrent test stores from racing on one env; production single-daemon single-DB single-archive-dir semantics unchanged.
- **Retention monitor (drain path coverage)**: `enforce_retention` was only called on the high-risk `append_event` sync path; the drain thread only inserts L1/L2 low-risk rows without triggering rotation → audit_events unbounded growth under high-volume low-risk traffic. Daemon startup `spawn_retention_monitor(interval_secs=5)` periodically calls `enforce_retention` covering low-risk accumulation (commercial blocker #6, found via soak).
- **Rotate lock optimization**: `rotate_old_rows` check phase (COUNT aged rows + db_bytes threshold check) + selecting rows to archive now uses `read_conn` (query_only, does not take `audit_writer` write lock); only row delete + checkpoint + VACUUM mutate section locks `audit_writer`. Original impl held the write lock for the entire span including empty checks → append_event high-risk sync path self-DoS + 5s monitor holding lock for empty queries tanked throughput. 30s soak: throughput +24%, p99 −20ms. TOCTOU safe: rowid monotonically increases, delete by rowid range, concurrent inserts unaffected.

### H-E: Master-key Loss Single-point Fatal (product-audit-0827, 2026-08-29)

Master key loss = all historical audit chain verification fails (false tamper report) + reversible tokens undecryptable, indistinguishable from real tampering. Four remediation items:

- **(a) Refuse silent remint**: Keychain miss + DB already has historical data → `load_keychain_or_err` refuses startup with explicit error (not silently regenerating a new key rendering all history undecryptable); only virgin DB allows first-time generation.
- **(b) Key escrow**: after first mint, immediately export the Keychain master to an offline backup; on loss, restore the **same** key → anchors match → no false tamper (ops procedure, see `DEPLOYMENT.md` §Master Key Escrow, no daemon code).
- **(c) `rotate_key` historical rows verifiable (no re-hash)**: `rotate_key` = bump `key_version` (master unchanged, HKDF derives per version). Old rows record old version, verified with old derived key (deterministic HKDF, same master recomputable) → after rotation historical rows verifiable/decryptable. **Re-hashing the audit chain is deliberately rejected**: hash immutability = tamper-evidence guarantee; re-signing defeats the purpose and cannot distinguish real tamper from ops re-hash.
- **(d) Key loss vs real tamper distinction**: per-version `key_versions.key_anchor` anchor (HMAC of a fixed message under `derive_chain_key(master, version)`). On HMAC mismatch, verify calls `classify_break`: anchor **matches** current-master recompute → real tamper (`tampered=true`); **mismatches** → key loss (`key_version_unknown_rows++`, not counted as tampered); **NULL** (legacy) → fail-closed tamper (attacker stripping the anchor has no hiding place). `guard.audit.verify` adds `key_version_unknown_rows` (single chain) + `key_loss` (aggregated) fields. Tests `he_key_loss_distinguish_test.rs` (4 cases) + `he_key_loss_test.rs` (5 decision-gate cases).

## Security Audit Hardening (audit-0827)

Per `audit/fusion-guard-audit-0827.md` (static adversarial review, verdict NO-BLOCK → re-reviewed after fixes), landed in three waves. All defects (P0 release-blocking + P1 first sprint + P2 tech debt) fixed; `cargo build`/`cargo test`/`cargo clippy` all green.

### P0 — Release-blocking (9 groups)

- **Auth baseline (E6/C1/C2 + P0-1)**: after `accept`, `getpeereid` (macOS) / `SO_PEERCRED` (Linux) reads peer uid; non-daemon uid rejected for all non-ping methods; **peercred→tenant binding** (`tenant_bindings` table uid→authorized tenant set): wire `tenant_id` must be in caller's authorized set (non-admin cross-tenant → -32001), `audit.list`/`audit.verify`/`evaluate`/`redact`/`reveal`/`confirm` all enforce tenant gate, verify adds `tenant_id` scoping (cuts cross-tenant row-count leak); non-ping requests verify shared secret (`FUSION_GUARD_SHARED_SECRET`, constant-time compare); macOS uses `getpeereid` because Darwin 25 `LOCAL_PEERCRED` measured returning len=4 cr_uid=0 (kernel no longer fills xucred).
- **Fail-closed (D/C16/C23/L1/M10)**: rule load failure/empty return → refuse startup not degrade; `save_rule`/`save_epoch` failure rolls back memory + returns error; high-risk audit write failure returns error and rejects evaluate (not continue); seed persistence failure refuses startup.
- **Audit chain HMAC (C6/C7/C8)**: HMAC-SHA256(key, payload) replaces bare SHA-256, key same origin as token-key; empty event_hash column treated as tampered not compat; payload uses length-prefixed encoding eliminating `\x1f` collision; single serialized write path prevents chain fork.
- **Audit governance P0-4 (audit §1.3/§6)**: rotation (DB>100MB or aged rows>30d → archive NDJSON + delete rows + VACUUM) + retention (archive filename timestamp>180d delete) + incremental verify (`chain_checkpoint` caches audit_id+hash anchor, O(new delta) not full table; VACUUM-stable audit_id anchor; archive-boundary checkpoint anchors remaining first row avoiding dangling false-report; empty-DB archived state empty-sentinel+last_archived_hash continues chain not genesis).
- **Audit coverage P0-5 (audit §1.4)**: dead-letter file gains per-row HMAC chain (prev_hmac‖hmac, same token-key) + reimport path (full pre-verify → if pass, re-import to audit_events continuing main chain + clear dead-letter file; any row tampered/broken → abort, no partial import); `tcc_events` gains independent chain (prev_hash+event_hash direct columns, already append-only); `rule_mutations` append-only mutation table records each add/update/remove/epoch mutation (rules/rule_meta use INSERT OR REPLACE/DELETE which break chains, hence independent mutation chain); `verify_all_chains` aggregates audit+tcc+rules+dead_letter four chains, `guard.audit.verify` returns `{audit, tcc, rules, dead_letter, tampered}` (tampered=any sub-chain tampered). Rule tampering (controls highest-impact Block) now detectable.
- **Concurrency model P0-6 (audit §2.1)**: `handle_method` wrapped in `tokio::task::spawn_blocking` moving blocking SQLite/chain-hash computation to an independent blocking thread pool (default 512 threads); tokio workers only await `JoinHandle` (cancellable, 2s timeout can actually interrupt); old code `async fn handle_method` with zero `.await` ran on tokio worker, confirm burst load live-locked the 8-worker pool → accept/emergency intercept unschedulable → security bypass. `confirm_atomic` double-lock elimination: `pending_actions`+`audit_events` both in guard.db file, `audit_writer` Connection sees both tables, changed to single `audit_writer` lock for full SELECT+INSERT+UPDATE (no nested `action_db` lock); `action_db` Mutex retained only for `put`/`evict_expired` (no audit write path, no contention with `audit_writer`). 4 write connections add `PRAGMA busy_timeout=5000` preventing WAL multi-writer `SQLITE_BUSY`.
- **Key management (E/C13/C14/C15/A4)**: `zeroize` dependency, key stored as `Zeroizing<[u8;32]>`; removed `key_bytes()` leak; env key gated; Keychain failure refuses startup not ad-hoc generation; `Drop` zeroizes.
- **Interpreter RCE (C3) + tokenizer gap (L3/L4)**: whitelist binary `-c`/`-e`/`--command`/`--eval`/`-x` flag detection → L4 absolute Block; `rm -fr`/`--recursive --force` variants classified L4; `dd of=/dev/*` L4; `diskutil eraseDisk` L4; multi-segment commands scan all segments taking max.
- **H8 bypass (C9/L2/A8)**: confirm rebuilds verdict from `verdict_json`, risk_level read from verdict_json not action column; L4 second-check reject; consume+audit single transaction.
- **E5 case drift (C11)**: server serialize and client parse end-to-end lowercase alignment + e2e round-trip tests.
- **OOM/slowloris (C17/A6)**: `read_until` chunked read + cumulative > 1MiB disconnect; per-connection total deadline; rate limiting.
- **File permissions (C21/A5)**: after `AuditStore::open`, guard.db `0o600` + dir `0o700`; socket path TOCTOU protection.

### P1 — First sprint

- **Semantic stage robustness (C4/C5)**: `semantic_check` on syntax error does not short-circuit to zero (fail-closed L3 hit); Python-specific traversal builds import/alias map, alias-resolves dangerous calls; dynamic dispatch `getattr`/`__import__`/`globals` → L3.
- **TTL reveal (C12/P4)**: `reveal` entry `evict_expired`; expired token → H6 `[REDACTED:unrecoverable#...]` not restored; `evict_expired` background interval.
- **Redact regex expansion (C19)**: `password` covers JSON `"password":`/`"secret":`/`"token":`; API key adds non-sk- variants; private key adds single-line `ssh-ed25519`/`ssh-rsa`.
- **DLP masking blind-spot expansion P1-1 (audit §1.10)**: original 4 narrow patterns (api_key/password/id_number/private_key) blind to mainstream cloud credentials. Expanded to 13 patterns: JWT three-segment (`eyJ…\.eyJ…\.…`), OAuth bearer (`Bearer <token>` preserves prefix masks value), AWS Secret Access Key (40-char base64, no AKIA prefix, validator char diversity ≥6 + base64 boundary prevents false positive), GCP `ya29.`/Azure `AIza`/Stripe `sk_live`/`sk_test` (folded into api_key), credit card (`\d{13,19}` + Luhn validator + digit boundary prevents swallowing id_number subfield), connection-string embedded creds (`postgres://user:pass@host` preserves protocol+host masks pass), phone number (`1[3-9]\d{9}` + digit boundary), secret/token generic key-value, .env `KEY=value` generalization, .netrc `password XXX`. **Pattern order critical**: credential key-value (explicit tag, value may contain digits) + long tokens (PEM/JWT/bearer/api_key) precede bare-digit patterns (credit_card/phone/id_number), first-accept wins on overlap — otherwise 17-digit `id_number` swallows 40-digit AWS Secret or digits inside a password value. **Rule 5**: regex crate lacks lookaround; boundaries (non-same-class chars before/after) + Luhn + char diversity use code validators (`fn(content, span start, span end) -> bool`) not regex not model; Luhn rejects non-payment 16-digit numbers, char diversity rejects all-same 40-char, boundaries reject subfield swallowing. `has_sensitive` and `collect_spans` semantically aligned (validator-rejected candidates not counted sensitive).
- **Key separation + rotation P1-2 (audit §1.6)**: original master key (Keychain/env 32B) served double duty as HMAC audit-chain key and AES-GCM token encryption key — single-point leak = audit forgery + token decryption both compromised. Changed to HKDF (RFC5869) domain separation: master as PRK (high entropy skips Extract), derives via different `info` labels `chain_key = HKDF(master, "fusion-guard/audit-chain-hmac/v<ver>")` and `token_key = HKDF(master, "fusion-guard/token-aes-gcm/v<ver>")` — chain key leak cannot decrypt tokens, token key leak cannot forge audit chain. **Versioned rotation**: version embedded in `info` label, rotation = bump version + persist to `key_versions` table; derivation deterministic (master unchanged → same version always same key), so DB stores only `key_version INT` (audit_events/tcc_events/rule_mutations/tokens four tables) not key material; old rows verify/decrypt with old-version derived key, new rows use new version. `AuditStore::rotate_key()` bumps shared `Arc<AtomicI64>` (drain thread + confirm sync write see live, not stale closure capture); `current_key_version()` live version; `verify_chain`/`verify_tcc_chain`/`verify_rules_chain`/`verify_dead_letter` derive key per row's `key_version` (cross-rotation mixed chain verifiable); token `get_tenant` decrypts per row version (old tokens don't invalidate on rotation). Verification: 4 tests (`p12_key_separation_test`) — domain separation (chain≠token), version-derived independence (v1≠v2), post-rotation old audit rows verify, post-rotation old tokens decrypt.
- **Pending action put fail-closed P1-3 (audit §2.5)**: `evaluate` calling `actions().put()` (persist pending_actions for confirm) failure originally only `warn` and continued returning a verdict with action_id — caller holds id, calls `guard.confirm`, finds no such row → L3 confirm flow permanent dead-end (occasional under disk pressure, no alert). Changed to fail-closed: put failure → `evaluate` returns `Engine` error, no action_id issued (L3 confirm flow cannot be built → reject evaluation). Aligns with H7 audit-write fail-closed durability semantics (two writes in one evaluate, durability consistent). L4 Block likewise fail-closed (H8 no confirm path, but durability consistent). Verification: 2 tests (`p13_put_failclosed_test`) — L3/L4 fault injection (DROP pending_actions) then evaluate returns Engine err.
- **req_sem permit timeout separation P1-4 (audit §2.3)**: old code `req_sem.acquire_owned().await` nested inside the 2s handler timeout future → permit queue wait stole from business budget, high concurrency left handler with < 2s actual, intercept decision window compressed. Split into two stages: (1) permit has its own short timeout `PERMIT_TIMEOUT_MS=500ms`, can't acquire → `-32002` rate limit immediate reject (fail-fast, doesn't consume handler window); (2) once acquired, the 2s `REQ_TIMEOUT_SECS` only wraps `spawn_blocking(handle_method)` giving business the full window. `fg-ipc` adds `test-helpers` feature: `new_with_req_permits(engine, audit, permits)` custom slot count + `req_sem_handle()` exposes `Arc<Semaphore>` — tests pre-acquire and hold all permits forcing the permit-wait path (deterministic, no real slow handler, no timing race). Verification: 2 tests (`p14_req_sem_timeout_test`) — permit full returns -32002 and rejects faster than 2s (separation effective); permit idle ping returns pong normally (not false reject).
- **IpcServer auth layer trait extraction P1-5 (audit §3.1)**: old code had peercred→identity resolution (`handle_conn`) and shared-secret verification (`dispatch_arc`) scattered across the socket I/O path, no independent unit tests, only real-socket integration tests covered them. Extracted `Authorizer` trait (`authorizer.rs` module) + `PeerAuthorizer` default impl — identity resolution (`resolve_identity`: peercred uid → `CallerIdentity` incl authorized tenant set) + method-level auth (`authorize_method`: ping open to any peer, non-ping requires same uid + shared secret) pure logic separated. `AuthDecision` enum (Allow/DenyPeercred/DenySecret) three Denys all map to `-32001` but distinguish reason for audit assertion; `deny_resp` produces wire error bytes. `TenantLookup` minimal trait (`tenants_for_uid`) decouples AuditStore dependency — unit tests inject `FakeLookup` no real DB/Keychain/env needed. Secret env read + warn moved down to `PeerAuthorizer::new`, server no longer redundantly holds `shared_secret` field. **Scope trimming (Rule 2/7)**: audit listed 4 traits (Transport/Authorizer/Dispatcher/Policy), only Authorizer landed as trait — it's the only layer with "untested pure logic + no need to mirror engine interface"; Transport is I/O wrapper (trait adds abstraction no test gain), Dispatcher is thin engine dispatch (trait must cover all method facades = mirror interface), Policy (tenant/limit) already `CallerIdentity::tenant_allowed` pure method + `cap_limit` free function (already testable). One trait + doc note on trim rationale, avoids dual mode (Rule 7). Verification: 10 tests (`p15_authorizer_test`, needs `test-helpers`) — resolve_identity (admin empty tenant/non-admin table lookup/peercred reject), authorize_method (ping open to rejected peer/non-ping peercred reject/dev no secret allow/secret wrong DenySecret/secret correct Allow/secret set but not carried DenySecret), deny_resp wire error code.
- **audit.list filters + cursor pagination P1-6 (audit §3.2)**: old `guard.audit.list` only had tenant_id + limit — monitoring pulled full volume and filtered client-side, high volume and no incremental capability. Added 4 filter dimensions + cursor pagination: `since`/`until` (RFC3339 ts lexicographic compare, time window), `event_type` (exact match, distinguishes evaluate/confirm), `level_min` (`l1`..`l4` via `json_extract(verdict_json,'$.risk_level') >= ?` takes risk-level floor, NULL rows naturally excluded; store layer `.to_lowercase()` defensive — json_extract returns lowercase, uppercase `L3` due to ASCII < `l3` would make all rows miss the filter, wrongly returning full volume), cursor `"ts\x1faudit_id"` continuation (0x1f separator, `LIMIT limit+1` judges `has_more`, ORDER BY ts DESC+audit_id DESC, cursor condition `(ts < ? OR (ts = ? AND audit_id < ?))`). Store layer `AuditListFilter<'a>` + `AuditListPage` + `list_events_filtered` (dynamic WHERE, bound params `?N` continuously incrementing not fmt concatenation prevents injection, bind order = clause push order) + `list_filtered_page`; handler decodes cursor and passes through to store. Monitoring incremental pull: `since=<last row ts>` pulls only new rows. **Scope trimming (Rule 2)**: audit also proposed "notification channel (webhook/SSE/UDS event stream)" but self-noted "PRD does not define notification channels" — an un-PRD-backed new external interface, not introduced (product contract lives in PRD); filters+pagination already solve the brute-polling root cause (incremental fetch). Added `insert_test_event` test-helper (test-helpers gated, serializes real GuardVerdict with risk_level for level_min verification; old `insert_event_at_ts` verdict_json always "{}" has no risk_level, unusable). Verification: 6 tests (`p16_audit_filter_test`, needs `test-helpers`) — time window (since+until cuts 2 rows), event_type (excludes confirm), level_min (L3 keeps 4 rows / L4 keeps 1 row / uppercase same effect), cursor pagination (limit=2 pages through 3 pages has_more→last page false), combined filter (since+event_type+level_min simultaneously keeps 2 rows), no filter all 6 rows DESC.
- **Write-path physical DB split P1-7 (audit §3.5)**: old code had 5+ SQLite connections (audit_writer FULL + low_writer NORMAL + read_conn + token_store + action_store) all opening guard.db — sharing one WAL write lock, all writes serialized at SQLite layer; app-layer Mutex is false isolation. H7 audit_writer (synchronous=FULL, per-row fsync) hot path blocked by token_store put / action_store put contending for the lock, evaluation latency dragged down by side writes. **Physical file split**: `AuditStore::open(db_path)` splits into audit.db (db_path, audit_events+chain+rules+tcc+tenant_bindings+checkpoint) / token.db sibling (tokens+key_versions) / action.db sibling (pending_actions), each with independent WAL — evaluate path's action put / token put / audit write no longer contend on one WAL. `open(db_path)` signature unchanged (tests pass single path), token/action.db derived via `db_path.with_file_name("token.db")`/`"action.db"`. All three files `harden_db_perms` 0o600 (C21 three-DB hardening, perm_test adds assertion). **H4 confirm atomicity preserved**: `confirm_atomic` does SELECT pending_actions + INSERT audit_events + UPDATE consumed in one transaction; after split, audit_writer connection opens with `ATTACH DATABASE 'action.db' AS action`, references changed to `action.pending_actions`, cross-DB transaction coordinated commit (each ATTACHed db independent WAL, atomicity preserved) — H4 one-time consume + L2+A8 audit same-success-same-failure intact. ActionStore's own connection (put/evict_expired) not ATTACHed, still uses main.pending_actions. **Legacy DB migration**: `drop_legacy_split_tables` after open DROPs legacy single-file guard.db main residual pending_actions/tokens/key_versions (sqlite_master existence check idempotent, failure warn-not-fatal); three tables are transient (pending TTL 30s / token TTL 300s) no row copy (old values likely expired), only clears residual. `tamper_verdict_json` test-helper changed to open action.db sibling (old opened audit.db querying pending_actions which migrated → no such table). Verification: 4 tests (`p17_write_split_test`, needs `test-helpers`) — three files exist+0o600, pending_actions in action.db not audit.db + put row lands in action.db, confirm cross-DB transaction atomic (audit.db has confirm row + action.db consumed=1 + re-confirm Consumed), legacy residual tables DROPped after open.
- **Cross-tenant confirm (C20)**: `pending_actions` adds `tenant_id` column; confirm verifies `action.tenant_id == caller.tenant_id`.
- **Rule mutation stale-epoch (L7)**: `rule.add/update/remove` verifies `caller_epoch` (non-0 and == current), else -32003; seed fail-open fixed.
- **Positional params (L8/M2/M1)**: `RpcRequest` params must be object, reject array; unknown method -32601 without method name; wire error code + generic message only, details in server log.
- **tcc.report validation (M8)**: handler calls `TccService::parse(permission)?`; `requester`/`reason`/`result` length-limited 1024.
- **Read connection + limit cap (A3/P3)**: `audit.verify`/`list_events` open dedicated read connection (no mutex); limit hard cap 10000 + truncation log.

### P2 — Tech debt

- **env key gating + alert P2-1 (audit §2.6)**: old `load_or_create_key` checked `FUSION_GUARD_TOKEN_KEY` env first, used it if hit, skipping Keychain with no dev/prod gating — misconfig puts master key into process environment (`/proc`-equivalent `ps eww`/lsof/launchctl), readable by same-UID processes (one-core-nine-ends 9 fusion-* all same UID) → AES-GCM token key + HMAC chain key dual leak (§1.6 key reuse, mitigated by P1-2 HKDF domain separation but still same master). Test global `ensure_env()` reused the env posture, operators easily copy it into launchd plists. **Gating**: extracted pure decision function `resolve_key_source(is_debug, allow_env_flag, env_present) -> KeySource` (Rule 5: decisions in code not tokens) — `cfg(debug_assertions)` (dev) → `EnvDebug` (info posture); release only `FUSION_GUARD_ALLOW_ENV_KEY=1` or `--insecure-env-key` CLI flag (fg-bin `start` subcommand sets `FUSION_GUARD_ALLOW_ENV_KEY=1`) allows → `EnvInsecure`; env not allowed or absent → `KeychainRequired` (macOS uses Keychain, non-macOS fail-closed refuses startup, no weak-key fallback). **Alert**: `EnvInsecure` path `tracing::warn!`-level banner ("INSECURE (P2-1): master key loaded from env in release — visible to any same-UID process; prod MUST use Keychain"), visible in ops audit; `EnvDebug` still `info!` (dev posture). fg-bin flag-set additionally warns. `decode_env_key`/`load_keychain_or_err` split (old `load_or_create_key` inlined three paths → independent fn, readable testable). **Scope**: §1.6 key reuse itself fixed by P1-2 HKDF (master derives independent chain/token keys via HKDF), this P2-1 only adds env gating + alert (prevents misconfig leak channel), does not change key derivation. Verification: 3 tests (`p21_env_key_gating_test`, needs `test-helpers`) — decision matrix all 7 branches (debug/release × flag × env_present → EnvDebug/EnvInsecure/KeychainRequired), debug env loads without touching Keychain (token put+reveal roundtrip works), release env no flag → KeychainRequired gate regression (calls real `resolve_key_source` not oracle, Rule 7 no dual logic).
- **A1 shell_words fail-closed**: tokenizer adds `check_unmodeled_shell_features` — bare tilde/brace expansion `{a,b}`/`{n..m}`/glob `*`/`?`/`[abc]`/heredoc `<<`/`|&`/fd redirect `>&N`/`<&N`/`<>`/backslash line-continuation → Block L4 (shell_words does not model these features, each is a bypass channel, fail-closed reject not per-file arm).
- **peercred transient failure to warn + distinguish reject type P2-3 (audit §3.4)**: old `peer_uid(fd) -> Option<u32>` logged `getpeereid`/`SO_PEERCRED` transient syscall failures (fd stale/EBADF/ECONNRESET) at `tracing::debug!` only, invisible at prod info level, and mixed with "cross-UID reject" into the same `None` path → ghost unauthorized undiagnosable (ops cannot distinguish "syscall failure needs diagnosis" from "cross-UID attack/misconnect"). **Three-state separation**: extracted `PeerUid` enum (`Resolved(u32)`/`SyscallFail`/`Unsupported`) replacing `Option<u32>` — `peer_uid` syscall failure returns `SyscallFail` and escalates to `tracing::warn!` (with OS errno); platform-unsupported returns `Unsupported` (warn); success returns `Resolved(uid)` (still debug). `peer_allowed` three-state input: `Resolved` does same-uid/root check, `SyscallFail`/`Unsupported` always reject (no credential = untrusted, fail-closed). **Distinguished logging**: `PeerAuthorizer::resolve_identity` reject branch splits into two warn paths by `is_syscall_fail()` — `SyscallFail` logs "peer credential syscall failed (P2-3 §3.4); fail-closed", `Resolved(other)` logs "non-peer connection (E6 cross-UID)", both fail-closed reject but logs distinct. `PeerUid` re-exported via `fg-ipc` (pub use fg_peercred::PeerUid), `resolve_identity` trait signature `Option<u32>` → `PeerUid`. `resolved()`/`is_syscall_fail()` helper methods for callers to get uid + classify. Verification: +2 tests — `peercred_test` adds `syscall_fail_peer_denied` (SyscallFail/Unsupported always reject, allow_root doesn't pass) + `peer_uid_resolved_and_is_syscall_fail` (three-state helper methods); `p15_authorizer_test` adds `p23_resolve_identity_syscall_fail_distinct_from_cross_uid` (SyscallFail uid falls back to u32::MAX vs cross-UID keeps real uid 999, two types distinguishable by uid field). Also fixed existing unused warning for `fg-store/src/lib.rs` `CheckStage` import (test-helpers off by default, lib doesn't use it, split `#[cfg(feature="test-helpers")] use`). Full 178 pass (176→178, +2), clippy clean (0 warning), release green.
- **UDS connection pool + persistent reuse P2-4 (audit §3.6)**: old `UdsClient::call` did connect+write+read+drop each call — each call paying UDS connect handshake overhead (socket create+bind+connect+accept kernel round-trip), high-frequency L1 evaluate P99 dominated by handshake, 9-end concurrency P99<1ms unreachable. **Server already supports single-connection multi-request** (`conn_loop` read→dispatch→write loop, disconnect only on EOF, `CONN_DEADLINE_SECS=30s` backstop prevents slowloris), audit's claim "disconnect after handling" was inaccurate → **client-side change only, server untouched** (Rule 2 minimize). `UdsClient` holds `Mutex<Option<UnixStream>>` persistent connection: `call` delegates to `call_once`, the latter lazy-connect (first call builds stream) + borrows stream for read/write (`BufReader<&UnixStream>` not consuming/clone, same fd reused across calls) + on success retains stream for reuse + IO error (server 30s deadline disconnect/restart/peer EOF/EPIPE/timeout) clears stream prompting next reconnect. `call` retries reconnect-once on `call_once` failure (transparent self-heal, only once prevents fault amplification), caller unaware of server restart. **No multiplexing** — Python single-threaded blocking model has one request in flight at a time, connection reuse already eliminates handshake overhead (Rule 2). `PyGuardClient` holds `UdsClient` directly (not `sock: PathBuf` building new `UdsClient::new` each time, which would bypass the pool), `client()` returns `&UdsClient`. Verification: +1 test `p24_persistent_conn_reuse_and_reconnect` — (1) same client 5 pings reuse connection all succeed (reuse doesn't corrupt wire); (2) after server abort+restart, dead stream detected+cleared+reconnect, ping still ok (transparent self-heal). Full 179 pass (178→179, +1), clippy clean (0 warning, also cleared `map_err(|x| x)` identity lint), release green.
- **category_hint caller risk floor P2-6 (audit §3.2/F6, PRD §6.3 H9)**: old `guard.evaluate` had no `category_hint` param, caller-asserted category had no audit visibility, and v0.1 "caller self-certifies category" could be downgraded-bypassed (caller lies `read` to lower level and bypass Block). **H9 contract**: guard infers category authoritatively from content (`inferred_category`), caller `category_hint` acts only as risk floor — `final level = max(inferred, rule hit, hint)`, hint raises level never lowers (two-way anti-bypass). Wire: `guard.evaluate {action, content, context, caller_epoch, category_hint?}` (default None backward-compat). IPC receives `category_hint` (s_param idx 6) → passes through to `AuditEngine::evaluate(content, caller_epoch, tenant_id, content_type, category_hint: Option<&str>)`. engine sets `verdict.category_hint` (caller assertion visible in audit) + pure fn `hint_risk_floor(hint)` computes floor: `shell_exec`/`network`/`file_write` → L2 floor, read/clean/unknown → None (no floor). Floor capped at L2 (L3/L4 always driven by real rule hits, not caller assertion), `Allow`→`Redact` when floor raises level past L1. `GuardVerdict` adds `category_hint: Option<String>` field (`#[serde(default, skip_serializing_if)]` lets old verdict JSON missing this field still deserialize, pending_actions/audit cross-version compat), `PyGuardVerdict` mirrors + `to_dict` exposes; `fg-pyo3` evaluate pymethod adds `category_hint: Option<String>` signature (default None). Verification: +5 tests `p26_category_hint_test` — `hint_risk_floor_known_categories` (shell_exec/network/file_write→Some(L2)) + `hint_risk_floor_low_or_unknown_is_none` (read/clean/bogus/""→None) + `hint_raises_floor_from_l1_to_l2` (`ls /tmp` no hit L1 Allow + hint "network" → L2 Redact, inferred_category still "read" hint doesn't override inference) + `hint_never_lowers_l4_block` (`rm -rf /tmp/x` L4 Block + hint "read" → no lower, still L4 Block) + `hint_floor_below_current_no_change` (L4 Block + hint "shell_exec" L2 floor < L4 → no change). Pure decision fn unit-testable (Rule 5). Full 184 pass (179→184, +5), clippy clean (0 warning), release green.
- **A2 bounded queue + dead-letter**: low-risk audit changed to `sync_channel(8192)` + `try_send` backpressure; drain runs batch inline (not spawn-per-batch); queue full/disconnect → persistent dead-letter file (guard.db.deadletter, 0o600), no silent event loss.
- **A9 semantic SSOT**: removed dead code `semantic_default_rules()` (produced 6 stage=Semantic GuardRules injected into ruleset, but evaluate skips non-Regex stage, never matched); hardcoded danger tables (PY_DANGER_L4 etc.) are the semantic execution single source of truth, non-admin mutable (documented), restored SSOT honesty.
- **L5 mv/cp destination (M)**: `check_argv` models `-t DIR`/`--target-directory=DIR`/`--target-directory DIR`/`--` terminator, correctly parses GNU mv/cp destination.
- **L6 span tracking**: redact changed to single-pass span collection on original content (rejects overlap, first-pattern priority), placeholder never written back to original content → `id_number` doesn't corrode prior `tok_<uuid>` placeholder (old sequential replace_all ran on already-redacted text, id_number matched 17-digit subfield inside placeholder → broke placeholder → reveal hit H6 → reversible silent-degrade to irreversible). `id_number` tightened to `\d{17}[\dXx]`.
- **L9 PyO3 errors explicit**: fg-pyo3 client removes all `unwrap_or` silent fallbacks — reveal/redact/confirm/audit_verify/list_rules missing key field → `PyValueError` (prevents empty-string masquerading as successful reveal, false forging no-tamper, epoch 0 permanently stale).
- **L10 category derived from hit**: `infer_category` derives from actual hit scope (Network→network/Filesystem→file_write/non-whitelist→shell_exec/no hit→clean), not fixed-name table fallback.
- **L11 verdict explicit rank**: `verdict_from_hits` deterministic sort by `(action_severity, risk_level, stage_rank)` taking head, not `max_by_key` tie-ambiguous last hit wins.
- **L12 confirm audit schema**: confirm audit event adds dedicated field storing outcome/approve-reject, `action` column no longer one-column-two-meanings.
- **L13 migrate uses PRAGMA**: `migrate_audit_chain` changed to `PRAGMA table_info` to check column existence (not `prepare(SELECT col)` — latter returns Err on legacy DB without column causing open failure, migration path unreachable).
- **M3 poison explicit handling**: `PoisonError` explicit recover (11 `.expect` changed to lock macro).
- **M4 Redactor Result**: `Redactor::new` returns `Result` propagating compile failure (not process panic); `OnceLock` caches static regex.
- **M5/M7 build.rs**: `rerun-if-changed .git/refs` prevents stale FG_GIT_SHA; build.rs compile failure explicit `expect` checks success.
- **M6 RiskLevel explicit Ord**: explicit `Ord` impl replaces `as u8` implicit.
- **M9 json_to_py direct conversion**: fg-pyo3 `Value` → Python recursive direct conversion (not `to_string` + `json.loads` round-trip), f64 precision preserved, zero import.
- **P1/P2 regex single scan**: `Lazy`/`OnceLock` static regex; `redact_counted` single-pass returns `(redacted, hit_count)` replacing has_sensitive+redact two-scan.

### Product Commercial Audit Sweep (product-audit-0827)

Per `audit/fusion-guard-audit-result-product-0827.md` (product commercial verdict) landed. A different wave from the audit-0827 static adversarial review; this fixes hard blockers before commercial release. See CLAUDE.md for details.

- **shared secret prod config missing (H-C, audit §5)**: old shared secret was env-only (`FUSION_GUARD_SHARED_SECRET`) = readable by same-UID processes (`ps eww`/lsof/launchctl), a compromised subagent (one-core-nine-ends 9 fusion-* same UID) could steal the second factor → rule mutation/reversible redact reveal full-power calls. **prod source changed to macOS Keychain** (service `fusion-guard`, account `shared-secret`, same service as token-key different account for domain separation). New `fg-store::secret_store` module: `resolve_shared_secret(is_debug, allow_insecure_flag, env_present) -> SharedSecretSource` pure decision function (Rule 5, mirrors token-key's `resolve_key_source`) + `keychain_secret_get`/`keychain_secret_store` (macOS vs non-macOS cfg) + `generate_shared_secret` (32 bytes hex 64 chars). `load_shared_secret` resolution order Keychain → env → none: Keychain present use it (prod path, not into env var); Keychain absent + env allowed → env (escape hatch); Keychain absent + env not allowed → not silently use env (prevent missed-flag degrade) treated as no secret; both absent + macOS release first start → generate strong random secret stored to Keychain (allow_mint, operator can also pre-provision pure-Keychain no generation). **Release gate** `require_shared_secret_for_release()`: release startup checks both sources absent → refuse startup (prevents peercred-only fallback being fully callable by a same-UID compromised process); Keychain present / env allowed / `FUSION_GUARD_ALLOW_NO_SECRET=1` (emergency ops peercred-only) any one allows. `ALLOW_NO_SECRET` **judged first** (startup gate + load both places), skips Keychain read — non-interactive env `get_generic_password` may serially block (CLAUDE.md Keychain hang risk), CI/soak spawn release daemon sets this flag, client need not carry secret. dev build (debug) skips gate, tolerates secret absence (test convenience). `fg-bin` `start` subcommand adds `--insecure-secret-env` flag (sets `FUSION_GUARD_ALLOW_INSECURE_SECRET=1`, mirrors `--insecure-env-key`). `start.sh` shared-secret supply block mirrors token-key block: env set → flag; dev keyfile `${GUARD_DIR}/shared-secret` → read + flag; both absent → Keychain path. Verification: 6 tests (`secret_store_test`) — decision matrix 4 branches (Keychain/env-debug/env-insecure/release-no-flag) + generates hex 64 chars + randomness.
- **token-test hang fix (environmental)**: `ciphertext_not_plaintext` originally scanned entire `std::env::temp_dir()` (this machine polluted by other processes, FIFO/large-dir entry) → `std::fs::read` → `open()` blocked on some entry, test hung 60s+. Changed `open_conn_in_dir()` to scan only the test's self-built subdir, assertion intent unchanged (no plaintext under self-built db dir). env-key test precondition unchanged.
- **Ops docs**: new `DEPLOYMENT.md` — two-key trust model comparison table (token-key vs shared-secret, Keychain account / env var / leak impact), Keychain secure path (first auto-generation + operator pre-provision `security add-generic-password`), env insecure path table (allow flag CLI + env), release gate behavior, quick prod deployment checklist, multi-node cluster (shared secret consistent across nodes), launchd persistence (user-domain LaunchAgents), key rotation.

### Test Robustness (verify-phase reinforcement)

- **semantic_verdict_block payload fix**: original payload `os.system('rm -rf /')` hit both regex rm-rf (Block L4) + semantic os.system (Block L4); L11 stage_rank Regex>Semantic → verdict.stage=Regex not Semantic (test false-failed). Then changed to `subprocess.run(['ls', '-la'])` which also collided with A1 glob `[...]` Ast L4 tie. Finally settled on `os.system('id')`: Ast only non-whitelist L3, semantic os.system L4 — L4 risk > L3 → semantic deterministically wins. L11 sort design correct, error was payload not isolating a single stage.
- **fg-pyo3 test flake elimination**: `evaluate_block_returns_verdict` under workspace high-concurrency load occasionally `-32010` (server.serve accept loop not scheduled by worker_threads=2 → first request 2s read timeout). Added `wait_for_sock` polling 1s→5s + `call_retry`/`call_retry_err` transient -32010 retry 3 × 200ms; non-32010 business errors (e.g. -32003 stale epoch) returned as-is not retried.

## IPC Protocol

UDS socket: `/tmp/fusion-guard.sock` (env `FUSION_GUARD_SOCK`)
Frame format: JSON-RPC 2.0 + `0x0A` delimiter, 1MiB cap, 2s timeout fail-closed

Methods:
- `guard.ping` — `{pong: bool, version, rules_epoch}` (`pong` is boolean — cross-repo consumers fusion-cli #9 / fusion-studio #344 read as `Bool`; never return string)
- `guard.evaluate` — `{action, content, caller_epoch?, tenant_id?, requester?}` → GuardVerdict (caller_epoch != 0 and != guard epoch → `-32003` stale epoch)
- `guard.rule.list` — `{rules: [GuardRule], epoch}`
- `guard.rules.dump` — `{rules, epoch}` (same as rule.list)
- `guard.rule.add` — `{rule: GuardRule}` → `{new_epoch}`
- `guard.rule.update` — `{name, rule}` → `{new_epoch}`
- `guard.rule.remove` — `{name}` → `{new_epoch}`
- `guard.tcc.status` — `{statuses: [TccStatus]}` (Swift bridge, source `swift-bridge:live` or `tccutil:stub`)
- `guard.tcc.report` — `{permission, requester, result, reason}` → `{audit_id}` (audit aggregation H1, each subproject self-requests TCC, guard only aggregates)
- `guard.tcc.events` — `{limit?}` → `{events: [TccEventRecord]}`
- `guard.audit.list` — `{tenant_id?, limit?}` → `{records: [AuditRecord]}`
- `guard.audit.verify` — `{}` → `{audit:{...}, tcc:{...}, rules:{...}, dead_letter:{...}, tampered}` (all-chain aggregation verify, P0-5: audit+tcc+rules+dead_letter four sub-chains; each sub-chain `{total_rows, unhashed_rows, verified_links, broken_links, tampered, first_broken_at?}`; top-level `tampered`=any sub-chain tampered, PRD §13.3)
- `guard.redact` — `{content, reversible:bool}` → `{redacted_content, token_map_id?}` (reversible: token AES-GCM encrypted persisted, in-flight flag R3; irreversible: `[REDACTED:type#last4]`)
- `guard.redact.patterns.dump` — `{}` → `{patterns: [{name, regex, validator}]}` (issue #7: 15 redaction pattern definitions read-only dump, priority order preserved, validator tag `none|ipv4|aws_secret|luhn|phone`; consumers pull instead of vendoring, eliminates manual lockstep)
- `guard.reveal` — `{content, token_map_id}` → `{content}` (restore; token missing falls back to `[REDACTED:unrecoverable#...]` H6)
- `guard.confirm` — `{action_id, approved:bool, approved_by?, tenant_id?}` → `{verdict: GuardVerdict}` (L3 human confirmation; L4 rejected H8; action_id one-time consume H4; TTL 30s expired rejected; approve→Allow, reject→Block)

GuardRule fields: `name, pattern, stage(Regex|Ast|Semantic), action(Allow|Preview|Redact|Block), risk_level(L1-L4), reason, scope(Command|Content|Network|Filesystem)`

Rule SSOT: guard is the rule authority, epoch monotonically increments. Caller holds caller_epoch; after rule changes guard rejects stale epoch. Rules persisted to SQLite, survive restart.

Error codes: `-32700` parse / `-32600` invalid / `-32601` not found / `-32001` unauthorized / `-32002` rate limit / `-32003` stale epoch / `-32010` internal (BLOCK = `result.action="block"`, not an error code — E5)

## Usage

```bash
cargo build --release
./start.sh start    # launch daemon
./start.sh status
./start.sh stop
./start.sh log
./start.sh doctor

# ping
./target/release/fusion-guard ping
```

## Development

```bash
make build    # cargo build
make test     # cargo test
make lint     # clippy + fmt
make check    # lint + test
```

Code conventions: 4-space indentation, no docstrings, logging always included, `unsafe_code = "deny"` (workspace lint).

## Production Deployment

**Two production keys** (token-key master + shared-secret second factor) deploy differently; prod must use macOS Keychain (service `fusion-guard`, account `token-key`/`shared-secret`), env is dev/CI/emergency escape hatch only (release requires explicit flag to allow).

Full deployment doc: **`DEPLOYMENT.md`** (Keychain secure path + env insecure path + release gate H-C + quick prod checklist + multi-node cluster + launchd persistence + key rotation).

Before launching the release binary, pre-provision the Keychain secret or the release gate refuses startup (unless `FUSION_GUARD_ALLOW_NO_SECRET=1` emergency allows):

```bash
SS=$(python3 -c "import secrets;print(secrets.token_hex(32))")
security add-generic-password -s fusion-guard -a shared-secret -w "${SS}"
./start.sh start    # client non-ping requests must carry secret
```

### Headless / CI / SSH (issue #17)

macOS Keychain (`SecItemCopyMatching` / `get_generic_password`) **serially blocks** in non-interactive sessions (no WindowServer — SSH, CI, launchd-without-gui). The release daemon hangs silently on startup when neither an env var nor a keyfile escape hatch is set — `start.sh`'s `kill -0` liveness check may pass while the process is stuck inside the blocking Keychain call, so the failure mode is "daemon appears started but never binds the socket".

`start.sh` auto-detects headless and **skips Keychain**, falling back to file-backed keys (preserves DLP + audit-chain cross-restart verifiability, no `allow-no-key` weakening):

- **Headless when**: `--headless` flag (`./start.sh start --headless`), `FUSION_GUARD_HEADLESS=1` env, no tty (stdin not a tty), or under SSH (`SSH_CONNECTION`/`SSH_TTY`/`SSH_CLIENT` set). Desktop interactive sessions default to Keychain (prod).
- **Behavior**: headless + no env + no keyfile → auto-generates `~/.fusion-guard/token-key` (32-byte hex, 600 perms) and `~/.fusion-guard/shared-secret` (32-byte base64, 600 perms), exports to env + passes `--insecure-env-key`/`--insecure-secret-env`. Keyfiles persist across restarts (same master → audit chain verifies, tokens decrypt) — generated once, reused after.
- **Stronger than `FUSION_GUARD_ALLOW_NO_SECRET=1`**: keeps the §12.1 shared-secret second factor (file-backed secret, clients carry it) instead of degrading to peercred-only auth.
- **Desktop prod recovery**: delete the keyfiles (`~/.fusion-guard/token-key`, `~/.fusion-guard/shared-secret`) and restart in an interactive session → Keychain path (keys not in env, not same-UID readable). Or pre-provision Keychain + run `./start.sh start` (no `--headless`).

```bash
# CI / SSH / launchd-without-gui
./start.sh start --headless
# or auto-detected (piped stdin / SSH) — no flag needed
FUSION_GUARD_HEADLESS=1 ./start.sh start
```

### Soak / Stress Test (commercial blocker #6)

`crates/fg-ipc/tests/soak_test.rs` — long-running concurrency stress test, validates production form: under sustained high-concurrency load latency doesn't degrade, child process memory doesn't leak, fail-closed holds.

```bash
# Build release daemon first (soak spawns a child process, not in-process)
cargo build --release -p fg-bin

# Run soak (needs release binary, auto-skips if missing without failing full cargo test)
export FUSION_GUARD_TOKEN_KEY=$(python3 -c "import secrets;print(secrets.token_hex(32))")
cargo test -p fg-ipc --test soak_test -- --nocapture
```

Model: spawn `target/release/fusion-guard start` child process (isolated SOCK+DATA_DIR+TOKEN_KEY+LOG_DIR), 48 concurrent UDS connections looping `guard.evaluate` for 10s, sampling child process RSS (`ps -o rss=`) every 2s + DB disk usage. Child-process mode = RSS measures pure server, no client-thread-stack/malloc pollution, no debug bloat.

Assertions: throughput ≥5000 reqs/10s, error rate <1%, p50 ≤25ms, p99 ≤200ms, DB disk ≤200MB (rotation bounded), daemon RSS ≤1200MB (tolerates macOS libmalloc non-return + tokio pool residency). Fail-closed case (`rm -rf /`) verifies Block L4 not misjudged as allow under high concurrency.

**Test precondition**: `cargo test` must first `export FUSION_GUARD_TOKEN_KEY=<hex 32B>`, else `AuditStore::open` → macOS Keychain `SecItemCopyMatching` hangs 60s+ in non-interactive env.

## Roadmap (PRD §17)

- **Phase 0** ✅ Engineering skeleton: workspace + 8 crate + start.sh + CI + launchd
- **Phase -1** ✅ Gate: fusion-security decision A (converge overlapping capability only, SAST retained independently) — issue #23
- **Phase 1** Rule convergence: ✅ SSOT + epoch + persistence, ✅ SQLite WAL audit, ✅ encrypted token store (redact/reveal), ✅ confirm + action_id (H4/H8)
- **Phase 2** AST stage: ✅ Stage 2 tokenizer (shell-words MVP), ✅ category inference (H9), ✅ seatbelt_required (E7), ✅ SENSITIVE_PATHS/WHITELIST convergence
- **Phase 3** fail-closed local cache + seatbelt compile inline (blocked-on-upstream-PR: executor E2)
- **Phase 5** ✅ TCC audit aggregation (H1) + Swift tcc-bridge (status query, C stub fallback, independent CI lane — E1)
- **Phase 6** agent-studio/studio integration (blocked-on-upstream-PR: E2)
- **Phase 7** Audit chain hash tamper-evidence ✅ (PRD §13.3); Endpoint Security ✅ (fg-es, stub degraded → TCC, Q#3); PyO3 binding ✅ (fg-pyo3, UDS client exposed to Python, Q#4); Stage 3 tree-sitter semantic stage ✅ (feature=semantic, PRD §7.4 R5)

## Monorepo Context

27 `fusion-*` subprojects share `/Users/dahai/fusion/.venv`. fusion-guard is a Rust + Swift project, not Python. IPC aligns with the monorepo JSON-RPC 2.0 over UDS contract. See `/Users/dahai/fusion/CLAUDE.md`.
