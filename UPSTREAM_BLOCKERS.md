# Upstream Blockers — Product Audit P0-P3 Sweep

来源: `audit/fusion-guard-audit-result-product-0827.md` (2026-08-28 产品商用审计).
本文件记录 **非 fusion-guard 代码可独立修复** 的审计项 —— 属上游/生态依赖, 按项目规则
(上游问题先提 issue 再提 PR, 跟着提交落地 code) 记录追踪, 不在本仓本地修复.

所有 fusion-guard code-fixable 项 (H-A~H-G 中的代码项 + P1-1~P1-7 + P2-1~P2-4 + P2-6)
已落地, 242 tests green. 下列项 BLOCKED-ON-UPSTREAM:

---

## H-F — 零真实消费者 (executor#23 仍 OPEN, PR#25 已 MERGED)

**审计定位:** §1 商用阻断 1, §H-F (line 236/256).
**状态 (2026-08-28 复核):** `executor#23` 仍 OPEN, 但 `fusion-executor` PR#22/#24/#25 已 MERGED
(2026-08-27~28), 含 seatbelt 4-layer fix (ARCH-1) + fusion-code integration skeleton + circuit
breaker (ARCH-3) + guard IPCClient 接入骨架。executor 正在接入 guard, 非零消费者状态收尾中。
**属上游 repo:** `fusion-executor` (issue #23 OPEN; PR#25 merged 9b96aeb4).
**guard 侧已就绪:** `guard.evaluate` IPC + action_id + confirm + seatbelt flag 全落地。
**解除条件:** executor#23 close (executor 执行前 evaluate 调用全链路 land)。
**本项目动作:** 不本地修; 推进上游 executor#23 close。

---

## P2-5 — CI 计费解除 + release 产物

**审计定位:** §P2-5 (line 279).
**状态 (2026-08-28 复核):** GitHub 账户计费已解除 — runner 现可执行 (runs queued/completed, 非
billing-blocked)。但 CI 仍 conclusion=failure: jobs `rust-check`/`swift-bridge` steps 数组空 +
job logs run 结束即 404 (retention/infra 层, 非代码错)。本地复现 CI 完整序列全绿:
`cargo check --all-targets` ok, `cargo test` 196 pass 0 fail (3× 稳定), `cargo fmt --check` ok,
`cargo clippy --all-targets -- -D warnings` 0 error, `cargo build --release` ok。CI failure 推断
为 runner/checkout/rust-cache infra 层 (非 guard 代码), 需 GitHub Actions 侧重查。
**仍缺:** release tag + 产物 (binary/wheel/plist) + 校验和 + 签名 (release workflow 未建)。
**属:** GitHub Actions infra + release pipeline, 非 guard 代码逻辑。
**解除条件:** CI infra 排障 (runner/checkout/cache) → 实跑绿 → 建 release workflow + tag + 产物 + checksum + 签名。
**本项目动作:** 不本地修代码; CI infra 排障 + 建 release workflow。

---

## P2-7 — studio#344 + gateway#128 上游落地 ✅ RESOLVED 2026-08-28

**审计定位:** §P2-7 (line 281), §1 商用阻断 2/3 (line 59/60).
**状态:** 两上游 issue 已 CLOSED COMPLETED 2026-08-28, 非再阻断。
- `studio#344` CLOSED COMPLETED (2026-08-28T06:59Z): guard integration — TCC audit reporting
  (Phase 5) + IPCClient guard.* UDS + human-challenge modal↔guard.confirm (Phase 6)。
  guard L3 requires_approval 现有桌面端确认 UI。
- `gateway#128` CLOSED COMPLETED (2026-08-28T06:39Z): PIIChecker regex subscribe to guard
  authoritative DLP pattern set (SSOT, no drift) + keep RBAC/prompt_injection local。
  PII SSOT 已对接 guard.redact.patterns.dump。
**guard 侧已就绪:** guard.tcc.* + guard.confirm + guard.redact.patterns.dump 全落地
(issue #7 已 closed)。上游已消费, 闭环成立。
**本项目动作:** 无, 监控上游消费方回归即可。

---

## 已落地 code-fixable 项 (对照)

H-A (审计链双写者→单 writer), H-B (规则越权→authorizer), H-C (VACUUM 持锁→split DB),
H-D (confirm 非事务→跨库 ATTACH 原子), H-E (密钥丢失→检测拒启动+HKDF 版本轮换),
H-F-launchd (plist 占位符→install-launchd.sh, 归 H-G 落地), H-G (launchd 安装脚本),
P1-1 (DLP 模式扩展), P1-2 (HKDF 域分离), P1-3 (put fail-closed), P1-4 (req_sem timeout),
P1-5 (epoch 编排互斥锁), P1-6 (AppleEvents honest tag), P1-7 (slow_sem 限流),
P2-1 (semantic SLA guard), P2-2 (stale socket + Keychain), P2-3 (peercred warn),
P2-4 (UDS 连接池), P2-6 (category_hint)。详见 CLAUDE.md + memory/*.md。
