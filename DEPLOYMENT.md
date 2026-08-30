# Deployment Guide — fusion-guard 生产部署

fusion-guard 守护进程依赖**两个生产密钥**, 二者信任模型不同, 部署方式不同。本文档覆盖安全 (Keychain) 与不安全 (env) 路径、release gate 行为、launchd 常驻配置。

## 两个密钥

| 密钥 | 用途 | Keychain account | env 变量 | 泄露影响 |
|------|------|------------------|----------|----------|
| **token key** (主密钥) | 可逆脱敏 token 的 AES-256-GCM 加密 + 审计链 HMAC 派生 (HKDF 域分离) | `token-key` | `FUSION_GUARD_TOKEN_KEY` (hex, 32 字节) | 跨租户可逆脱敏 token 全可解 + 审计链可伪造 |
| **shared secret** (第二因子) | §12.1 非 ping 请求的第二鉴权因子 (常量时间比对, 超越 peercred) | `shared-secret` | `FUSION_GUARD_SHARED_SECRET` | 同 UID 任意进程可全权调规则突变 / 可逆脱敏 reveal |

两者 Keychain service 同为 `fusion-guard`, account 域分离。

## 安全路径: macOS Keychain (生产推荐)

Keychain 密钥不入进程环境变量, 同 UID 进程不可经 `ps eww` / `lsof` / `launchctl` 读取。被攻陷的 subagent (同 UID 运行) 无法窃取。

### 首次启动自动生成

守护进程**首次启动**时, 若 Keychain 无对应密钥且 env 也未设, macOS 上自动生成强随机密钥并存入 Keychain:
- token key: `rand::thread_rng` 32 字节, 存 `fusion-guard` / `token-key`。
- shared secret: 32 字节 hex (64 字符), 存 `fusion-guard` / `shared-secret`。

之后启动直接从 Keychain 加载, 不再生成。**H-E**: token key 一旦 Keychain 丢失而 DB 已有历史数据, 拒绝静默重生成 (否则历史 token 不可解 + 审计链验证全报篡改), 启动报错。

### 主密钥托管 (escrow, H-E item b)

token key 丢失 = 单点致命: 历史可逆 token 不可解 + 全审计链验证失败。**首次自动生成或预置后, 立即把密钥导出到离线备份**, 不要只存 Keychain (Keychain 可能因用户账户重置 / keychain 重建而丢)。

```bash
# 导出 (首次启动后, 或预置后):
security find-generic-password -s fusion-guard -a token-key -w > /secure/offline/fusion-guard-token-key.txt
chmod 600 /secure/offline/fusion-guard-token-key.txt
# 立即清屏历史: history -d ... (勿留 shell 历史)
```

**恢复路径 (密钥丢失)**: 从 escrow 取回**同一**密钥 → 重写 Keychain → 重启守护。同 master → 锚点匹配 → 无假篡改, 无需 remint:

```bash
KEY=$(cat /secure/offline/fusion-guard-token-key.txt)
security delete-generic-password -s fusion-guard -a token-key   # 若残留错误项先删
security add-generic-password -s fusion-guard -a token-key -w "${KEY}"
./start.sh start
```

无 escrow 备份 → 密钥不可恢复。此时历史审计链无法复验, 只能作为"密钥丢失 (key_loss=true, 非真篡改)"处理 (见下 §密钥丢失区分); 可逆 token 历史数据彻底不可解。**这是为何 escrow 是部署必需步骤**。

### operator 预置 (推荐: 不依赖自动生成)

operator 可预先写入固定密钥 (多节点部署需各节点同密钥以互操作):

```bash
# token key (32 字节 hex; 多节点须一致以解密彼此同步的可逆 token)
TOKEN_KEY=$(python3 -c "import secrets;print(secrets.token_hex(32))")
security add-generic-password -s fusion-guard -a token-key -w "${TOKEN_KEY}"

# shared secret (32 字节 hex; 多节点须一致以验签彼此 confirm relay)
SHARED_SECRET=$(python3 -c "import secrets;print(secrets.token_hex(32))")
security add-generic-password -s fusion-guard -a shared-secret -w "${SHARED_SECRET}"
```

查询 / 删除:
```bash
security find-generic-password -s fusion-guard -a token-key -w     # 读
security delete-generic-password -s fusion-guard -a token-key      # 删 (谨慎: 历史数据不可解)
security delete-generic-password -s fusion-guard -a shared-secret
```

⚠️ guard 以**用户身份**运行 (读用户 Keychain), launchd 须部署到 `~/Library/LaunchAgents` (用户域), 非 `/Library/LaunchDaemons` (系统域, 无用户 Keychain 访问)。见 `install-launchd.sh`。

## 不安全路径: env (escape hatch, 非 prod 推荐)

env 密钥进进程环境, **同 UID 进程可读**。仅 dev / CI / 应急使用。release 构建须显式 flag 放行, 否则拒绝加载 (不静默降级):

| 密钥 | env 变量 | 放行 flag (CLI) | 放行 env |
|------|----------|-----------------|----------|
| token key | `FUSION_GUARD_TOKEN_KEY` | `--insecure-env-key` | `FUSION_GUARD_ALLOW_ENV_KEY=1` |
| shared secret | `FUSION_GUARD_SHARED_SECRET` | `--insecure-secret-env` | `FUSION_GUARD_ALLOW_INSECURE_SECRET=1` |

`start.sh` 自动处理: 存在 `${GUARD_DIR}/token-key` 或 `${GUARD_DIR}/shared-secret` dev keyfile, 或 env 已设 → 传对应 flag。无 keyfile / env 未设 → 走 Keychain。

dev keyfile (本机便利):
```bash
python3 -c "import secrets;print(secrets.token_hex(32))" > ~/.fusion-guard/token-key
python3 -c "import secrets;print(secrets.token_hex(32))" > ~/.fusion-guard/shared-secret
./start.sh start   # start.sh 检测 keyfile → 传 --insecure-env-key + --insecure-secret-env
```

⚠️ **dev keyfile 切勿入库** (`.gitignore` 已排除 `~/.fusion-guard/`, 但跨机器勿手动 copy)。

## Release Gate (H-C)

release 构建 (非 `debug_assertions`) 启动时, `require_shared_secret_for_release()` 检查 shared secret 两来源:

1. Keychain 有 `fusion-guard` / `shared-secret` → 放行。
2. env `FUSION_GUARD_SHARED_SECRET` 设 **且** `FUSION_GUARD_ALLOW_INSECURE_SECRET=1` → 放行 (warn)。
3. 两来源皆无 → **拒绝启动** (防仅 peercred 兜底被同 UID 攻陷进程全权调用)。

应急放行: `FUSION_GUARD_ALLOW_NO_SECRET=1` (运维知情, peercred-only, 非 prod)。

该 flag 同时作用于两处: (1) 启动 gate 放行 (不拒启动); (2) `load_shared_secret` 跳过 secret 加载 → `authorize_method` 不校验 secret (peercred-only 鉴权)。CI/soak spawn release daemon 设此 flag 即可, 客户端无需携 secret。prod 移除该 flag, 否则第二因子失效仅剩 peercred 兜底。

dev 构建 (debug) 跳过 gate, 容许 secret 缺失 (测试便利)。

token key 无独立 release gate, 但 `FUSION_GUARD_TOKEN_KEY` 在 release 未放行时 → `KeychainRequired` 路径: macOS 走 Keychain, 非 macOS 拒启动。

## 快速部署清单 (prod, macOS 单节点)

```bash
# 1. 构建 release
cargo build --release

# 2. 预置 Keychain 密钥 (推荐, 跳过自动生成)
TK=$(python3 -c "import secrets;print(secrets.token_hex(32))")
SS=$(python3 -c "import secrets;print(secrets.token_hex(32))")
security add-generic-password -s fusion-guard -a token-key -w "${TK}"
security add-generic-password -s fusion-guard -a shared-secret -w "${SS}"

# 3. 启动 (start.sh 检测无 keyfile/env → 走 Keychain, 不传 insecure flag)
./start.sh start

# 4. 验证
./start.sh status
./start.sh doctor
# 客户端调用须携 shared secret (非 ping):
#   {"jsonrpc":"2.0","id":1,"method":"guard.evaluate","params":{"secret":"<SHARED_SECRET>","content":"...","caller_epoch":0}}
```

## 多节点部署 (cluster)

跨节点 (fg-cluster, multi-nodes#52) 须各节点 **shared secret 一致** (验签 confirm relay MAC)。token key 各节点可独立 (可逆 token 不跨节点同步), 但若启用审计链联邦同步, chain-HMAC key 派生自 token key → 各节点须一致以互验。

预置时各节点写入**同一**密钥值 (Keychain account `shared-secret` / `token-key`)。

## launchd 常驻

`install-launchd.sh` 渲染 `com.fusion-mlx.guard.plist` 到 `~/Library/LaunchAgents` (用户域, 读用户 Keychain):

```bash
./install-launchd.sh install    # 渲染 + load
./install-launchd.sh status     # 查运行状态
./install-launchd.sh uninstall  # unload + 删 plist
```

plist 占位符 `__GUARD_BIN__` / `__HOME__` 渲染为真实绝对路径; 残留占位符检测中止 (防半渲染产物)。launchd 以用户身份启动 → Keychain 访问正常。

## 密钥轮换

轮换分两种语义, 不可混淆:

- **版本轮换 (rotate_key, 推荐常态)**: master key 不变, 仅 bump `key_version`。HKDF 按 version 派生新 chain/token key; 旧行落库时记旧 `key_version`, 用旧派生 key 验/解 (确定性 HKDF, 同 master 可重算)。**历史数据轮换后仍可验可解**, 无需 re-hash/re-encrypt。
  ```bash
  # IPC 调用 (bump version, master 不动, 不碰 Keychain)
  # {"jsonrpc":"2.0","id":1,"method":"guard.key.rotate","params":{"secret":"<SHARED_SECRET>"}}
  # 返回 new_version。之后新审计行/token 记 new_version。
  ```
  验证: `guard.audit.verify` 透过 (混合 v1+v2 链 broken_links=0, tampered=false)。测试 `he_key_loss_distinguish_test::rotation_all_chains_and_tokens_verify` 覆盖全 4 链 + token。

- **master key 替换 (慎用, 非常态)**: 真·换 Keychain 主密钥。**不在 rotate_key 接口语义内** (与 H-E (a) 拒绝 remint 一致)。仅当 master 疑似泄露且已 escrow 旧 key (只读保留以验旧链) 时做。替换后旧 `key_version` 的审计链锚点与新 master 不匹配 → 被归类为"密钥丢失" (见下), 非假篡改。流程: escrow 旧 key → 写新 key 到 Keychain → 重启。

> ⚠️ **re-hash 审计链被刻意拒绝**: 即便 master 替换, 也**不**用新 key 重算历史行的 HMAC。防篡改的保证正是"hash 不可变" —— re-sign 等于自废武功, 攻击者无法区分真篡改与运维 re-hash。正确做法: 旧 key escrow 只读保留, 旧链用旧 key 验 (锚点匹配旧 master); 新链起新 version。`guard.audit.verify` 的 `key_loss` 字段区分"密钥丢失"与"真篡改"。

- **shared secret 轮换**: 直接 Keychain 更新 + 重启 + 同步所有客户端新 secret。无版本化 (第二因子, 非加密密钥), 轮换瞬间旧 client secret 失效。

## 密钥丢失区分 (H-E item d)

`guard.audit.verify` 返回字段区分 HMAC 不匹配的根因, 避免密钥丢失被误报为全量篡改:

| 字段 | 含义 |
|------|------|
| `tampered` | 真·篡改 (同 master 能派生该行 version, 但 HMAC 对不上 = 内容被改) 或 prev_hash 断链或空 hash 行 |
| `key_version_unknown_rows` | 密钥丢失行数: 行 version 锚点与当前 master 重算不匹配 (master 无法派生该 version) |
| `key_loss` | 聚合: 任一链有 `key_version_unknown_rows > 0` |
| `broken_links` | 总不可验证行数 = 篡改 + 丢失 + 空hash |

诊断逻辑 (per-version `key_anchor`):
- 纯密钥丢失 (master 换了, 无内容篡改): `key_loss=true`, `tampered=false`, `key_version_unknown_rows>0` → 从 escrow 恢复原 master 即可复验, **非安全事件**。
- 真篡改: `tampered=true`, `key_version_unknown_rows=0` → 立即按安全事件响应。
- 锚点缺失 (legacy NULL 迁移行 / 攻击者清锚点): fail-closed 当 `tampered` (攻击者无法靠删锚点把篡改伪装成密钥丢失)。

旧库 (H-E 迁移前无 `key_anchor` 列) 启动时 idempotent `ALTER TABLE ADD COLUMN key_anchor TEXT`, 旧行锚点 NULL → 验证时若 HMAC 不匹配则 fail-closed 当篡改 (保守)。新行 mint/rotate 即写锚点。
