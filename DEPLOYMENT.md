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

- **token key 轮换**: `guard` IPC 暴露轮换接口 (bump key_version, HKDF 新派生 key; 旧 key_version 行用旧 key 验/解)。轮换后 Keychain 更新:
  ```bash
  NEW=$(python3 -c "import secrets;print(secrets.token_hex(32))")
  security delete-generic-password -s fusion-guard -a token-key
  security add-generic-password -s fusion-guard -a token-key -w "${NEW}"
  # 重启守护进程加载新 key (旧 key_version 数据仍可解 — 版本化派生)
  ```
- **shared secret 轮换**: 直接 Keychain 更新 + 重启 + 同步所有客户端新 secret。无版本化 (第二因子, 非加密密钥), 轮换瞬间旧 client secret 失效。
