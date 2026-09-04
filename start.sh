#!/usr/bin/env bash
set -euo pipefail

GUARD_NAME="fusion-guard"
GUARD_DIR="${HOME}/.fusion-guard"
GUARD_SOCK="${FUSION_GUARD_SOCK:-/tmp/fusion-guard.sock}"
GUARD_PID="${GUARD_DIR}/run/fusion-guard.pid"
GUARD_LOG="${GUARD_DIR}/logs/fusion-guard.log"
GUARD_BIN="$(cd "$(dirname "$0")" && pwd)/target/release/${GUARD_NAME}"

mkdir -p "${GUARD_DIR}/run" "${GUARD_DIR}/logs" "${GUARD_DIR}/audit-archive"

cmd="${1:-status}"

# Issue #17: strip --headless flag from args so it isn't mistaken for a
# subcommand. `start --headless` → cmd=start, HEADLESS=1.
HEADLESS=0
case "${cmd}" in
    --headless) HEADLESS=1; cmd="${2:-status}" ;;
    start|stop|status|log|doctor)
        if [ "${2:-}" = "--headless" ]; then HEADLESS=1; fi
        ;;
esac

# Issue #17: headless detection. macOS Keychain (SecItemCopyMatching /
# get_generic_password) serially blocks in non-interactive sessions (no
# WindowServer / SSH / launchd-without-gui / CI). Both token-key master and
# shared-secret Keychain reads hang the daemon on startup in release builds
# when no env/keyfile escape hatch is set. Auto-detect headless so the daemon
# fails open to a keyfile path (skips Keychain) instead of hanging silently.
#
# Headless when: --headless flag passed, FUSION_GUARD_HEADLESS=1 set, OR
# heuristics — no tty (stdin not a tty) or under SSH (SSH_CONNECTION /
# SSH_TTY / SSH_CLIENT set). Explicit --headless or env wins even on a
# desktop with a tty. Desktop interactive sessions default to Keychain (prod).
if [ "${FUSION_GUARD_HEADLESS:-}" = "1" ]; then
    HEADLESS=1
fi
if [ "${HEADLESS}" -eq 0 ]; then
    if [ ! -t 0 ]; then
        HEADLESS=1
    elif [ -n "${SSH_CONNECTION:-}${SSH_TTY:-}${SSH_CLIENT:-}" ]; then
        HEADLESS=1
    fi
fi
if [ "${HEADLESS}" -eq 1 ]; then
    echo "[${GUARD_NAME}] headless mode: Keychain skipped, keyfile path (issue #17)" >&2
fi

start() {
    if [ -f "${GUARD_PID}" ] && kill -0 "$(cat "${GUARD_PID}")" 2>/dev/null; then
        echo "[${GUARD_NAME}] already running, pid=$(cat "${GUARD_PID}")"
        return 0
    fi
    if [ ! -x "${GUARD_BIN}" ]; then
        echo "[${GUARD_NAME}] binary missing, build first: cargo build --release" >&2
        return 1
    fi
    # P2-2 (audit §P2-2): 主动清 stale socket。上次崩溃残留 socket 文件会致新进程 bind 报
    # "address already in use"。守护进程 serve() 内虽 remove_file, 但 start.sh 侧先清更稳,
    # 且 stop() 已清 —— 此处补 start 路径 (崩溃后重启无 stale socket 阻塞)。
    if [ -S "${GUARD_SOCK}" ] && [ ! -f "${GUARD_PID}" ]; then
        echo "[${GUARD_NAME}] clearing stale socket ${GUARD_SOCK} (no pid file)"
        rm -f "${GUARD_SOCK}"
    fi
    export FUSION_GUARD_SOCK="${GUARD_SOCK}"
    export FUSION_GUARD_LOG_DIR="${GUARD_DIR}/logs"
    local guard_args=(start)
    # P2-2 (audit §P2-2): 生产用 Keychain 免 env 传递主密钥。dev keyfile 是 escape hatch ——
    # 仅当显式存在 ${GUARD_DIR}/token-key 时, 读入 env + 传 --insecure-env-key flag 放行
    # (release 默认 Keychain, env key 需 flag 否则 KeychainRequired 拒启动)。
    # 无 keyfile → 不导 env, 不传 flag → 走 macOS Keychain (prod 路径, 密钥不入环境变量)。
    # Issue #17: headless 下 Keychain 串行阻塞 (无 WindowServer)。headless + 无 env + 无 keyfile
    # → 自动生成 32-byte hex keyfile (600 perms, 重启复用同密钥, 保 DLP + 审计链跨重启可验),
    # 传 --insecure-env-key。不生成 = Keychain 挂死; 生成优于「allow-no-key」(后者废 DLP)。
    if [ -z "${FUSION_GUARD_TOKEN_KEY:-}" ]; then
        local keyfile="${GUARD_DIR}/token-key"
        if [ -r "${keyfile}" ]; then
            echo "[${GUARD_NAME}] WARNING: dev keyfile ${keyfile} in use — passing --insecure-env-key (P2-2: prod use Keychain)" >&2
            export FUSION_GUARD_TOKEN_KEY="$(cat "${keyfile}")"
            guard_args+=(--insecure-env-key)
        elif [ "${HEADLESS}" -eq 1 ]; then
            echo "[${GUARD_NAME}] WARNING: headless detected, no Keychain (issue #17) — auto-generating token-key keyfile ${keyfile} (INSECURE: file-backed, prod on desktop should delete + use Keychain)" >&2
            generate_token_keyfile "${keyfile}"
            export FUSION_GUARD_TOKEN_KEY="$(cat "${keyfile}")"
            guard_args+=(--insecure-env-key)
        else
            echo "[${GUARD_NAME}] no dev keyfile — prod Keychain path (P2-2)" >&2
        fi
    else
        # env 已由 operator 显式设 → 同样需 flag 放行 release gate。
        echo "[${GUARD_NAME}] WARNING: FUSION_GUARD_TOKEN_KEY from env — passing --insecure-env-key (P2-2: prod use Keychain)" >&2
        guard_args+=(--insecure-env-key)
    fi
    # H-C secret 侧: 共享 secret (§12.1 第二因子) 来源。镜像 token-key 模式:
    # - env 已设 (FUSION_GUARD_SHARED_SECRET) → 传 --insecure-secret-env flag 放行 release gate (env = 同 UID 可读, escape hatch)。
    # - dev keyfile ${GUARD_DIR}/shared-secret 存在 → 读入 env + flag (escape hatch)。
    # - 两处皆无 → 不导 env 不传 flag → 走 macOS Keychain (account shared-secret, prod 路径)。
    #   release 守护进程首次启动 Keychain 无 secret 时自动生成存 Keychain (PeerAuthorizer::load_shared_secret)。
    #   operator 也可预置: `security add-generic-password -s fusion-guard -a shared-secret -w <secret>`。
    if [ -z "${FUSION_GUARD_SHARED_SECRET:-}" ]; then
        local secret_keyfile="${GUARD_DIR}/shared-secret"
        if [ -r "${secret_keyfile}" ]; then
            echo "[${GUARD_NAME}] WARNING: dev shared-secret keyfile ${secret_keyfile} in use — passing --insecure-secret-env (H-C: prod use Keychain)" >&2
            export FUSION_GUARD_SHARED_SECRET="$(cat "${secret_keyfile}")"
            guard_args+=(--insecure-secret-env)
        elif [ "${HEADLESS}" -eq 1 ]; then
            # Issue #17: headless 下 Keychain read 阻塞。headless + 无 env + 无 keyfile →
            # 自动生成 secret keyfile (重启复用, 客户端须配同 secret), 传 --insecure-secret-env。
            # 比 FUSION_GUARD_ALLOW_NO_SECRET=1 (peercred-only, 丢第二因子) 更强: 保 §12.1 双因子。
            echo "[${GUARD_NAME}] WARNING: headless detected, no Keychain (issue #17) — auto-generating shared-secret keyfile ${secret_keyfile} (INSECURE: file-backed; clients must carry same secret)" >&2
            generate_secret_keyfile "${secret_keyfile}"
            export FUSION_GUARD_SHARED_SECRET="$(cat "${secret_keyfile}")"
            guard_args+=(--insecure-secret-env)
        else
            echo "[${GUARD_NAME}] no dev shared-secret keyfile — prod Keychain path (H-C, account shared-secret)" >&2
        fi
    else
        echo "[${GUARD_NAME}] WARNING: FUSION_GUARD_SHARED_SECRET from env — passing --insecure-secret-env (H-C: prod use Keychain)" >&2
        guard_args+=(--insecure-secret-env)
    fi
    nohup "${GUARD_BIN}" "${guard_args[@]}" >"${GUARD_LOG}" 2>&1 &
    local pid=$!
    echo "${pid}" > "${GUARD_PID}"
    sleep 0.5
    if kill -0 "${pid}" 2>/dev/null; then
        echo "[${GUARD_NAME}] started, pid=${pid}, sock=${GUARD_SOCK}"
    else
        echo "[${GUARD_NAME}] failed to start, check ${GUARD_LOG}" >&2
        rm -f "${GUARD_PID}"
        return 1
    fi
}

# Issue #17 helpers: headless 下自动生成密钥文件 (替代 Keychain, 避免串行阻塞)。
# token-key: 32-byte 随机 hex (64 chars), 与 FUSION_GUARD_TOKEN_KEY 格式一致 (KEY_LEN=32)。
# shared-secret: 32-byte URL-safe base64 (强随机第二因子)。
# 均 600 perms, 仅 owner 可读。生成前清旧文件防 cat 残留。重启复用 (不覆盖已存在文件 ——
# 调用方先 [ -r ] 判存在, 此处仅生成缺失场景)。
generate_token_keyfile() {
    local path="$1"
    local hex
    # /dev/urandom → 32 bytes → hex。openssl 回退 (urandom 不可用时)。
    if [ -r /dev/urandom ]; then
        hex="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    else
        hex="$(openssl rand -hex 32)"
    fi
    ( umask 077; printf '%s' "${hex}" >"${path}" )
    chmod 600 "${path}"
}

generate_secret_keyfile() {
    local path="$1"
    local secret
    if [ -r /dev/urandom ]; then
        secret="$(head -c 32 /dev/urandom | base64)"
    else
        secret="$(openssl rand -base64 32)"
    fi
    ( umask 077; printf '%s' "${secret}" >"${path}" )
    chmod 600 "${path}"
}

stop() {
    if [ ! -f "${GUARD_PID}" ]; then
        echo "[${GUARD_NAME}] not running (no pid file)"
        return 0
    fi
    local pid
    pid="$(cat "${GUARD_PID}")"
    if kill -0 "${pid}" 2>/dev/null; then
        kill -TERM "${pid}" 2>/dev/null || true
        sleep 1
        if kill -0 "${pid}" 2>/dev/null; then
            kill -KILL "${pid}" 2>/dev/null || true
        fi
        echo "[${GUARD_NAME}] stopped, pid=${pid}"
    else
        echo "[${GUARD_NAME}] stale pid file, removing"
    fi
    rm -f "${GUARD_PID}"
    rm -f "${GUARD_SOCK}"
}

status() {
    if [ -f "${GUARD_PID}" ] && kill -0 "$(cat "${GUARD_PID}")" 2>/dev/null; then
        echo "[${GUARD_NAME}] running, pid=$(cat "${GUARD_PID}"), sock=${GUARD_SOCK}"
    else
        echo "[${GUARD_NAME}] not running"
    fi
}

log() {
    tail -n 100 -f "${GUARD_LOG}" 2>/dev/null || echo "[${GUARD_NAME}] no log at ${GUARD_LOG}"
}

doctor() {
    echo "=== ${GUARD_NAME} doctor ==="
    echo "binary: ${GUARD_BIN}"
    [ -x "${GUARD_BIN}" ] && echo "  [ok] binary exists" || echo "  [fail] binary missing"
    echo "pid file: ${GUARD_PID}"
    if [ -f "${GUARD_PID}" ] && kill -0 "$(cat "${GUARD_PID}")" 2>/dev/null; then
        echo "  [ok] process alive, pid=$(cat "${GUARD_PID}")"
    else
        echo "  [warn] process not running"
    fi
    echo "socket: ${GUARD_SOCK}"
    [ -S "${GUARD_SOCK}" ] && echo "  [ok] socket exists" || echo "  [warn] socket absent"
    if [ -x "${GUARD_BIN}" ]; then
        "${GUARD_BIN}" ping --sock "${GUARD_SOCK}" 2>&1 | head -5
    fi
}

case "${cmd}" in
    start)  start ;;
    stop)   stop ;;
    status) status ;;
    log)    log ;;
    doctor) doctor ;;
    *) echo "usage: $0 {start|stop|status|log|doctor}" >&2; exit 1 ;;
esac
