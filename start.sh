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
    if [ -z "${FUSION_GUARD_TOKEN_KEY:-}" ]; then
        local keyfile="${GUARD_DIR}/token-key"
        if [ -r "${keyfile}" ]; then
            echo "[${GUARD_NAME}] WARNING: dev keyfile ${keyfile} in use — passing --insecure-env-key (P2-2: prod use Keychain)" >&2
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
