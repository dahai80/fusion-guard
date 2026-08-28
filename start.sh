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
    export FUSION_GUARD_SOCK="${GUARD_SOCK}"
    export FUSION_GUARD_LOG_DIR="${GUARD_DIR}/logs"
    if [ -z "${FUSION_GUARD_TOKEN_KEY:-}" ]; then
        local keyfile="${GUARD_DIR}/token-key"
        if [ -r "${keyfile}" ]; then
            export FUSION_GUARD_TOKEN_KEY="$(cat "${keyfile}")"
        else
            echo "[${GUARD_NAME}] WARNING: token-key file missing at ${keyfile}, Keychain prompt may appear" >&2
            echo "  fix: echo <64-hex-chars> > ${keyfile} && chmod 600 ${keyfile}" >&2
        fi
    fi
    nohup "${GUARD_BIN}" start >"${GUARD_LOG}" 2>&1 &
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
