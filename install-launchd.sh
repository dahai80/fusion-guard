#!/usr/bin/env bash
# H-G (product-audit §H-G): launchd plist 安装就绪脚本。
#
# com.fusion-mlx.guard.plist 是模板态 —— 含未替换占位符 __GUARD_BIN__ (line 9) / __HOME__
# (line 17/24/26), 直接 launchctl load 会因路径无效启动失败, 非可部署产物。
# 本脚本: 渲染占位符 → 写入真实路径 plist → 设权限 0o600 → load → 验启动。
#
# 域选择: guard 读用户 macOS Keychain (token master key) → 须以用户身份跑 →
# ~/Library/LaunchAgents (用户域), 非 /Library/LaunchDaemons (系统域, root, 无用户 Keychain)。
# audit 措辞 "LaunchDaemons" 泛指 launchd 守护进程; 用户 Keychain 约束下 LaunchAgents 正确。
#
# 验收 (audit §H-G): launchctl load 成功启动守护进程; plist 无残留占位符; 权限 0o600。
#
# 用法: ./install-launchd.sh install|uninstall|status
#   install   渲染 plist + load
#   uninstall unload + 删渲染 plist
#   status    查 load 状态
set -euo pipefail

PLIST_TEMPLATE="$(cd "$(dirname "$0")" && pwd)/com.fusion-mlx.guard.plist"
LABEL="com.fusion-mlx.guard"
RENDERED_PLIST="${HOME}/Library/LaunchAgents/${LABEL}.plist"
GUARD_BIN="${FUSION_GUARD_BIN:-$(cd "$(dirname "$0")" && pwd)/target/release/fusion-guard}"

err() { echo "[install-launchd] ERROR: $*" >&2; exit 1; }
log() { echo "[install-launchd] $*"; }

render_plist() {
    [ -f "${PLIST_TEMPLATE}" ] || err "plist 模板缺失: ${PLIST_TEMPLATE}"
    # 占位符残留检测 (render 前模板必含, render 后渲染产物必无)。
    grep -q "__GUARD_BIN__" "${PLIST_TEMPLATE}" || err "模板无 __GUARD_BIN__ 占位符 — 模板已变, 检查"
    grep -q "__HOME__" "${PLIST_TEMPLATE}" || err "模板无 __HOME__ 占位符 — 模板已变, 检查"
    [ -x "${GUARD_BIN}" ] || err "binary 不可执行: ${GUARD_BIN} (先 cargo build --release 或设 FUSION_GUARD_BIN)"
    mkdir -p "$(dirname "${RENDERED_PLIST}")"
    # sed 替换两占位符 → 真实绝对路径。& 在 replacement 需转义 (路径含 / 用 | 分隔避免)。
    sed -e "s|__GUARD_BIN__|${GUARD_BIN}|g" -e "s|__HOME__|${HOME}|g" \
        "${PLIST_TEMPLATE}" > "${RENDERED_PLIST}"
    # 权限 0o600: 仅属主读写, 防其他用户篡改 ProgramArguments 指向恶意 binary。
    chmod 600 "${RENDERED_PLIST}"
    # 渲染后无残留占位符 (H-G 验收)。
    if grep -q "__GUARD_BIN__\|__HOME__" "${RENDERED_PLIST}"; then
        rm -f "${RENDERED_PLIST}"
        err "渲染后仍残留占位符 — 中止 (H-G 验收失败)"
    fi
    log "rendered plist → ${RENDERED_PLIST} (mode 0o600, no placeholders)"
}

install_launchd() {
    render_plist
    # 已 load 先 unload (幂等, 防 duplicate-label 报错)。
    launchctl unload "${RENDERED_PLIST}" 2>/dev/null || true
    launchctl load "${RENDERED_PLIST}" || err "launchctl load 失败 — 检查 plist + binary 权限"
    log "loaded ${LABEL} (launchctl load 成功)"
    # 验启动: launchctl list 含 label + PID 非 -。
    sleep 1
    if launchctl list "${LABEL}" >/dev/null 2>&1; then
        local pid
        pid="$(launchctl list "${LABEL}" 2>/dev/null | awk '/"PID"/{print $3}' | tr -d ' ;')"
        log "status: ${LABEL} loaded, pid=${pid:-starting}"
        log "H-G 验收通过: launchctl load 成功 + plist 无占位符 + 权限 0o600"
    else
        err "launchctl load 后 list 不见 ${LABEL} — 启动失败, 查 ~/.fusion-guard/logs/fusion-guard.launchd.err"
    fi
}

uninstall_launchd() {
    if [ -f "${RENDERED_PLIST}" ]; then
        launchctl unload "${RENDERED_PLIST}" 2>/dev/null || true
        rm -f "${RENDERED_PLIST}"
        log "unloaded + removed ${RENDERED_PLIST}"
    else
        log "no rendered plist at ${RENDERED_PLIST} — nothing to uninstall"
    fi
}

status_launchd() {
    if launchctl list "${LABEL}" >/dev/null 2>&1; then
        log "loaded: ${LABEL}"
        launchctl list "${LABEL}"
    else
        log "not loaded: ${LABEL}"
    fi
}

cmd="${1:-install}"
case "${cmd}" in
    install)   install_launchd ;;
    uninstall) uninstall_launchd ;;
    status)    status_launchd ;;
    *) echo "usage: $0 {install|uninstall|status}" >&2; exit 1 ;;
esac
