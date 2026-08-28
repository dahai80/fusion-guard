# fusion_guard — Python client for fusion-guard daemon.
# Issue #5: maturin 产出 fusion_guard._native 扩展 (PyO3), 本 __init__ 透传公开符号,
# 使 `from fusion_guard import NativeGuardClient` 可用 (issue #5 验收条件)。
# 客户端连运行中的守护进程 (FUSION_GUARD_SOCK, 默认 /tmp/fusion-guard.sock), 非 in-process engine。

from . import _native
from ._native import (
    NativeGuardClient,
    NativeGuardVerdict,
    NativeGuardRule,
    NativeRedactResult,
    NativeChainVerification,
    NativeAllChainsVerification,
    version_info,
)

__all__ = [
    "NativeGuardClient",
    "NativeGuardVerdict",
    "NativeGuardRule",
    "NativeRedactResult",
    "NativeChainVerification",
    "NativeAllChainsVerification",
    "version_info",
    "_native",
]

__version__ = "0.1.2"
