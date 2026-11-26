# fusion_guard — Python client for fusion-guard daemon.
# Issue #5: maturin builds the fusion_guard._native extension (PyO3); this __init__ re-exports the public symbols,
# so that `from fusion_guard import NativeGuardClient` works (issue #5 acceptance criterion).
# The client connects to a running daemon (FUSION_GUARD_SOCK, default /tmp/fusion-guard.sock), not an in-process engine.

from . import _native
from ._native import (
    NativeAllChainsVerification,
    NativeChainVerification,
    NativeGuardClient,
    NativeGuardRule,
    NativeGuardVerdict,
    NativeRedactResult,
    version_info,
)
from .laya_guard import DimensionScore, GuardResult, LayaGuardClient
from .two_tier import LAYA_MAX_PROMPT_CHARS, TwoTierGuard, TwoTierResult

__all__ = [
    "NativeGuardClient",
    "NativeGuardVerdict",
    "NativeGuardRule",
    "NativeRedactResult",
    "NativeChainVerification",
    "NativeAllChainsVerification",
    "version_info",
    "_native",
    "LayaGuardClient",
    "GuardResult",
    "DimensionScore",
    "TwoTierGuard",
    "TwoTierResult",
    "LAYA_MAX_PROMPT_CHARS",
]

__version__ = "0.2.0-rc.14"
