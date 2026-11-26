import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .laya_guard import GuardResult, LayaGuardClient

logger = logging.getLogger("fusion_guard.two_tier")

# Issue #45: laya model max_len is 1024 tokens — pre-check runs on the
# user-visible prompt, truncated to this bound before the laya call.
LAYA_MAX_PROMPT_CHARS = 1024

DEFAULT_MIN_CONFIDENCE = 0.8

MIN_CONFIDENCE_ENV = "LAYA_GUARD_MIN_CONFIDENCE"

# All four scored dimensions must be present before the pre-check may allow
# locally — a missing answer is an unknown, not a pass. The confidence gate
# applies ONLY to the three noul dimensions: live measurement (issue #45)
# shows the server discounts harm_severity confidence by design ("harm
# severity discounted when other dimensions are clean" — false-positive
# damping), so gating it would zero out the pass-through rate. harm_severity
# safety is already enforced by its threshold via blocked.
NOUL_DIMS = frozenset({"jailbreak", "prompt_injection", "sensitive_data"})
SCORED_DIMS = frozenset(NOUL_DIMS | {"harm_severity"})


def _load_min_confidence():
    raw = os.environ.get(MIN_CONFIDENCE_ENV)
    if raw is None:
        return DEFAULT_MIN_CONFIDENCE
    try:
        v = float(raw)
    except ValueError:
        logger.warning("invalid %s=%r, using default", MIN_CONFIDENCE_ENV, raw)
        return DEFAULT_MIN_CONFIDENCE
    if v < 0.0 or v > 1.0:
        logger.warning("%s=%r out of [0,1], using default", MIN_CONFIDENCE_ENV, raw)
        return DEFAULT_MIN_CONFIDENCE
    return v


@dataclass
class TwoTierResult:
    tier: str
    precheck: GuardResult
    full_result: Optional[Any]
    pass_through: bool
    total_latency_ms: float

    def to_dict(self):
        return {
            "tier": self.tier,
            "pass_through": self.pass_through,
            "total_latency_ms": self.total_latency_ms,
            "precheck": self.precheck.to_dict(),
            "full_result": self.full_result,
        }


@dataclass
class TwoTierGuard:
    laya: LayaGuardClient = field(default_factory=LayaGuardClient)
    full_evaluate: Optional[Callable[[str], Any]] = None
    min_confidence: float = field(default_factory=_load_min_confidence)
    stats: dict = field(
        default_factory=lambda: {
            "total": 0,
            "fast_allow": 0,
            "escalated": 0,
            "precheck_fallback": 0,
            "truncated_prompts": 0,
        }
    )

    def __post_init__(self):
        if self.full_evaluate is None:
            # Imported lazily: the PyO3 native module may be absent in
            # laya-only deployments. Failure surfaces on first escalation.
            from . import _native

            client = _native.NativeGuardClient()
            self.full_evaluate = lambda prompt: client.evaluate(prompt)

    def _is_high_confidence_clean(self, pre: GuardResult) -> bool:
        if pre.blocked or pre.fallback:
            return False
        if not SCORED_DIMS.issubset(pre.dimensions.keys()):
            return False
        for name, ds in pre.dimensions.items():
            if name not in NOUL_DIMS:
                continue
            if ds.confidence < self.min_confidence:
                return False
        return True

    def _escalate(self, prompt, pre, start):
        logger.info(
            "two-tier escalate to full guard evaluation | precheck_latency=%.2fms | "
            "precheck_blocked=%s | precheck_fallback=%s",
            pre.latency_ms,
            pre.blocked,
            pre.fallback,
        )
        full = self.full_evaluate(prompt)
        total = (time.perf_counter() - start) * 1000.0
        self.stats["escalated"] += 1
        return TwoTierResult(
            tier="escalated",
            precheck=pre,
            full_result=full,
            pass_through=False,
            total_latency_ms=total,
        )

    def evaluate(self, prompt):
        start = time.perf_counter()
        self.stats["total"] += 1
        precheck_prompt = prompt
        truncated = False
        if len(precheck_prompt) > LAYA_MAX_PROMPT_CHARS:
            truncated = True
            self.stats["truncated_prompts"] += 1
            logger.debug(
                "pre-check prompt truncated %d -> %d chars (laya max_len bound)",
                len(precheck_prompt),
                LAYA_MAX_PROMPT_CHARS,
            )
            precheck_prompt = precheck_prompt[:LAYA_MAX_PROMPT_CHARS]
        pre = self.laya.evaluate(precheck_prompt)
        if truncated:
            # Content beyond the laya max_len bound was never scanned by the
            # pre-check — this traffic cannot "certainly pass", so it always
            # escalates to the full evaluation (issue #45 zero-verdict-change
            # intent; the pre-check run above stays for logging/visibility).
            return self._escalate(prompt, pre, start)
        if pre.fallback:
            # Explicit fail-open per issue #45 constraints: laya unavailable
            # falls through to the existing evaluation path, never a silent
            # allow. The fallback reason stays visible in the result.
            self.stats["precheck_fallback"] += 1
            return self._escalate(prompt, pre, start)
        if self._is_high_confidence_clean(pre):
            total = (time.perf_counter() - start) * 1000.0
            self.stats["fast_allow"] += 1
            logger.info(
                "two-tier FAST ALLOW (full evaluation skipped) | precheck_latency=%.2fms | total=%.2fms | topic=%s",
                pre.latency_ms,
                total,
                pre.topic,
            )
            return TwoTierResult(
                tier="fast_allow",
                precheck=pre,
                full_result=None,
                pass_through=True,
                total_latency_ms=total,
            )
        return self._escalate(prompt, pre, start)

    def pass_through_rate(self):
        total = self.stats["total"]
        if total == 0:
            return 0.0
        return self.stats["fast_allow"] / total

    def validate_agreement(self, samples):
        # Issue #45 acceptance: on a sample, pre-check allow decisions must
        # agree with the full guard verdict. Escalated samples are excluded
        # (the full verdict governs them by construction).
        agreed = 0
        disagreed = 0
        details = []
        for prompt in samples:
            pre = self.laya.evaluate(prompt[:LAYA_MAX_PROMPT_CHARS])
            if pre.fallback or pre.blocked:
                continue
            full = self.full_evaluate(prompt)
            full_blocked = self._full_verdict_blocked(full)
            if full_blocked:
                disagreed += 1
                details.append({"prompt_prefix": prompt[:80], "precheck": "clean", "full": "blocked"})
            else:
                agreed += 1
        total = agreed + disagreed
        rate = (agreed / total) if total else 1.0
        result = {
            "sampled": total,
            "agreed": agreed,
            "disagreed": disagreed,
            "agreement_rate": rate,
            "details": details,
        }
        logger.info(
            "two-tier agreement validation | sampled=%d agreed=%d disagreed=%d rate=%.4f",
            total,
            agreed,
            disagreed,
            rate,
        )
        return result

    def _full_verdict_blocked(self, full):
        if full is None:
            return False
        if isinstance(full, dict):
            action = full.get("action") or full.get("verdict", {}).get("action")
            return str(action).lower() in ("block", "blocked")
        action = getattr(full, "action", None)
        if action is not None:
            return str(action).lower() in ("block", "blocked")
        blocked = getattr(full, "blocked", None)
        if blocked is not None:
            return bool(blocked)
        return False
