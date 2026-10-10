import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx

logger = logging.getLogger("fusion_guard.laya_guard")

DEFAULT_THRESHOLDS = {
    "jailbreak": 0.5,
    "prompt_injection": 0.5,
    "sensitive_data": 0.5,
    "harm_severity": 2.0,
}

THRESHOLD_ENV = {
    "jailbreak": "LAYA_GUARD_JAILBREAK_THRESHOLD",
    "prompt_injection": "LAYA_GUARD_INJECTION_THRESHOLD",
    "sensitive_data": "LAYA_GUARD_SENSITIVE_THRESHOLD",
    "harm_severity": "LAYA_GUARD_HARM_SEVERITY_THRESHOLD",
}

DIM_TYPES = {
    "jailbreak": "noul",
    "prompt_injection": "noul",
    "sensitive_data": "noul",
    "harm_severity": "score",
    "topic": "choice",
}


@dataclass
class DimensionScore:
    name: str
    dim_type: str
    value: float
    confidence: float
    threshold: Optional[float]
    exceeded: bool


@dataclass
class GuardResult:
    blocked: bool
    reasons: list
    dimensions: dict
    topic: Optional[str]
    latency_ms: float
    model: Optional[str]
    fallback: bool

    def to_dict(self):
        return {
            "blocked": self.blocked,
            "reasons": self.reasons,
            "dimensions": {
                k: {
                    "type": v.dim_type,
                    "value": v.value,
                    "confidence": v.confidence,
                    "threshold": v.threshold,
                    "exceeded": v.exceeded,
                }
                for k, v in self.dimensions.items()
            },
            "topic": self.topic,
            "latency_ms": self.latency_ms,
            "model": self.model,
            "fallback": self.fallback,
        }


def _load_thresholds():
    thresholds = dict(DEFAULT_THRESHOLDS)
    for dim, env_key in THRESHOLD_ENV.items():
        raw = os.environ.get(env_key)
        if raw is None:
            continue
        try:
            thresholds[dim] = float(raw)
        except ValueError:
            logger.warning("invalid threshold env %s=%r, using default", env_key, raw)
    return thresholds


def _parse_answer(name, answer, threshold):
    dim_type = DIM_TYPES.get(name, answer.get("type", "noul"))
    confidence = float(answer.get("confidence", 0.0))
    if dim_type == "choice":
        value = 0.0
        choice = answer.get("choice")
    elif dim_type == "score":
        value = float(answer.get("score", 0.0))
        choice = None
    else:
        value = float(answer.get("noul", 0.0))
        choice = None
    exceeded = threshold is not None and value >= threshold
    return DimensionScore(
        name=name,
        dim_type=dim_type,
        value=value,
        confidence=confidence,
        threshold=threshold,
        exceeded=exceeded,
    ), choice


@dataclass
class LayaGuardClient:
    base_url: str = "http://127.0.0.1:11434"
    api_key: Optional[str] = None
    timeout: float = 5.0
    thresholds: dict = field(default_factory=_load_thresholds)

    def __post_init__(self):
        if self.api_key is None:
            self.api_key = os.environ.get("FUSION_MLX_API_KEY")
        self._endpoint = self.base_url.rstrip("/") + "/v1/laya/decide"
        self._headers = {"Content-Type": "application/json"}
        if self.api_key:
            self._headers["Authorization"] = "Bearer " + self.api_key

    def evaluate(self, prompt):
        start = time.perf_counter()
        reasons = []
        dimensions = {}
        topic = None
        model = None
        try:
            resp = httpx.post(
                self._endpoint,
                json={"prompt": prompt, "preset": "guard"},
                headers=self._headers,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            latency = (time.perf_counter() - start) * 1000.0
            logger.warning("laya endpoint unavailable, fail-open: %s", e)
            return GuardResult(
                blocked=False,
                reasons=["laya_unavailable:" + type(e).__name__],
                dimensions={},
                topic=None,
                latency_ms=latency,
                model=None,
                fallback=True,
            )
        model = data.get("model")
        answers = data.get("answers", {})
        for name in ("jailbreak", "prompt_injection", "sensitive_data", "harm_severity", "topic"):
            ans = answers.get(name)
            if ans is None:
                continue
            threshold = self.thresholds.get(name) if name != "topic" else None
            ds, choice = _parse_answer(name, ans, threshold)
            dimensions[name] = ds
            if name == "topic":
                topic = choice
            if ds.exceeded:
                reasons.append("{}={:.4f} >= {:.4f}".format(name, ds.value, ds.threshold))
        latency = float(data.get("latency_ms", (time.perf_counter() - start) * 1000.0))
        blocked = len(reasons) > 0
        flagged = []
        for name, ds in dimensions.items():
            if name == "topic" or ds.exceeded:
                continue
            if ds.value > 0.0:
                flagged.append("{}={:.4f}".format(name, ds.value))
        if blocked:
            logger.warning(
                "laya-guard BLOCKED prompt | reasons=%s | topic=%s | latency=%.2fms",
                reasons, topic, latency,
            )
        elif flagged:
            logger.info(
                "laya-guard flagged (below threshold, non-zero) | %s | topic=%s | latency=%.2fms",
                flagged, topic, latency,
            )
        else:
            logger.debug("laya-guard allowed | topic=%s | latency=%.2fms", topic, latency)
        return GuardResult(
            blocked=blocked,
            reasons=reasons,
            dimensions=dimensions,
            topic=topic,
            latency_ms=latency,
            model=model,
            fallback=False,
        )
