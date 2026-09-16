"""Runtime helpers that enforce RunSpec contracts during execution."""

from __future__ import annotations

import time
from time import perf_counter
from typing import Any

from .constants import COST_METRIC_KEYS, EVIDENCE_TEXT_LIMITS, RUN_PROFILE_DEFAULTS
from .types import BudgetSpec


class BudgetExceeded(RuntimeError):
    """Raised when a run exceeds duration or reported cost budget."""


class BudgetTracker:
    """Tracks wall-clock duration and reported USD cost against a BudgetSpec."""

    def __init__(self, budget: BudgetSpec):
        self.max_duration_seconds = budget.max_duration_seconds
        self.max_cost_usd = budget.max_cost_usd
        self.started = perf_counter()
        self.cost_usd = 0.0
        self.cost_samples = 0

    @property
    def elapsed_seconds(self) -> float:
        return perf_counter() - self.started

    def observe_metrics(self, metrics: dict[str, Any] | None) -> None:
        amount = extract_cost_usd(metrics)
        if amount is None:
            return
        self.cost_usd += amount
        self.cost_samples += 1

    def check(self, *, stage: str) -> None:
        elapsed = self.elapsed_seconds
        if elapsed > self.max_duration_seconds:
            raise BudgetExceeded(
                f"Budget exceeded: duration {elapsed:.1f}s > {self.max_duration_seconds}s at {stage}"
            )
        if (
            self.max_cost_usd is not None
            and self.cost_samples > 0
            and self.cost_usd > self.max_cost_usd
        ):
            raise BudgetExceeded(
                f"Budget exceeded: reported cost ${self.cost_usd:.4f} > ${self.max_cost_usd} at {stage}"
            )

    def snapshot(self) -> dict[str, Any]:
        return {
            "elapsed_seconds": round(self.elapsed_seconds, 4),
            "max_duration_seconds": self.max_duration_seconds,
            "cost_usd": round(self.cost_usd, 6),
            "cost_samples": self.cost_samples,
            "max_cost_usd": self.max_cost_usd,
            "cost_enforcement": (
                "enforced"
                if self.max_cost_usd is not None and self.cost_samples > 0
                else "unmetered"
                if self.max_cost_usd is not None
                else "unset"
            ),
        }


class RequestRateLimiter:
    """Sequential min-interval limiter for a single target adapter instance."""

    def __init__(self) -> None:
        self._last_request_at = 0.0

    def wait(self, rate_limits: dict[str, Any] | None) -> None:
        interval = min_request_interval_seconds(rate_limits)
        if interval is None or interval <= 0:
            return
        now = time.monotonic()
        wait_for = interval - (now - self._last_request_at)
        if wait_for > 0:
            time.sleep(wait_for)
        self._last_request_at = time.monotonic()


def extract_cost_usd(metrics: dict[str, Any] | None) -> float | None:
    if not metrics:
        return None
    for key in COST_METRIC_KEYS:
        raw = metrics.get(key)
        if raw is None:
            continue
        try:
            return float(raw)
        except (TypeError, ValueError):
            continue
    return None


def min_request_interval_seconds(rate_limits: dict[str, Any] | None) -> float | None:
    if not rate_limits:
        return None
    raw_interval = rate_limits.get("min_interval_seconds")
    if raw_interval is not None:
        try:
            parsed = float(raw_interval)
        except (TypeError, ValueError):
            parsed = 0.0
        if parsed > 0:
            return parsed
    raw_rpm = rate_limits.get("requests_per_minute")
    if raw_rpm is None:
        return None
    try:
        rpm = float(raw_rpm)
    except (TypeError, ValueError):
        return None
    if rpm <= 0:
        return None
    return 60.0 / rpm


def profile_defaults(run_profile: str) -> dict[str, Any]:
    return dict(RUN_PROFILE_DEFAULTS.get(run_profile, RUN_PROFILE_DEFAULTS["nightly"]))


def merge_profile_section(run_profile: str, section: str, explicit: dict[str, Any] | None) -> dict[str, Any]:
    defaults = dict(profile_defaults(run_profile).get(section, {}))
    if explicit is None:
        return defaults
    merged = dict(defaults)
    merged.update(explicit)
    return merged


def build_runtime_env(context: Any) -> dict[str, str]:
    env: dict[str, str] = {}
    run_id = getattr(context, "run_id", None)
    if run_id:
        # Tools that call the gateway can forward this as `X-URT-Run-Id` so their
        # traces join the run exactly rather than by time window.
        env["URT_RUN_ID"] = str(run_id)
    seed = getattr(context, "seed", None)
    if seed is not None:
        env["URT_SEED"] = str(seed)
        env["PYTHONHASHSEED"] = str(int(seed) % (2**32))
    scenarios = getattr(context, "enabled_scenarios", None) or []
    if scenarios:
        env["URT_ENABLED_SCENARIOS"] = ",".join(str(item) for item in scenarios)
    evidence = getattr(context, "evidence_level", None)
    if evidence:
        env["URT_EVIDENCE_LEVEL"] = str(evidence)
    profile = getattr(context, "run_profile", None)
    if profile:
        env["URT_RUN_PROFILE"] = str(profile)
    findings_path = getattr(context, "engine_findings_path", None)
    if findings_path:
        env["URT_ENGINE_FINDINGS_PATH"] = str(findings_path)
    return env


def limit_evidence_text(text: str, evidence_level: str | None) -> str:
    level = str(evidence_level or "standard").strip().lower()
    limit = EVIDENCE_TEXT_LIMITS.get(level, EVIDENCE_TEXT_LIMITS["standard"])
    if limit is None or len(text) <= limit:
        return text
    marker = "\n...[TRUNCATED]"
    keep = max(0, limit - len(marker))
    return text[:keep] + marker


def normalize_scenario_tokens(scenarios: list[str] | None) -> list[str]:
    tokens: list[str] = []
    seen: set[str] = set()
    for item in scenarios or []:
        token = str(item).strip().lower()
        if not token or token in seen:
            continue
        seen.add(token)
        tokens.append(token)
    return tokens


def value_matches_scenarios(value: Any, scenarios: list[str] | None) -> bool:
    tokens = normalize_scenario_tokens(scenarios)
    if not tokens:
        return True
    text = str(value or "").strip().lower()
    if not text:
        return False
    for token in tokens:
        if text == token or token in text or text in token:
            return True
    return False


def row_matches_scenarios(payload: dict[str, Any], scenarios: list[str] | None) -> bool:
    tokens = normalize_scenario_tokens(scenarios)
    if not tokens:
        return True
    haystacks = [
        payload.get("category"),
        payload.get("subcategory"),
        payload.get("sub_category"),
        payload.get("dataset"),
        payload.get("benchmark_source"),
        payload.get("source"),
        payload.get("plugin"),
        payload.get("preset"),
    ]
    return any(value_matches_scenarios(item, tokens) for item in haystacks)


def filter_names_by_scenarios(names: list[str], scenarios: list[str] | None) -> list[str]:
    tokens = normalize_scenario_tokens(scenarios)
    if not tokens:
        return list(names)
    matched = [name for name in names if value_matches_scenarios(name, tokens)]
    return matched or list(names)
