"""Core data models for Redplane."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

from .constants import (
    RUN_PROFILE_DEFAULTS,
    SUPPORTED_EVALUATORS,
    SUPPORTED_EVIDENCE_LEVELS,
    SUPPORTED_TARGETS,
    SUPPORTED_ENGINES,
    SUPPORTED_PROFILES,
)


class ValidationError(ValueError):
    """Raised when run configuration is invalid."""


@dataclass(slots=True)
class BudgetSpec:
    max_duration_seconds: int = 3600
    max_cost_usd: float | None = None

    @classmethod
    def from_dict(cls, payload: dict[str, Any] | None) -> "BudgetSpec":
        if not payload:
            return cls()
        max_duration_seconds = int(payload.get("max_duration_seconds", 3600))
        max_cost_usd_raw = payload.get("max_cost_usd")
        max_cost_usd = None if max_cost_usd_raw is None else float(max_cost_usd_raw)
        if max_duration_seconds <= 0:
            raise ValidationError("budget.max_duration_seconds must be > 0")
        if max_cost_usd is not None and max_cost_usd <= 0:
            raise ValidationError("budget.max_cost_usd must be > 0 when set")
        return cls(max_duration_seconds=max_duration_seconds, max_cost_usd=max_cost_usd)


@dataclass(slots=True)
class TimeoutSpec:
    connect_seconds: int = 10
    request_seconds: int = 60
    engine_seconds: int = 1800

    @classmethod
    def from_dict(cls, payload: dict[str, Any] | None) -> "TimeoutSpec":
        if not payload:
            return cls()
        connect_seconds = int(payload.get("connect_seconds", 10))
        request_seconds = int(payload.get("request_seconds", 60))
        engine_seconds = int(payload.get("engine_seconds", 1800))
        if min(connect_seconds, request_seconds, engine_seconds) <= 0:
            raise ValidationError("timeouts fields must be > 0")
        return cls(
            connect_seconds=connect_seconds,
            request_seconds=request_seconds,
            engine_seconds=engine_seconds,
        )


@dataclass(slots=True)
class TargetSpec:
    target_id: str
    target_type: str
    endpoint: str | None = None
    auth: dict[str, Any] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=dict)
    rate_limits: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "TargetSpec":
        target_id = str(payload.get("id", "")).strip()
        target_type = str(payload.get("type", "")).strip().lower()
        if not target_id:
            raise ValidationError("target.id is required")
        if target_type not in SUPPORTED_TARGETS:
            raise ValidationError(f"Unsupported target type '{target_type}'. Supported: {sorted(SUPPORTED_TARGETS)}")

        endpoint = payload.get("endpoint")
        if endpoint is not None:
            endpoint = str(endpoint)

        return cls(
            target_id=target_id,
            target_type=target_type,
            endpoint=endpoint,
            auth=dict(payload.get("auth", {})),
            config=dict(payload.get("config", {})),
            rate_limits=dict(payload.get("rate_limits", {})),
        )


@dataclass(slots=True)
class EngineSpec:
    name: str
    version: str | None = None
    enabled_scenarios: list[str] = field(default_factory=list)
    params: dict[str, Any] = field(default_factory=dict)
    fail_open: bool = True

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "EngineSpec":
        name = str(payload.get("name", "")).strip().lower()
        if name not in SUPPORTED_ENGINES:
            raise ValidationError(f"Unsupported engine '{name}'. Supported: {sorted(SUPPORTED_ENGINES)}")

        return cls(
            name=name,
            version=payload.get("version"),
            enabled_scenarios=[str(s) for s in payload.get("enabled_scenarios", [])],
            params=dict(payload.get("params", {})),
            fail_open=bool(payload.get("fail_open", True)),
        )


@dataclass(slots=True)
class EvaluatorSpec:
    name: str
    version: str | None = None
    metrics: list[str] = field(default_factory=list)
    params: dict[str, Any] = field(default_factory=dict)
    fail_open: bool = True

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "EvaluatorSpec":
        name = str(payload.get("name", "")).strip().lower()
        if name not in SUPPORTED_EVALUATORS:
            raise ValidationError(f"Unsupported evaluator '{name}'. Supported: {sorted(SUPPORTED_EVALUATORS)}")

        return cls(
            name=name,
            version=payload.get("version"),
            metrics=[str(m) for m in payload.get("metrics", [])],
            params=dict(payload.get("params", {})),
            fail_open=bool(payload.get("fail_open", True)),
        )


@dataclass(slots=True)
class RunSpec:
    name: str
    run_profile: str
    targets: list[TargetSpec]
    engines: list[EngineSpec]
    evaluators: list[EvaluatorSpec] = field(default_factory=list)
    policy_profiles: list[str] = field(default_factory=lambda: ["owasp_llm", "owasp_agentic", "mitre_atlas"])
    budget: BudgetSpec = field(default_factory=BudgetSpec)
    timeouts: TimeoutSpec = field(default_factory=TimeoutSpec)
    evidence_level: str = "standard"
    seed: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "RunSpec":
        name = str(payload.get("name", "")).strip()
        if not name:
            raise ValidationError("name is required")

        run_profile = str(payload.get("run_profile", "nightly")).strip().lower()
        if run_profile not in SUPPORTED_PROFILES:
            raise ValidationError(
                f"Unsupported run_profile '{run_profile}'. Supported: {sorted(SUPPORTED_PROFILES)}"
            )

        targets_payload = payload.get("targets", [])
        engines_payload = payload.get("engines", [])

        if not targets_payload:
            raise ValidationError("At least one target is required")
        if not engines_payload:
            raise ValidationError("At least one engine is required")

        targets = [TargetSpec.from_dict(item) for item in targets_payload]
        engines = [EngineSpec.from_dict(item) for item in engines_payload]
        evaluators = [EvaluatorSpec.from_dict(item) for item in payload.get("evaluators", [])]

        seed_raw = payload.get("seed")
        seed = None if seed_raw is None else int(seed_raw)

        profile_defaults = RUN_PROFILE_DEFAULTS.get(run_profile, RUN_PROFILE_DEFAULTS["nightly"])
        budget_payload = payload.get("budget")
        if budget_payload is None:
            budget = BudgetSpec.from_dict(profile_defaults.get("budget"))
        else:
            budget = BudgetSpec.from_dict({**profile_defaults.get("budget", {}), **dict(budget_payload)})

        timeouts_payload = payload.get("timeouts")
        if timeouts_payload is None:
            timeouts = TimeoutSpec.from_dict(profile_defaults.get("timeouts"))
        else:
            timeouts = TimeoutSpec.from_dict({**profile_defaults.get("timeouts", {}), **dict(timeouts_payload)})

        evidence_level = str(payload.get("evidence_level", "standard")).strip().lower() or "standard"
        if evidence_level not in SUPPORTED_EVIDENCE_LEVELS:
            raise ValidationError(
                f"Unsupported evidence_level '{evidence_level}'. Supported: {sorted(SUPPORTED_EVIDENCE_LEVELS)}"
            )

        return cls(
            name=name,
            run_profile=run_profile,
            targets=targets,
            engines=engines,
            evaluators=evaluators,
            policy_profiles=[str(x) for x in payload.get("policy_profiles", ["owasp_llm", "owasp_agentic", "mitre_atlas"])],
            budget=budget,
            timeouts=timeouts,
            evidence_level=evidence_level,
            seed=seed,
            metadata=dict(payload.get("metadata", {})),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class UnifiedFinding:
    finding_id: str
    run_id: str
    target_id: str
    engine: str
    category: str
    sub_category: str | None
    severity: str
    confidence: float
    attack_vector: str
    attack_complexity: str
    success: bool
    description: str
    evidence_refs: list[str] = field(default_factory=list)
    repro_steps: list[str] = field(default_factory=list)
    mappings: dict[str, list[str]] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class UnifiedScorecard:
    run_id: str
    created_at: str
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    success_count: int
    total_attacks: int
    asr_overall: float
    asr_by_category: dict[str, float]
    by_engine: dict[str, int]
    eval_scores: dict[str, float] = field(default_factory=dict)
    eval_pass_rate: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @staticmethod
    def now_timestamp() -> str:
        return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class RunRecord:
    run_id: str
    name: str
    profile: str
    status: str
    created_at: str
    updated_at: str
    scorecard_path: str | None = None
    findings_path: str | None = None


@dataclass(slots=True)
class WaiverRecord:
    waiver_id: str
    target_id: str
    control_id: str
    reason: str
    owner: str
    expires_at: str


@dataclass(slots=True)
class EngineRunResult:
    engine: str
    target_id: str
    findings: list[UnifiedFinding] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    status: str = "completed"
    message: str = ""


@dataclass(slots=True)
class EvalScore:
    metric: str
    score: float
    threshold: float = 0.5
    passed: bool = True
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class EvalRunResult:
    evaluator: str
    target_id: str
    scores: list[EvalScore] = field(default_factory=list)
    findings: list[UnifiedFinding] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    status: str = "completed"
    message: str = ""


@dataclass(slots=True)
class TargetResponse:
    content: str
    raw: dict[str, Any]
