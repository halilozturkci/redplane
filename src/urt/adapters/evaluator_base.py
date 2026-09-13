"""Evaluator adapter base interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..storage.artifact_store import ArtifactStore
from ..types import (
    EngineRunResult,
    EvalRunResult,
    EvaluatorSpec,
    TargetSpec,
    UnifiedFinding,
)


@dataclass(slots=True)
class EvalContext:
    run_id: str
    run_name: str
    target: TargetSpec
    artifact_store: ArtifactStore
    timeout_seconds: int
    seed: int | None
    engine_findings: list[UnifiedFinding]
    engine_results: list[EngineRunResult]
    evidence_level: str = "standard"
    enabled_scenarios: list[str] = field(default_factory=list)
    run_profile: str = "nightly"
    engine_findings_path: str | None = None


class EvaluatorAdapter(ABC):
    """Abstract evaluator adapter."""

    def __init__(self, spec: EvaluatorSpec):
        self.spec = spec

    @property
    @abstractmethod
    def name(self) -> str:
        """Stable evaluator name."""

    @abstractmethod
    def evaluate(self, context: EvalContext) -> EvalRunResult:
        """Execute evaluation for one target."""

    def _write_text_artifact(self, context: EvalContext, file_name: str, text: str) -> str:
        return context.artifact_store.write_text(context.run_id, file_name, text)

    def _write_json_artifact(self, context: EvalContext, file_name: str, payload: Any) -> str:
        return context.artifact_store.write_json(context.run_id, file_name, payload)
