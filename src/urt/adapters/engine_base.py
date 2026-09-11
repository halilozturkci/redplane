"""Engine adapter base interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..storage.artifact_store import ArtifactStore
from ..types import EngineRunResult, EngineSpec, TargetSpec


@dataclass(slots=True)
class EngineContext:
    run_id: str
    run_name: str
    run_profile: str
    target: TargetSpec
    artifact_store: ArtifactStore
    timeout_seconds: int
    seed: int | None
    evidence_level: str = "standard"
    enabled_scenarios: list[str] = field(default_factory=list)
    connect_seconds: int = 10
    request_seconds: int = 60


class EngineAdapter(ABC):
    """Abstract engine adapter."""

    def __init__(self, spec: EngineSpec):
        self.spec = spec

    @property
    @abstractmethod
    def name(self) -> str:
        """Stable engine name."""

    @abstractmethod
    def run(self, context: EngineContext) -> EngineRunResult:
        """Execute engine run for one target."""

    def _write_text_artifact(self, context: EngineContext, file_name: str, text: str) -> str:
        return context.artifact_store.write_text(context.run_id, file_name, text)

    def _write_json_artifact(self, context: EngineContext, file_name: str, payload: Any) -> str:
        return context.artifact_store.write_json(context.run_id, file_name, payload)

    def _copy_artifact(self, context: EngineContext, source: str | Path, dest_name: str | None = None) -> str:
        return context.artifact_store.copy_file(context.run_id, source, dest_name)
