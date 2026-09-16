"""Common helpers for command-based evaluator adapters."""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..evaluator_base import EvalContext, EvaluatorAdapter
from ...runtime import build_runtime_env, limit_evidence_text, run_tool_process
from ...types import EvalRunResult, EvalScore, UnifiedFinding


@dataclass(slots=True)
class CommandRunResult:
    returncode: int
    stdout: str
    stderr: str


class CommandEvaluatorAdapter(EvaluatorAdapter):
    """Base class for CLI-wrapped evaluator integrations."""

    command_name: str = ""

    def _command_exists(self, executable: str | None = None) -> bool:
        candidate = executable or self.command_name
        return shutil.which(candidate) is not None

    def _run_command(
        self,
        command: list[str],
        timeout_seconds: int,
        *,
        env_overrides: dict[str, str] | None = None,
        cwd: str | Path | None = None,
    ) -> CommandRunResult:
        env = os.environ.copy()
        if env_overrides:
            for key, value in env_overrides.items():
                env[str(key)] = str(value)

        process = run_tool_process(command, timeout_seconds=timeout_seconds, env=env, cwd=cwd)
        return CommandRunResult(
            returncode=process.returncode,
            stdout=process.stdout,
            stderr=process.stderr,
        )

    def _skipped_result(self, context: EvalContext, reason: str) -> EvalRunResult:
        finding = UnifiedFinding(
            finding_id=f"{context.run_id}:{context.target.target_id}:{self.name}:skipped",
            run_id=context.run_id,
            target_id=context.target.target_id,
            engine=self.name,
            category="coverage_gap",
            sub_category="evaluator_skipped",
            severity="low",
            confidence=0.99,
            attack_vector="n/a",
            attack_complexity="n/a",
            success=False,
            description=reason,
            repro_steps=["Install and configure evaluator", "Re-run URT profile"],
            metadata={"status": "skipped"},
        )
        return EvalRunResult(
            evaluator=self.name,
            target_id=context.target.target_id,
            findings=[finding],
            artifacts=[],
            metrics={"executed": False},
            status="skipped",
            message=reason,
        )

    def _result_from_command(
        self,
        context: EvalContext,
        command: list[str],
        *,
        artifact_name_prefix: str,
        env_overrides: dict[str, str] | None = None,
        cwd: str | Path | None = None,
    ) -> tuple[CommandRunResult, list[str]]:
        merged_env = {**build_runtime_env(context), **(env_overrides or {})}
        output = self._run_command(
            command,
            timeout_seconds=context.timeout_seconds,
            env_overrides=merged_env or None,
            cwd=cwd,
        )

        stdout_path = self._write_text_artifact(
            context,
            f"raw/{artifact_name_prefix}/{context.target.target_id}_stdout.log",
            limit_evidence_text(output.stdout, context.evidence_level),
        )
        stderr_path = self._write_text_artifact(
            context,
            f"raw/{artifact_name_prefix}/{context.target.target_id}_stderr.log",
            limit_evidence_text(output.stderr, context.evidence_level),
        )

        return output, [stdout_path, stderr_path]

    def _parse_json_output(self, output_path: str | None) -> dict[str, Any] | None:
        if not output_path:
            return None
        path = Path(output_path)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))  # type: ignore[no-any-return]
        except (json.JSONDecodeError, OSError):
            return None

    def _make_eval_score(
        self,
        metric: str,
        score: float,
        *,
        threshold: float = 0.5,
        reason: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> EvalScore:
        return EvalScore(
            metric=metric,
            score=max(0.0, min(1.0, score)),
            threshold=threshold,
            passed=score >= threshold,
            reason=reason,
            metadata=metadata or {},
        )
