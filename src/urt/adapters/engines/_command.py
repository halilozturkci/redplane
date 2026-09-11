"""Common helpers for command-based engine adapters."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..engine_base import EngineAdapter, EngineContext
from ...runtime import build_runtime_env, limit_evidence_text
from ...types import EngineRunResult, UnifiedFinding


@dataclass(slots=True)
class CommandRunResult:
    returncode: int
    stdout: str
    stderr: str


class CommandEngineAdapter(EngineAdapter):
    """Base class for CLI-wrapped engine integrations."""

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

        process = subprocess.run(  # noqa: S603
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds,
            check=False,
            env=env,
            cwd=str(cwd) if cwd is not None else None,
        )
        return CommandRunResult(
            returncode=process.returncode,
            stdout=process.stdout,
            stderr=process.stderr,
        )

    def _skipped_result(self, context: EngineContext, reason: str) -> EngineRunResult:
        finding = UnifiedFinding(
            finding_id=f"{context.run_id}:{context.target.target_id}:{self.name}:skipped",
            run_id=context.run_id,
            target_id=context.target.target_id,
            engine=self.name,
            category="coverage_gap",
            sub_category="engine_skipped",
            severity="low",
            confidence=0.99,
            attack_vector="n/a",
            attack_complexity="n/a",
            success=False,
            description=reason,
            repro_steps=["Install and configure engine", "Re-run URT profile"],
            metadata={"status": "skipped"},
        )
        return EngineRunResult(
            engine=self.name,
            target_id=context.target.target_id,
            findings=[finding],
            artifacts=[],
            metrics={"executed": False},
            status="skipped",
            message=reason,
        )

    def _result_from_command(
        self,
        context: EngineContext,
        command: list[str],
        *,
        artifact_name_prefix: str,
        parse_payload: dict[str, Any] | None = None,
        env_overrides: dict[str, str] | None = None,
        cwd: str | Path | None = None,
    ) -> EngineRunResult:
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

        status = "completed" if output.returncode == 0 else "failed"
        severity = "info" if output.returncode == 0 else "medium"

        details = {
            "command": command,
            "returncode": output.returncode,
            "stdout_artifact": stdout_path,
            "stderr_artifact": stderr_path,
        }
        if parse_payload is not None:
            details["parse_payload"] = parse_payload
        if env_overrides:
            details["env_overrides"] = dict(env_overrides)
        if cwd is not None:
            details["cwd"] = str(cwd)

        finding = UnifiedFinding(
            finding_id=f"{context.run_id}:{context.target.target_id}:{self.name}:execution",
            run_id=context.run_id,
            target_id=context.target.target_id,
            engine=self.name,
            category="execution",
            sub_category="engine_runtime",
            severity=severity,
            confidence=0.90,
            attack_vector="tool_runtime",
            attack_complexity="n/a",
            success=output.returncode == 0,
            description=(
                f"{self.name} command succeeded"
                if output.returncode == 0
                else f"{self.name} command failed with return code {output.returncode}"
            ),
            evidence_refs=[stdout_path, stderr_path],
            repro_steps=["Run the same command manually", "Inspect stderr artifact"],
            metadata=details,
        )

        return EngineRunResult(
            engine=self.name,
            target_id=context.target.target_id,
            findings=[finding],
            artifacts=[stdout_path, stderr_path],
            metrics={
                "executed": True,
                "return_code": output.returncode,
                "command": command,
                "cwd": str(cwd) if cwd is not None else None,
            },
            status=status,
            message=f"command return code={output.returncode}",
        )
