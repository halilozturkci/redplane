"""Garak engine adapter."""

from __future__ import annotations

import json
import shlex
from pathlib import Path

from ..engine_base import EngineContext
from ...types import UnifiedFinding
from ._command import CommandEngineAdapter


class GarakEngineAdapter(CommandEngineAdapter):
    command_name = "garak"

    @property
    def name(self) -> str:
        return "garak"

    def run(self, context: EngineContext):
        command = self.spec.params.get("command")
        if not command:
            return self._skipped_result(context, "garak requires params.command")

        if isinstance(command, str):
            command_list = shlex.split(command)
        else:
            command_list = [str(part) for part in command]

        if not self._command_exists(command_list[0]):
            return self._skipped_result(
                context,
                f"garak command launcher not found in PATH: {command_list[0]}",
            )

        result = self._result_from_command(
            context,
            command_list,
            artifact_name_prefix="garak",
        )

        report_path = self.spec.params.get("report_jsonl")
        if report_path:
            report_file = Path(str(report_path))
            if report_file.exists():
                copied = self._copy_artifact(
                    context,
                    report_file,
                    f"raw/garak/{context.target.target_id}_report.jsonl",
                )
                result.artifacts.append(copied)
                result.findings.extend(self._parse_jsonl(run_id=context.run_id, target_id=context.target.target_id, path=report_file))
        return result

    def _parse_jsonl(self, *, run_id: str, target_id: str, path: Path) -> list[UnifiedFinding]:
        findings: list[UnifiedFinding] = []
        for idx, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines()):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue

            detector = str(payload.get("detector", "unknown"))
            score = float(payload.get("score", 0.0) or 0.0)
            passed = bool(payload.get("passed", score <= 0))
            severity = "high" if score >= 0.85 and not passed else "medium" if not passed else "info"
            findings.append(
                UnifiedFinding(
                    finding_id=f"{run_id}:{target_id}:garak:{idx}",
                    run_id=run_id,
                    target_id=target_id,
                    engine="garak",
                    category="robustness",
                    sub_category=detector,
                    severity=severity,
                    confidence=0.75,
                    attack_vector=str(payload.get("probe", "unknown")),
                    attack_complexity="unknown",
                    success=not passed,
                    description=f"Garak detector={detector} score={score}",
                    metadata={"raw": payload},
                )
            )
        return findings
