"""Giskard engine adapter."""

from __future__ import annotations

import json
import shlex
from pathlib import Path

from ..engine_base import EngineContext
from ...types import UnifiedFinding
from ._command import CommandEngineAdapter


class GiskardEngineAdapter(CommandEngineAdapter):
    command_name = "giskard"

    @property
    def name(self) -> str:
        return "giskard"

    def run(self, context: EngineContext):
        command = self.spec.params.get("command")
        if not command:
            return self._skipped_result(context, "giskard requires params.command")

        if isinstance(command, str):
            command_list = shlex.split(command)
        else:
            command_list = [str(part) for part in command]

        if not self._command_exists(command_list[0]):
            return self._skipped_result(
                context,
                f"giskard command launcher not found in PATH: {command_list[0]}",
            )

        result = self._result_from_command(
            context,
            command_list,
            artifact_name_prefix="giskard",
        )

        output_json = self.spec.params.get("output_json")
        if output_json:
            output_path = Path(str(output_json)).expanduser()
            if output_path.exists():
                copied = self._copy_artifact(
                    context,
                    output_path,
                    f"raw/giskard/{context.target.target_id}_scan.json",
                )
                result.artifacts.append(copied)
                result.findings.extend(self._parse_output(run_id=context.run_id, target_id=context.target.target_id, path=output_path))
        return result

    def _parse_output(self, *, run_id: str, target_id: str, path: Path) -> list[UnifiedFinding]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            return [
                UnifiedFinding(
                    finding_id=f"{run_id}:{target_id}:giskard:parse_error",
                    run_id=run_id,
                    target_id=target_id,
                    engine="giskard",
                    category="execution",
                    sub_category="parse_error",
                    severity="low",
                    confidence=0.9,
                    attack_vector="tool_output",
                    attack_complexity="n/a",
                    success=False,
                    description=f"Failed to parse Giskard output: {exc}",
                )
            ]

        if isinstance(payload, dict):
            issues = payload.get("issues") or payload.get("findings") or payload.get("tests") or []
        else:
            issues = payload if isinstance(payload, list) else []

        findings: list[UnifiedFinding] = []
        for idx, issue in enumerate(issues):
            if not isinstance(issue, dict):
                continue
            severity_raw = str(issue.get("severity", "medium")).lower()
            if severity_raw not in {"critical", "high", "medium", "low", "info"}:
                severity_raw = "medium"

            passed = bool(issue.get("passed", issue.get("status") in {"pass", "passed"}))
            findings.append(
                UnifiedFinding(
                    finding_id=f"{run_id}:{target_id}:giskard:{idx}",
                    run_id=run_id,
                    target_id=target_id,
                    engine="giskard",
                    category=str(issue.get("category", "security_test")),
                    sub_category=str(issue.get("test", issue.get("type", "giskard_scan"))),
                    severity="info" if passed else severity_raw,
                    confidence=float(issue.get("confidence", 0.8) or 0.8),
                    attack_vector=str(issue.get("attack_vector", issue.get("probe", "scan"))),
                    attack_complexity=str(issue.get("complexity", "unknown")),
                    success=not passed,
                    description=str(issue.get("description", "Giskard scan issue")),
                    metadata={"raw": issue},
                )
            )
        return findings
