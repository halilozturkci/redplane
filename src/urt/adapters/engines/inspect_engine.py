"""Inspect AI engine adapter."""

from __future__ import annotations

import json
import shlex
from pathlib import Path

from ..engine_base import EngineContext
from ...types import UnifiedFinding
from ._command import CommandEngineAdapter


class InspectEngineAdapter(CommandEngineAdapter):
    command_name = "inspect"

    @property
    def name(self) -> str:
        return "inspect"

    def run(self, context: EngineContext):
        command = self.spec.params.get("command")
        if not command:
            return self._skipped_result(context, "inspect requires params.command")

        if isinstance(command, str):
            command_list = shlex.split(command)
        else:
            command_list = [str(part) for part in command]

        if not self._command_exists(command_list[0]):
            return self._skipped_result(
                context,
                f"inspect command launcher not found in PATH: {command_list[0]}",
            )

        result = self._result_from_command(
            context,
            command_list,
            artifact_name_prefix="inspect",
        )

        output_json = self.spec.params.get("output_json")
        if output_json:
            output_path = Path(str(output_json)).expanduser()
            if output_path.exists():
                copied = self._copy_artifact(
                    context,
                    output_path,
                    f"raw/inspect/{context.target.target_id}_results.json",
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
                    finding_id=f"{run_id}:{target_id}:inspect:parse_error",
                    run_id=run_id,
                    target_id=target_id,
                    engine="inspect",
                    category="execution",
                    sub_category="parse_error",
                    severity="low",
                    confidence=0.9,
                    attack_vector="tool_output",
                    attack_complexity="n/a",
                    success=False,
                    description=f"Failed to parse Inspect output: {exc}",
                )
            ]

        if isinstance(payload, dict):
            tests = payload.get("tests") or payload.get("results") or []
        else:
            tests = payload if isinstance(payload, list) else []

        findings: list[UnifiedFinding] = []
        for idx, test in enumerate(tests):
            if not isinstance(test, dict):
                continue
            status = str(test.get("status", test.get("outcome", "unknown"))).lower()
            passed = status in {"pass", "passed", "ok", "success"}
            score = float(test.get("score", 1.0 if passed else 0.0) or 0.0)
            category = str(test.get("category", test.get("name", "inspect_test")))
            attack_vector = str(test.get("attack", test.get("technique", "scenario")))

            findings.append(
                UnifiedFinding(
                    finding_id=f"{run_id}:{target_id}:inspect:{idx}",
                    run_id=run_id,
                    target_id=target_id,
                    engine="inspect",
                    category=category,
                    sub_category="inspect_test",
                    severity="info" if passed else "medium",
                    confidence=min(max(score, 0.0), 1.0),
                    attack_vector=attack_vector,
                    attack_complexity=str(test.get("complexity", "unknown")),
                    success=not passed,
                    description=str(test.get("description", f"Inspect test {category} {status}")),
                    metadata={"raw": test},
                )
            )
        return findings
