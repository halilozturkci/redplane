"""Native PyRIT 1.x engine adapter (subprocess wrap of red_team_scan.py)."""

from __future__ import annotations

import json
import os
import shlex
from pathlib import Path
from typing import Any

from ..engine_base import EngineContext
from ...runtime import build_runtime_env, limit_evidence_text, run_tool_process
from ...types import EngineRunResult, UnifiedFinding
from ._command import CommandEngineAdapter

PROJECT_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_SCRIPT_PATH = PROJECT_ROOT / "src/urt/integrations/mcs_pyrit/red_team_scan.py"
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "src/urt/integrations/mcs_pyrit/config/mcs_agent_callback.json"


class PyRITEngineAdapter(CommandEngineAdapter):
    command_name = "python"

    @property
    def name(self) -> str:
        return "pyrit"

    def run(self, context: EngineContext) -> EngineRunResult:
        working_dir = Path(str(self.spec.params.get("working_dir", PROJECT_ROOT))).expanduser()
        if not working_dir.is_absolute():
            working_dir = working_dir.resolve()
        if not working_dir.exists():
            return self._skipped_result(context, f"PyRIT working_dir not found: {working_dir}")

        command = self.spec.params.get("command")
        if command:
            if isinstance(command, str):
                command_parts = shlex.split(command)
            else:
                command_parts = [str(part) for part in command]
        else:
            script_path = Path(
                str(
                    self.spec.params.get(
                        "script_path",
                        str(DEFAULT_SCRIPT_PATH),
                    )
                )
            ).expanduser()
            if not script_path.is_absolute():
                script_path = script_path.resolve()
            if not script_path.exists():
                return self._skipped_result(context, f"PyRIT script not found: {script_path}")

            config_path = self.spec.params.get("config_path", str(DEFAULT_CONFIG_PATH))
            config_path_obj = Path(str(config_path)).expanduser()
            if not config_path_obj.is_absolute():
                config_path_obj = config_path_obj.resolve()
            if not config_path_obj.exists():
                return self._skipped_result(context, f"PyRIT config not found: {config_path_obj}")

            command_parts = [
                "python",
                str(script_path),
                "--config",
                str(config_path_obj),
            ]

        before_scan_dirs = {p.name for p in working_dir.glob(".scan_*") if p.is_dir()}

        env = os.environ.copy()
        env.update(build_runtime_env(context))
        process = run_tool_process(command_parts, timeout_seconds=context.timeout_seconds, env=env, cwd=working_dir)

        stdout_path = self._write_text_artifact(
            context,
            f"raw/pyrit/{context.target.target_id}_stdout.log",
            limit_evidence_text(process.stdout, context.evidence_level),
        )
        stderr_path = self._write_text_artifact(
            context,
            f"raw/pyrit/{context.target.target_id}_stderr.log",
            limit_evidence_text(process.stderr, context.evidence_level),
        )

        after_scan_dirs = [p for p in working_dir.glob(".scan_*") if p.is_dir() and p.name not in before_scan_dirs]
        latest_scan_dir = max(after_scan_dirs, key=lambda p: p.stat().st_mtime, default=None)

        findings: list[UnifiedFinding] = []
        metrics: dict[str, Any] = {
            "executed": process.returncode == 0,
            "return_code": process.returncode,
        }
        artifacts = [stdout_path, stderr_path]

        if latest_scan_dir is not None:
            final_results = latest_scan_dir / "final_results.json"
            if final_results.exists():
                copied_final_results = self._copy_artifact(
                    context,
                    final_results,
                    f"raw/pyrit/{context.target.target_id}_final_results.json",
                )
                artifacts.append(copied_final_results)
                parsed_findings, parsed_metrics = self._parse_final_results(
                    run_id=context.run_id,
                    target_id=context.target.target_id,
                    final_results_path=final_results,
                )
                findings.extend(parsed_findings)
                metrics.update(parsed_metrics)

            scorecard_txt = latest_scan_dir / "scorecard.txt"
            if scorecard_txt.exists() and context.evidence_level != "minimal":
                artifacts.append(
                    self._copy_artifact(
                        context,
                        scorecard_txt,
                        f"raw/pyrit/{context.target.target_id}_scorecard.txt",
                    )
                )

        execution_finding = UnifiedFinding(
            finding_id=f"{context.run_id}:{context.target.target_id}:pyrit:execution",
            run_id=context.run_id,
            target_id=context.target.target_id,
            engine=self.name,
            category="execution",
            sub_category="engine_runtime",
            severity="info" if process.returncode == 0 else "high",
            confidence=0.95,
            attack_vector="tool_runtime",
            attack_complexity="n/a",
            success=process.returncode == 0,
            description=(
                "PyRIT run completed"
                if process.returncode == 0
                else f"PyRIT run failed with return code {process.returncode}"
            ),
            evidence_refs=[stdout_path, stderr_path],
            repro_steps=["Inspect pyrit stderr", "Re-run the same command manually"],
            metadata={"command": command_parts, "working_dir": str(working_dir)},
        )
        findings.append(execution_finding)

        status = "completed" if process.returncode == 0 else "failed"
        message = (
            f"PyRIT completed for target {context.target.target_id}"
            if process.returncode == 0
            else f"PyRIT failed for target {context.target.target_id}"
        )

        return EngineRunResult(
            engine=self.name,
            target_id=context.target.target_id,
            findings=findings,
            artifacts=artifacts,
            metrics=metrics,
            status=status,
            message=message,
        )

    def _parse_final_results(
        self,
        *,
        run_id: str,
        target_id: str,
        final_results_path: Path,
    ) -> tuple[list[UnifiedFinding], dict[str, Any]]:
        payload = json.loads(final_results_path.read_text(encoding="utf-8"))
        attack_details = payload.get("attack_details", [])
        findings: list[UnifiedFinding] = []

        for index, item in enumerate(attack_details):
            category = str(item.get("risk_category", "unknown"))
            success = bool(item.get("attack_success", False))
            attack_technique = str(item.get("attack_technique", "unknown"))
            attack_complexity = str(item.get("attack_complexity", "unknown"))
            severity = "high" if success else "info"
            conversation = item.get("conversation", [])

            findings.append(
                UnifiedFinding(
                    finding_id=f"{run_id}:{target_id}:pyrit:attack:{index}",
                    run_id=run_id,
                    target_id=target_id,
                    engine="pyrit",
                    category=category,
                    sub_category="prompt_attack",
                    severity=severity,
                    confidence=0.90,
                    attack_vector=attack_technique,
                    attack_complexity=attack_complexity,
                    success=success,
                    description=f"PyRIT {attack_technique} attack {'succeeded' if success else 'blocked'} for {category}",
                    repro_steps=[
                        "Replay the prompt from conversation_preview on the same target",
                        "Verify whether safety controls return same behavior",
                    ],
                    metadata={
                        "attack_success_threshold": item.get("attack_success_threshold"),
                        "conversation_preview": conversation[:2],
                        "full_conversation_length": len(conversation),
                    },
                )
            )

        overall_asr = (
            payload.get("scorecard", {})
            .get("risk_category_summary", [{}])[0]
            .get("overall_asr")
        )

        metrics = {
            "overall_asr": float(overall_asr) if overall_asr is not None else None,
            "total_attacks": len(attack_details),
            "successful_attacks": sum(1 for x in attack_details if x.get("attack_success")),
        }
        return findings, metrics
