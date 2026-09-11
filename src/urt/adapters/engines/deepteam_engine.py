"""DeepTeam engine adapter."""

from __future__ import annotations

import json
import shlex
from pathlib import Path

from ..engine_base import EngineContext
from ...types import UnifiedFinding
from ._command import CommandEngineAdapter


class DeepTeamEngineAdapter(CommandEngineAdapter):
    command_name = "deepteam"

    @property
    def name(self) -> str:
        return "deepteam"

    def run(self, context: EngineContext):
        command = self.spec.params.get("command")
        if not command:
            return self._skipped_result(context, "deepteam requires params.command")

        if isinstance(command, str):
            command_list = shlex.split(command)
        else:
            command_list = [str(part) for part in command]

        if not self._command_exists(command_list[0]):
            return self._skipped_result(
                context,
                f"deepteam command launcher not found in PATH: {command_list[0]}",
            )

        result = self._result_from_command(
            context,
            command_list,
            artifact_name_prefix="deepteam",
        )

        output_json = self.spec.params.get("output_json")
        require_test_cases = bool(self.spec.params.get("require_test_cases", True))
        if output_json:
            output_path = Path(str(output_json)).expanduser()
            if output_path.exists():
                copied = self._copy_artifact(
                    context,
                    output_path,
                    f"raw/deepteam/{context.target.target_id}_results.json",
                )
                result.artifacts.append(copied)
                parsed_findings = self._parse_output(
                    run_id=context.run_id,
                    target_id=context.target.target_id,
                    path=output_path,
                )
                result.findings.extend(parsed_findings)

                if require_test_cases and any(
                    finding.sub_category in {"no_test_cases_generated", "execution_errors"}
                    for finding in parsed_findings
                ):
                    result.status = "failed"
                    result.message = "DeepTeam completed without usable test cases"
                    result.metrics["quality_gate"] = "failed_no_test_cases"
                    result.metrics["require_test_cases"] = True
        return result

    def _parse_output(self, *, run_id: str, target_id: str, path: Path) -> list[UnifiedFinding]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            return [
                UnifiedFinding(
                    finding_id=f"{run_id}:{target_id}:deepteam:parse_error",
                    run_id=run_id,
                    target_id=target_id,
                    engine="deepteam",
                    category="execution",
                    sub_category="parse_error",
                    severity="low",
                    confidence=0.9,
                    attack_vector="tool_output",
                    attack_complexity="n/a",
                    success=False,
                    description=f"Failed to parse DeepTeam output: {exc}",
                )
            ]

        records = self._collect_records(payload, output_path=path)
        if not records:
            overview: dict[str, object] = {}
            errored_count = 0
            if isinstance(payload, dict):
                payload_overview = payload.get("overview")
                if isinstance(payload_overview, dict):
                    overview = payload_overview
                    errored_count = int(self._to_float(payload_overview.get("errored"), 0.0))

            sub_category = "execution_errors" if errored_count > 0 else "no_test_cases_generated"
            severity = "medium" if errored_count > 0 else "low"
            description = (
                "DeepTeam reported execution errors and did not generate test cases/results"
                if errored_count > 0
                else "DeepTeam completed but did not generate test cases/results"
            )
            hints = [
                "Set deepteam system_config.ignore_errors=false to surface generation/evaluation failures.",
                "Use a dedicated simulator model and evaluation model instead of routing both through a strict target proxy.",
                "Ensure custom model wrappers return valid schema objects for simulator outputs.",
            ]

            return [
                UnifiedFinding(
                    finding_id=f"{run_id}:{target_id}:deepteam:no_results",
                    run_id=run_id,
                    target_id=target_id,
                    engine="deepteam",
                    category="coverage_gap",
                    sub_category=sub_category,
                    severity=severity,
                    confidence=0.95,
                    attack_vector="deepteam_assessment",
                    attack_complexity="n/a",
                    success=False,
                    description=description,
                    metadata={
                        "output_path": str(path),
                        "overview": overview,
                        "errored_count": errored_count,
                        "troubleshooting_hints": hints,
                    },
                )
            ]

        findings: list[UnifiedFinding] = []
        for idx, record in enumerate(records):
            if not isinstance(record, dict):
                continue

            vulnerability = str(
                record.get("vulnerability", record.get("vulnerability_type", record.get("category", "unknown")))
            )
            attack = str(record.get("attack", record.get("attack_method", record.get("method", "unknown"))))
            score = self._to_float(record.get("score", record.get("risk_score", record.get("vulnerability_score"))), 0.0)

            is_issue = self._coerce_bool(record.get("is_vulnerable"))
            if is_issue is None:
                is_issue = self._coerce_bool(record.get("failed"))
            if is_issue is None:
                status = str(record.get("status", record.get("outcome", ""))).strip().lower()
                if status in {"pass", "passed", "ok", "success"}:
                    is_issue = False
                elif status in {"fail", "failed", "error", "vulnerable"}:
                    is_issue = True
            if is_issue is None:
                error_text = record.get("error")
                if error_text:
                    is_issue = False
                else:
                    is_issue = score >= 0.5

            # Gate keys on severity, not success. A high score that is not an
            # issue must stay info; do not force HIGH from the raw score.
            if not is_issue:
                severity = "info"
            elif score >= 0.85:
                severity = "high"
            else:
                severity = "medium"

            findings.append(
                UnifiedFinding(
                    finding_id=f"{run_id}:{target_id}:deepteam:{idx}",
                    run_id=run_id,
                    target_id=target_id,
                    engine="deepteam",
                    category=vulnerability,
                    sub_category="deepteam_probe",
                    severity=severity,
                    confidence=min(max(score, 0.0), 1.0),
                    attack_vector=attack,
                    attack_complexity=str(record.get("complexity", "unknown")),
                    success=is_issue,
                    description=str(record.get("description", f"DeepTeam probe result for {vulnerability}")),
                    metadata={"raw": record},
                )
            )

        return findings

    def _collect_records(self, payload: object, *, output_path: Path) -> list[dict]:
        records: list[dict] = []
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]

        if isinstance(payload, dict):
            for key in ("results", "findings"):
                value = payload.get(key)
                if isinstance(value, list):
                    records.extend(item for item in value if isinstance(item, dict))

            test_cases = payload.get("test_cases")
            if isinstance(test_cases, list):
                records.extend(self._normalize_test_cases(test_cases))

            if not records:
                source = payload.get("source")
                if source:
                    source_path = Path(str(source)).expanduser()
                    if not source_path.is_absolute():
                        source_path = (output_path.parent / source_path).resolve()
                    if source_path.exists():
                        try:
                            source_payload = json.loads(source_path.read_text(encoding="utf-8"))
                        except Exception:  # noqa: BLE001
                            source_payload = None
                        if isinstance(source_payload, dict):
                            source_cases = source_payload.get("test_cases")
                            if isinstance(source_cases, list):
                                records.extend(self._normalize_test_cases(source_cases))

        return records

    def _normalize_test_cases(self, cases: list[object]) -> list[dict]:
        records: list[dict] = []
        for case in cases:
            if not isinstance(case, dict):
                continue

            score = self._to_float(case.get("score", case.get("risk_score", case.get("vulnerability_score"))), 0.0)
            status = str(case.get("status", case.get("outcome", ""))).strip().lower()
            is_vulnerable = self._coerce_bool(case.get("is_vulnerable"))
            if is_vulnerable is None:
                is_vulnerable = self._coerce_bool(case.get("failed"))
            if is_vulnerable is None and status:
                if status in {"pass", "passed", "ok", "success"}:
                    is_vulnerable = False
                elif status in {"fail", "failed", "error", "vulnerable"}:
                    is_vulnerable = True
            if is_vulnerable is None:
                is_vulnerable = score >= 0.5

            description = case.get("description") or case.get("reason")
            if not description and case.get("error"):
                description = f"DeepTeam error: {case.get('error')}"

            records.append(
                {
                    "vulnerability": case.get("vulnerability", case.get("vulnerability_type", "unknown")),
                    "attack": case.get("attack", case.get("attack_method", case.get("method", "unknown"))),
                    "score": score,
                    "is_vulnerable": bool(is_vulnerable),
                    "description": description or "DeepTeam test case result",
                    "complexity": case.get("complexity", "unknown"),
                    "raw_case": case,
                }
            )

        return records

    @staticmethod
    def _to_float(value: object, default: float) -> float:
        try:
            if value is None:
                return default
            return float(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _coerce_bool(value: object) -> bool | None:
        if isinstance(value, bool):
            return value
        if value is None:
            return None
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"true", "yes", "1", "pass", "passed", "ok", "success", "vulnerable"}:
                return True
            if normalized in {"false", "no", "0", "fail", "failed", "error"}:
                return False
            return None
        if isinstance(value, (int, float)):
            return bool(value)
        return None
