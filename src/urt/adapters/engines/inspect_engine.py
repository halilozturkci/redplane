"""Inspect AI engine adapter."""

from __future__ import annotations

import json
import shlex
from pathlib import Path

from ..engine_base import EngineContext
from ...types import UnifiedFinding
from ._command import CommandEngineAdapter

_DIAGNOSTIC_METRICS = frozenset({"stderr", "std", "std_err", "se", "bootstrap_std"})
_PASS_STATUS = frozenset({"pass", "passed", "ok", "success"})
_PASS_TOKENS = frozenset({"C", "P", "PASS", "PASSED", "OK", "CORRECT", "TRUE"})
_FAIL_TOKENS = frozenset({"I", "F", "FAIL", "FAILED", "INCORRECT", "FALSE"})


def _as_number(value: object) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _inspect_score_polarity(score_obj: object) -> tuple[bool, float]:
    value: object = score_obj
    if isinstance(score_obj, dict):
        value = score_obj.get("value", score_obj.get("score"))
    if isinstance(value, bool):
        return value, 1.0 if value else 0.0
    numeric = _as_number(value)
    if numeric is not None:
        return numeric >= 0.5, numeric
    if isinstance(value, str):
        token = value.strip().upper()
        if token in _PASS_TOKENS:
            return True, 1.0
        if token in _FAIL_TOKENS:
            return False, 0.0
    return False, 0.0


def _inspect_attack_vector(sample: dict[str, object]) -> str:
    raw: object = sample.get("input") or sample.get("target") or sample.get("attack") or "scenario"
    if isinstance(raw, list):
        parts: list[str] = []
        for item in raw:
            if isinstance(item, dict):
                content = item.get("content") or item.get("text")
                if content:
                    parts.append(str(content))
            else:
                parts.append(str(item))
        raw = " | ".join(parts) if parts else "scenario"
    text = " ".join(str(raw).split())
    return text[:200] if text else "scenario"


def _inspect_cases_from_sample(sample: dict[str, object], index: int) -> list[dict[str, object]]:
    sample_id = str(sample.get("id", sample.get("name", f"sample-{index}")))
    attack = _inspect_attack_vector(sample)
    scores = sample.get("scores")
    if isinstance(scores, dict) and scores:
        cases: list[dict[str, object]] = []
        for scorer_name, score_obj in scores.items():
            passed, value = _inspect_score_polarity(score_obj)
            explanation = ""
            if isinstance(score_obj, dict):
                explanation = str(score_obj.get("explanation") or score_obj.get("answer") or "")
            cases.append(
                {
                    "name": f"{sample_id}:{scorer_name}",
                    "category": str(scorer_name),
                    "status": "passed" if passed else "failed",
                    "score": value,
                    "description": explanation or attack,
                    "attack": attack,
                    "complexity": sample.get("complexity", "unknown"),
                }
            )
        return cases
    case = dict(sample)
    case.setdefault("name", sample_id)
    case.setdefault("attack", attack)
    return [case]


def _inspect_cases_from_results_object(results: dict[str, object]) -> list[dict[str, object]]:
    scores = results.get("scores")
    if not isinstance(scores, list):
        return []
    cases: list[dict[str, object]] = []
    for block in scores:
        if not isinstance(block, dict):
            continue
        primary = str(block.get("name") or block.get("scorer") or "accuracy")
        metrics = block.get("metrics")
        selected: object | None = None
        selected_name = primary
        if isinstance(metrics, dict):
            if primary in metrics:
                selected = metrics[primary]
            else:
                for key, value in metrics.items():
                    if str(key).lower() in _DIAGNOSTIC_METRICS:
                        continue
                    selected = value
                    selected_name = str(key)
                    break
        if selected is None:
            if "value" in block or "score" in block:
                selected = block
            else:
                continue
        passed, value = _inspect_score_polarity(selected)
        cases.append(
            {
                "name": selected_name,
                "category": primary,
                "status": "passed" if passed else "failed",
                "score": value,
                "description": f"Inspect metric {primary}/{selected_name}={value}",
                "attack": "scenario",
            }
        )
    return cases


def _iter_inspect_test_dicts(payload: object) -> list[dict[str, object]]:
    """Unwrap Inspect EvalLog / legacy URT shapes into a list of test dicts.

    Native EvalLog ``results`` is an object. Iterating it yields key strings,
    which the previous parser skipped, producing silent zero findings.
    """
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []

    tests = payload.get("tests")
    if isinstance(tests, list):
        return [item for item in tests if isinstance(item, dict)]

    samples = payload.get("samples")
    if isinstance(samples, list):
        cases: list[dict[str, object]] = []
        for idx, sample in enumerate(samples):
            if isinstance(sample, dict):
                cases.extend(_inspect_cases_from_sample(sample, idx))
        if cases:
            return cases

    results = payload.get("results")
    if isinstance(results, list):
        return [item for item in results if isinstance(item, dict)]
    if isinstance(results, dict):
        return _inspect_cases_from_results_object(results)
    return []


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

        tests = _iter_inspect_test_dicts(payload)
        findings: list[UnifiedFinding] = []
        for idx, test in enumerate(tests):
            status = str(test.get("status", test.get("outcome", "unknown"))).lower()
            passed = status in _PASS_STATUS
            raw_score = test.get("score", 1.0 if passed else 0.0)
            try:
                score = float(raw_score or 0.0)
            except (TypeError, ValueError):
                score = 0.0
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
