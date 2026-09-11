"""Giskard scan evaluator adapter."""

from __future__ import annotations

import shlex
from typing import Any

from ..evaluator_base import EvalContext
from ._command import CommandEvaluatorAdapter
from ...types import EvalRunResult, EvalScore, UnifiedFinding


class GiskardEvalEvaluator(CommandEvaluatorAdapter):
    """Wraps Giskard's scan functionality for quality and safety evaluation."""

    command_name = "giskard"

    @property
    def name(self) -> str:
        return "giskard_eval"

    def evaluate(self, context: EvalContext) -> EvalRunResult:
        command_raw = self.spec.params.get("command")
        if not command_raw:
            if not self._command_exists():
                return self._skipped_result(context, "giskard not found in PATH and no params.command set")
            command_raw = "giskard scan"

        if isinstance(command_raw, str):
            command_list = shlex.split(command_raw)
        else:
            command_list = [str(c) for c in command_raw]

        output_json = self.spec.params.get("output_json")
        env_overrides: dict[str, str] = {}
        for k, v in self.spec.params.get("env", {}).items():
            env_overrides[str(k)] = str(v)
        cwd = self.spec.params.get("working_dir")

        cmd_output, artifacts = self._result_from_command(
            context,
            command_list,
            artifact_name_prefix="giskard_eval",
            env_overrides=env_overrides or None,
            cwd=cwd,
        )

        scores: list[EvalScore] = []
        findings: list[UnifiedFinding] = []
        threshold = float(self.spec.params.get("threshold", 0.5))

        payload = self._parse_json_output(output_json)
        if payload:
            scores.extend(self._parse_giskard_output(payload, threshold))

        execution_finding = UnifiedFinding(
            finding_id=f"{context.run_id}:{context.target.target_id}:{self.name}:execution",
            run_id=context.run_id,
            target_id=context.target.target_id,
            engine=self.name,
            category="evaluation",
            sub_category="evaluator_runtime",
            severity="info" if cmd_output.returncode == 0 else "medium",
            confidence=0.90,
            attack_vector="n/a",
            attack_complexity="n/a",
            success=cmd_output.returncode == 0,
            description=f"giskard eval {'succeeded' if cmd_output.returncode == 0 else 'failed'}",
            evidence_refs=artifacts,
            metadata={"returncode": cmd_output.returncode},
        )
        findings.append(execution_finding)

        for score in scores:
            if not score.passed:
                findings.append(UnifiedFinding(
                    finding_id=f"{context.run_id}:{context.target.target_id}:{self.name}:{score.metric}",
                    run_id=context.run_id,
                    target_id=context.target.target_id,
                    engine=self.name,
                    category="evaluation",
                    sub_category=score.metric,
                    severity="medium",
                    confidence=score.score,
                    attack_vector="n/a",
                    attack_complexity="n/a",
                    success=False,
                    description=f"Giskard detector '{score.metric}' failed: score={score.score:.2f} < threshold={score.threshold:.2f}. {score.reason}",
                    metadata=score.metadata,
                ))

        return EvalRunResult(
            evaluator=self.name,
            target_id=context.target.target_id,
            scores=scores,
            findings=findings,
            artifacts=artifacts,
            metrics={"executed": True, "return_code": cmd_output.returncode, "score_count": len(scores)},
            status="completed" if cmd_output.returncode == 0 else "failed",
            message=f"return code={cmd_output.returncode}, scores={len(scores)}",
        )

    def _parse_giskard_output(self, payload: dict[str, Any], threshold: float) -> list[EvalScore]:
        scores: list[EvalScore] = []

        # Giskard scan report: {"issues": [...], "summary": {...}}
        issues = payload.get("issues", [])
        if isinstance(issues, list):
            for issue in issues:
                if not isinstance(issue, dict):
                    continue
                detector = str(issue.get("detector", issue.get("name", "unknown")))
                # Giskard issues have severity levels; map to a score (1.0 = no issue, lower = worse)
                level = str(issue.get("level", issue.get("severity", "minor"))).lower()
                level_scores = {"major": 0.1, "medium": 0.3, "minor": 0.6, "info": 0.8}
                score_val = level_scores.get(level, 0.5)
                passed = issue.get("passed", score_val >= threshold)
                description = str(issue.get("description", issue.get("message", "")))
                scores.append(self._make_eval_score(
                    detector,
                    score_val,
                    threshold=threshold,
                    reason=description,
                    metadata={"raw": issue},
                ))
                scores[-1].passed = bool(passed)

        # Giskard test suite results: {"results": [...]}
        results = payload.get("results", payload.get("test_results", []))
        if isinstance(results, list) and not scores:
            for result in results:
                if not isinstance(result, dict):
                    continue
                test_name = str(result.get("test_name", result.get("name", "unknown")))
                raw_score = result.get("metric", result.get("score", result.get("value", 0.0)))
                score_val = float(raw_score) if raw_score is not None else 0.0
                passed = result.get("passed", result.get("is_passed"))
                if passed is None:
                    passed = score_val >= threshold
                scores.append(self._make_eval_score(
                    test_name,
                    score_val,
                    threshold=float(result.get("threshold", threshold)),
                    reason=str(result.get("message", result.get("details", ""))),
                    metadata={"raw": result},
                ))
                scores[-1].passed = bool(passed)

        # Fallback: flat scores array
        if not scores:
            for key in ("scores", "evaluations", "detectors"):
                items = payload.get(key, [])
                if isinstance(items, list):
                    for item in items:
                        if not isinstance(item, dict):
                            continue
                        metric = str(item.get("metric", item.get("name", item.get("detector", "unknown"))))
                        score_val = float(item.get("score", item.get("value", 0.0)))
                        scores.append(self._make_eval_score(
                            metric,
                            score_val,
                            threshold=float(item.get("threshold", threshold)),
                            reason=str(item.get("reason", "")),
                        ))

        return scores
