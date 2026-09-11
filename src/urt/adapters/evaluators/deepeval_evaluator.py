"""DeepEval evaluator adapter."""

from __future__ import annotations

import shlex
from typing import Any

from ..evaluator_base import EvalContext
from ._command import CommandEvaluatorAdapter
from ...types import EvalRunResult, EvalScore, UnifiedFinding


class DeepEvalEvaluator(CommandEvaluatorAdapter):
    """Wraps the DeepEval framework for LLM quality evaluation."""

    command_name = "deepeval"

    @property
    def name(self) -> str:
        return "deepeval"

    def evaluate(self, context: EvalContext) -> EvalRunResult:
        command_raw = self.spec.params.get("command")
        if not command_raw:
            if not self._command_exists():
                return self._skipped_result(context, "deepeval not found in PATH and no params.command set")
            command_raw = "deepeval test run"

        if isinstance(command_raw, str):
            command_list = shlex.split(command_raw)
        else:
            command_list = [str(c) for c in command_raw]

        output_json = self.spec.params.get("output_json")
        env_overrides: dict[str, str] = {}
        for k, v in self.spec.params.get("env", {}).items():
            env_overrides[str(k)] = str(v)
        if self.spec.params.get("model"):
            env_overrides["DEEPEVAL_MODEL"] = str(self.spec.params["model"])

        cwd = self.spec.params.get("working_dir")

        cmd_output, artifacts = self._result_from_command(
            context,
            command_list,
            artifact_name_prefix="deepeval_eval",
            env_overrides=env_overrides or None,
            cwd=cwd,
        )

        scores: list[EvalScore] = []
        findings: list[UnifiedFinding] = []
        threshold = float(self.spec.params.get("threshold", 0.5))

        payload = self._parse_json_output(output_json)
        if payload:
            scores.extend(self._parse_deepeval_output(payload, threshold))

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
            description=f"deepeval evaluation {'succeeded' if cmd_output.returncode == 0 else 'failed'}",
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
                    description=f"DeepEval metric '{score.metric}' failed: score={score.score:.2f} < threshold={score.threshold:.2f}. {score.reason}",
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

    def _parse_deepeval_output(self, payload: dict[str, Any], threshold: float) -> list[EvalScore]:
        scores: list[EvalScore] = []

        test_results = payload.get("test_results", payload.get("results", []))
        if isinstance(test_results, list):
            for result in test_results:
                if not isinstance(result, dict):
                    continue
                metrics_data = result.get("metrics_data", result.get("metrics", []))
                if isinstance(metrics_data, list):
                    for metric_item in metrics_data:
                        if not isinstance(metric_item, dict):
                            continue
                        metric_name = str(metric_item.get("name", metric_item.get("metric", "unknown")))
                        raw_score = metric_item.get("score", metric_item.get("value", 0.0))
                        score_val = float(raw_score) if raw_score is not None else 0.0
                        item_threshold = float(metric_item.get("threshold", metric_item.get("minimum_score", threshold)))
                        passed = metric_item.get("success", metric_item.get("passed"))
                        if passed is None:
                            passed = score_val >= item_threshold
                        scores.append(self._make_eval_score(
                            metric_name,
                            score_val,
                            threshold=item_threshold,
                            reason=str(metric_item.get("reason", "")),
                            metadata={"raw": metric_item},
                        ))
                        scores[-1].passed = bool(passed)

        if not scores:
            for key in ("scores", "evaluations"):
                items = payload.get(key, [])
                if isinstance(items, list):
                    for item in items:
                        if not isinstance(item, dict):
                            continue
                        metric = str(item.get("metric", item.get("name", "unknown")))
                        score_val = float(item.get("score", item.get("value", 0.0)))
                        scores.append(self._make_eval_score(
                            metric,
                            score_val,
                            threshold=float(item.get("threshold", threshold)),
                            reason=str(item.get("reason", "")),
                        ))

        return scores
