"""Inspect AI evaluator adapter."""

from __future__ import annotations

import shlex
from typing import Any

from ..evaluator_base import EvalContext
from ._command import CommandEvaluatorAdapter
from ...types import EvalRunResult, EvalScore, UnifiedFinding


class InspectEvalEvaluator(CommandEvaluatorAdapter):
    """Wraps Inspect AI's task-based evaluation framework."""

    command_name = "inspect"

    @property
    def name(self) -> str:
        return "inspect_eval"

    def evaluate(self, context: EvalContext) -> EvalRunResult:
        command_raw = self.spec.params.get("command")
        if not command_raw:
            if not self._command_exists():
                return self._skipped_result(context, "inspect not found in PATH and no params.command set")
            command_raw = "inspect eval"

        if isinstance(command_raw, str):
            command_list = shlex.split(command_raw)
        else:
            command_list = [str(c) for c in command_raw]

        output_json = self.spec.params.get("output_json")
        log_dir = self.spec.params.get("log_dir")
        env_overrides: dict[str, str] = {}
        for k, v in self.spec.params.get("env", {}).items():
            env_overrides[str(k)] = str(v)
        if log_dir:
            env_overrides["INSPECT_LOG_DIR"] = str(log_dir)
        cwd = self.spec.params.get("working_dir")

        cmd_output, artifacts = self._result_from_command(
            context,
            command_list,
            artifact_name_prefix="inspect_eval",
            env_overrides=env_overrides or None,
            cwd=cwd,
        )

        scores: list[EvalScore] = []
        findings: list[UnifiedFinding] = []
        threshold = float(self.spec.params.get("threshold", 0.5))

        payload = self._parse_json_output(output_json)
        if payload:
            scores.extend(self._parse_inspect_output(payload, threshold))

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
            description=f"inspect eval {'succeeded' if cmd_output.returncode == 0 else 'failed'}",
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
                    description=f"Inspect AI scorer '{score.metric}' failed: score={score.score:.2f} < threshold={score.threshold:.2f}. {score.reason}",
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

    def _parse_inspect_output(self, payload: dict[str, Any], threshold: float) -> list[EvalScore]:
        scores: list[EvalScore] = []

        # Inspect AI eval log JSON: {"results": {"scorer": {...}, "scores": [...]}}
        results = payload.get("results", {})
        if isinstance(results, dict):
            # Per-scorer metrics in results.scores
            score_list = results.get("scores", [])
            if isinstance(score_list, list):
                for scorer_block in score_list:
                    if not isinstance(scorer_block, dict):
                        continue
                    scorer_name = str(scorer_block.get("name", scorer_block.get("scorer", "unknown")))
                    metrics = scorer_block.get("metrics", {})
                    if isinstance(metrics, dict):
                        for metric_name, metric_data in metrics.items():
                            if isinstance(metric_data, dict):
                                score_val = float(metric_data.get("value", metric_data.get("mean", 0.0)))
                            else:
                                score_val = float(metric_data) if metric_data is not None else 0.0
                            full_name = f"{scorer_name}/{metric_name}" if scorer_name != "unknown" else metric_name
                            scores.append(self._make_eval_score(
                                full_name,
                                score_val,
                                threshold=threshold,
                                metadata={"scorer": scorer_name, "raw": scorer_block},
                            ))

            # Single scorer in results.scorer
            if not scores:
                scorer = results.get("scorer", {})
                if isinstance(scorer, dict):
                    scorer_name = str(scorer.get("name", "unknown"))
                    metrics = scorer.get("metrics", {})
                    if isinstance(metrics, dict):
                        for metric_name, metric_data in metrics.items():
                            if isinstance(metric_data, dict):
                                score_val = float(metric_data.get("value", metric_data.get("mean", 0.0)))
                            else:
                                score_val = float(metric_data) if metric_data is not None else 0.0
                            scores.append(self._make_eval_score(
                                metric_name,
                                score_val,
                                threshold=threshold,
                                metadata={"scorer": scorer_name},
                            ))

        # Inspect AI sample-level results
        if not scores:
            samples = payload.get("samples", [])
            if isinstance(samples, list):
                sample_scores: dict[str, list[float]] = {}
                for sample in samples:
                    if not isinstance(sample, dict):
                        continue
                    sample_score = sample.get("score", sample.get("scores", {}))
                    if isinstance(sample_score, dict):
                        for metric_name, val in sample_score.items():
                            if isinstance(val, dict):
                                val = val.get("value", 0.0)
                            if val is not None:
                                sample_scores.setdefault(metric_name, []).append(float(val))
                # Aggregate sample scores by mean
                for metric_name, values in sample_scores.items():
                    avg = sum(values) / len(values) if values else 0.0
                    scores.append(self._make_eval_score(
                        metric_name,
                        avg,
                        threshold=threshold,
                        metadata={"sample_count": len(values)},
                    ))

        # Fallback: flat scores array
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
