"""Inspect AI evaluator adapter."""

from __future__ import annotations

import shlex
from typing import Any

from ..evaluator_base import EvalContext
from ..inspect_log import (
    iter_block_metrics,
    iter_payload_samples,
    iter_result_score_metrics,
    iter_sample_score_items,
    result_scorer_block,
)
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

        results = payload.get("results", {})
        if isinstance(results, dict):
            for item in iter_result_score_metrics(results, skip_diagnostics=False):
                scores.append(
                    self._make_eval_score(
                        self._metric_name(item.scorer, item.metric),
                        self._metric_float(item.raw_value),
                        threshold=threshold,
                        metadata={"scorer": item.scorer, "raw": item.block},
                    )
                )

            if not scores:
                scorer = result_scorer_block(results)
                if scorer is not None:
                    scorer_name = str(scorer.get("name", "unknown"))
                    for metric_name, metric_data in iter_block_metrics(scorer, skip_diagnostics=False):
                        scores.append(
                            self._make_eval_score(
                                metric_name,
                                self._metric_float(metric_data),
                                threshold=threshold,
                                metadata={"scorer": scorer_name},
                            )
                        )

        if not scores:
            sample_scores: dict[str, list[float]] = {}
            for sample in iter_payload_samples(payload):
                for metric_name, val in iter_sample_score_items(sample, prefer_scores=False):
                    if isinstance(val, dict):
                        val = val.get("value", 0.0)
                    if val is not None:
                        sample_scores.setdefault(str(metric_name), []).append(float(val))
            for metric_name, values in sample_scores.items():
                avg = sum(values) / len(values) if values else 0.0
                scores.append(
                    self._make_eval_score(
                        metric_name,
                        avg,
                        threshold=threshold,
                        metadata={"sample_count": len(values)},
                    )
                )

        if not scores:
            for key in ("scores", "evaluations"):
                items = payload.get(key, [])
                if isinstance(items, list):
                    for item in items:
                        if not isinstance(item, dict):
                            continue
                        metric = str(item.get("metric", item.get("name", "unknown")))
                        score_val = float(item.get("score", item.get("value", 0.0)))
                        scores.append(
                            self._make_eval_score(
                                metric,
                                score_val,
                                threshold=float(item.get("threshold", threshold)),
                                reason=str(item.get("reason", "")),
                            )
                        )

        return scores

    @staticmethod
    def _metric_name(scorer_name: str, metric_name: str) -> str:
        return f"{scorer_name}/{metric_name}" if scorer_name != "unknown" else metric_name

    @staticmethod
    def _metric_float(metric_data: object) -> float:
        if isinstance(metric_data, dict):
            return float(metric_data.get("value", metric_data.get("mean", 0.0)))
        return float(metric_data) if metric_data is not None else 0.0
