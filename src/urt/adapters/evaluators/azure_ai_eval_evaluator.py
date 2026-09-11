"""Azure AI Evaluation SDK evaluator adapter."""

from __future__ import annotations

import shlex
from typing import Any

from ..evaluator_base import EvalContext
from ._command import CommandEvaluatorAdapter
from ...types import EvalRunResult, EvalScore, UnifiedFinding


class AzureAIEvalEvaluator(CommandEvaluatorAdapter):
    """Wraps the Azure AI Evaluation SDK for quality and safety evaluation."""

    command_name = "azure-ai-eval"

    @property
    def name(self) -> str:
        return "azure_ai_eval"

    def evaluate(self, context: EvalContext) -> EvalRunResult:
        command_raw = self.spec.params.get("command")
        script_path = self.spec.params.get("script_path")

        if not command_raw and not script_path:
            return self._skipped_result(
                context,
                "azure_ai_eval requires params.command or params.script_path",
            )

        if not command_raw:
            command_raw = f"python {script_path}"

        if isinstance(command_raw, str):
            command_list = shlex.split(command_raw)
        else:
            command_list = [str(c) for c in command_raw]

        output_json = self.spec.params.get("output_json")
        env_overrides: dict[str, str] = {}
        for k, v in self.spec.params.get("env", {}).items():
            env_overrides[str(k)] = str(v)
        # Pass Azure project endpoint if configured
        endpoint = self.spec.params.get("azure_project_endpoint")
        if endpoint:
            env_overrides["AZURE_PROJECT_ENDPOINT"] = str(endpoint)
        cwd = self.spec.params.get("working_dir")

        cmd_output, artifacts = self._result_from_command(
            context,
            command_list,
            artifact_name_prefix="azure_ai_eval",
            env_overrides=env_overrides or None,
            cwd=cwd,
        )

        scores: list[EvalScore] = []
        findings: list[UnifiedFinding] = []
        threshold = float(self.spec.params.get("threshold", 0.5))

        payload = self._parse_json_output(output_json)
        if payload:
            scores.extend(self._parse_azure_eval_output(payload, threshold))

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
            description=f"azure_ai_eval {'succeeded' if cmd_output.returncode == 0 else 'failed'}",
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
                    description=f"Azure AI Eval metric '{score.metric}' failed: score={score.score:.2f} < threshold={score.threshold:.2f}. {score.reason}",
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

    def _parse_azure_eval_output(self, payload: dict[str, Any], threshold: float) -> list[EvalScore]:
        scores: list[EvalScore] = []

        # Azure AI Evaluation SDK output: {"metrics": {"gpt_groundedness": 4.2, ...}, "rows": [...]}
        # Or: {"studio_url": "...", "metrics": {...}, "rows": [...]}
        metrics = payload.get("metrics", {})
        if isinstance(metrics, dict) and metrics:
            for metric_name, raw_value in metrics.items():
                if raw_value is None:
                    continue
                score_val = float(raw_value)
                # Azure AI SDK uses 1-5 scale for quality metrics; normalize to 0-1
                normalized = self._normalize_azure_score(metric_name, score_val)
                scores.append(self._make_eval_score(
                    metric_name,
                    normalized,
                    threshold=threshold,
                    metadata={"raw_value": score_val, "scale": self._get_scale(metric_name)},
                ))

        # Per-row results with individual evaluator outputs
        if not scores:
            rows = payload.get("rows", [])
            if isinstance(rows, list):
                metric_values: dict[str, list[float]] = {}
                for row in rows:
                    if not isinstance(row, dict):
                        continue
                    for key, val in row.items():
                        # Azure AI SDK outputs columns like "outputs.groundedness.gpt_groundedness"
                        if val is not None and isinstance(val, (int, float)):
                            metric_values.setdefault(key, []).append(float(val))
                for metric_name, values in metric_values.items():
                    avg = sum(values) / len(values) if values else 0.0
                    normalized = self._normalize_azure_score(metric_name, avg)
                    scores.append(self._make_eval_score(
                        metric_name,
                        normalized,
                        threshold=threshold,
                        metadata={"raw_mean": avg, "sample_count": len(values)},
                    ))

        # Fallback: flat scores array
        if not scores:
            for key in ("scores", "evaluations", "results"):
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

    @staticmethod
    def _get_scale(metric_name: str) -> str:
        """Determine the scoring scale used by this Azure metric."""
        metric_lower = metric_name.lower()
        # Safety metrics use 0-7 severity scale (lower is safer)
        safety_keywords = ("violence", "sexual", "self_harm", "hate", "content_safety")
        if any(kw in metric_lower for kw in safety_keywords):
            return "0-7_severity"
        # Quality metrics use 1-5 Likert scale
        return "1-5_likert"

    @staticmethod
    def _normalize_azure_score(metric_name: str, raw_score: float) -> float:
        """Normalize Azure AI SDK scores to 0.0-1.0 range."""
        metric_lower = metric_name.lower()
        safety_keywords = ("violence", "sexual", "self_harm", "hate", "content_safety")
        if any(kw in metric_lower for kw in safety_keywords):
            # Safety: 0-7 severity where 0=safe, 7=severe. Invert and normalize.
            return max(0.0, min(1.0, 1.0 - (raw_score / 7.0)))
        # Quality: 1-5 Likert scale. Normalize to 0-1.
        return max(0.0, min(1.0, (raw_score - 1.0) / 4.0))
