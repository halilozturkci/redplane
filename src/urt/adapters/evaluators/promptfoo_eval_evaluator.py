"""Promptfoo assertion-based evaluator adapter."""

from __future__ import annotations

import shlex
from typing import Any

from ..evaluator_base import EvalContext
from ._command import CommandEvaluatorAdapter
from ...types import EvalRunResult, EvalScore, UnifiedFinding


class PromptfooEvalEvaluator(CommandEvaluatorAdapter):
    """Wraps Promptfoo's eval mode for assertion-based quality evaluation."""

    command_name = "promptfoo"

    @property
    def name(self) -> str:
        return "promptfoo_eval"

    def evaluate(self, context: EvalContext) -> EvalRunResult:
        command_raw = self.spec.params.get("command")
        if not command_raw:
            if not self._command_exists():
                return self._skipped_result(context, "promptfoo not found in PATH and no params.command set")
            config_path = self.spec.params.get("config_path", "")
            parts = ["promptfoo", "eval"]
            if config_path:
                parts.extend(["-c", str(config_path)])
            output_json = self.spec.params.get("output_json")
            if output_json:
                parts.extend(["-o", str(output_json), "--output-format", "json"])
            command_raw = parts

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
            artifact_name_prefix="promptfoo_eval",
            env_overrides=env_overrides or None,
            cwd=cwd,
        )

        scores: list[EvalScore] = []
        findings: list[UnifiedFinding] = []
        threshold = float(self.spec.params.get("threshold", 0.5))

        payload = self._parse_json_output(output_json)
        if payload:
            scores.extend(self._parse_promptfoo_output(payload, threshold))

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
            description=f"promptfoo eval {'succeeded' if cmd_output.returncode == 0 else 'failed'}",
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
                    description=f"Promptfoo assertion '{score.metric}' failed: score={score.score:.2f} < threshold={score.threshold:.2f}. {score.reason}",
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

    def _parse_promptfoo_output(self, payload: dict[str, Any], threshold: float) -> list[EvalScore]:
        scores: list[EvalScore] = []

        # Promptfoo eval JSON: {"results": {"results": [...]}, "stats": {...}}
        results_wrapper = payload.get("results", payload)
        if isinstance(results_wrapper, dict):
            result_list = results_wrapper.get("results", [])
        else:
            result_list = []

        if isinstance(result_list, list):
            for result in result_list:
                if not isinstance(result, dict):
                    continue

                # Each result has "gradingResult" with component results
                grading = result.get("gradingResult", result.get("grading", {}))
                if not isinstance(grading, dict):
                    continue

                # Top-level pass/score from gradingResult
                overall_pass = grading.get("pass", grading.get("passed"))
                overall_score = grading.get("score", 0.0)

                # Per-component assertion results
                component_results = grading.get("componentResults", [])
                if isinstance(component_results, list) and component_results:
                    for comp in component_results:
                        if not isinstance(comp, dict):
                            continue
                        assertion_type = str(comp.get("assertion", {}).get("type", "unknown") if isinstance(comp.get("assertion"), dict) else "unknown")
                        comp_score = float(comp.get("score", 0.0))
                        comp_pass = comp.get("pass", comp.get("passed"))
                        if comp_pass is None:
                            comp_pass = comp_score >= threshold
                        reason = str(comp.get("reason", ""))
                        scores.append(self._make_eval_score(
                            assertion_type,
                            comp_score,
                            threshold=threshold,
                            reason=reason,
                            metadata={"raw": comp},
                        ))
                        scores[-1].passed = bool(comp_pass)
                elif overall_score is not None:
                    # No component breakdown — use top-level score
                    prompt_id = str(result.get("testIdx", result.get("id", "unknown")))
                    if overall_pass is None:
                        overall_pass = float(overall_score) >= threshold
                    scores.append(self._make_eval_score(
                        f"prompt_{prompt_id}",
                        float(overall_score),
                        threshold=threshold,
                        reason=str(grading.get("reason", "")),
                    ))
                    scores[-1].passed = bool(overall_pass)

        # Fallback: flat "scores" / "evaluations" array
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
