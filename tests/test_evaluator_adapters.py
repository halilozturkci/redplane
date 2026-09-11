"""Tests for evaluator adapter infrastructure."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict
from unittest.mock import MagicMock, patch

import pytest

from urt.adapters import create_evaluator_adapter
from urt.adapters.evaluator_base import EvalContext, EvaluatorAdapter
from urt.adapters.evaluators import (
    AzureAIEvalEvaluator,
    CustomScriptEvaluator,
    DeepEvalEvaluator,
    GiskardEvalEvaluator,
    InspectEvalEvaluator,
    PromptfooEvalEvaluator,
)
from urt.adapters.evaluators._command import CommandEvaluatorAdapter, CommandRunResult
from urt.normalization.scorecard import build_scorecard
from urt.types import (
    EvalRunResult,
    EvalScore,
    EvaluatorSpec,
    RunSpec,
    TargetSpec,
    UnifiedFinding,
    UnifiedScorecard,
    ValidationError,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_target() -> TargetSpec:
    return TargetSpec(
        target_id="test-target",
        target_type="http",
        endpoint="http://localhost:9000/invoke",
        config={"skip_healthcheck": True},
    )


def _make_eval_context(run_id: str = "run-test-001") -> EvalContext:
    store = MagicMock()
    store.write_text = MagicMock(return_value="/tmp/artifact.log")
    store.write_json = MagicMock(return_value="/tmp/artifact.json")
    return EvalContext(
        run_id=run_id,
        run_name="test-run",
        target=_make_target(),
        artifact_store=store,
        timeout_seconds=60,
        seed=42,
        engine_findings=[],
        engine_results=[],
    )


def _make_spec(name: str, **params) -> EvaluatorSpec:
    return EvaluatorSpec(name=name, params=params)


# ---------------------------------------------------------------------------
# Core Types Tests
# ---------------------------------------------------------------------------

class TestEvaluatorSpec:
    def test_from_dict_valid(self):
        spec = EvaluatorSpec.from_dict({
            "name": "deepeval",
            "metrics": ["faithfulness", "toxicity"],
            "params": {"model": "gpt-4.1-mini", "threshold": 0.5},
        })
        assert spec.name == "deepeval"
        assert spec.metrics == ["faithfulness", "toxicity"]
        assert spec.params["model"] == "gpt-4.1-mini"
        assert spec.fail_open is True

    def test_from_dict_unsupported(self):
        with pytest.raises(ValidationError, match="Unsupported evaluator"):
            EvaluatorSpec.from_dict({"name": "nonexistent_eval"})

    def test_from_dict_case_insensitive(self):
        spec = EvaluatorSpec.from_dict({"name": "DeepEval"})
        assert spec.name == "deepeval"

    def test_fail_open_false(self):
        spec = EvaluatorSpec.from_dict({"name": "custom_script", "fail_open": False})
        assert spec.fail_open is False


class TestEvalScore:
    def test_creation(self):
        score = EvalScore(metric="faithfulness", score=0.85, threshold=0.5, passed=True)
        assert score.metric == "faithfulness"
        assert score.score == 0.85
        assert score.passed is True

    def test_to_dict(self):
        score = EvalScore(metric="toxicity", score=0.2, threshold=0.5, passed=False, reason="High toxicity")
        d = score.to_dict()
        assert d["metric"] == "toxicity"
        assert d["score"] == 0.2
        assert d["passed"] is False
        assert d["reason"] == "High toxicity"


class TestEvalRunResult:
    def test_creation(self):
        result = EvalRunResult(evaluator="deepeval", target_id="t1")
        assert result.evaluator == "deepeval"
        assert result.scores == []
        assert result.status == "completed"


# ---------------------------------------------------------------------------
# RunSpec Evaluators Integration
# ---------------------------------------------------------------------------

class TestRunSpecEvaluators:
    def test_runspec_with_evaluators(self):
        spec = RunSpec.from_dict({
            "name": "test-run",
            "run_profile": "nightly",
            "targets": [{"id": "t1", "type": "http", "endpoint": "http://localhost:9000/invoke", "config": {"skip_healthcheck": True}}],
            "engines": [{"name": "promptfoo", "params": {"command": "echo ok"}}],
            "evaluators": [
                {"name": "deepeval", "metrics": ["faithfulness"], "params": {"threshold": 0.7}},
                {"name": "custom_script", "params": {"command": "echo ok"}},
            ],
        })
        assert len(spec.evaluators) == 2
        assert spec.evaluators[0].name == "deepeval"
        assert spec.evaluators[1].name == "custom_script"

    def test_runspec_without_evaluators(self):
        spec = RunSpec.from_dict({
            "name": "test-run",
            "run_profile": "nightly",
            "targets": [{"id": "t1", "type": "http", "endpoint": "http://localhost:9000/invoke", "config": {"skip_healthcheck": True}}],
            "engines": [{"name": "promptfoo", "params": {"command": "echo ok"}}],
        })
        assert spec.evaluators == []

    def test_runspec_invalid_evaluator(self):
        with pytest.raises(ValidationError, match="Unsupported evaluator"):
            RunSpec.from_dict({
                "name": "test-run",
                "run_profile": "nightly",
                "targets": [{"id": "t1", "type": "http", "endpoint": "http://localhost:9000/invoke", "config": {"skip_healthcheck": True}}],
                "engines": [{"name": "promptfoo", "params": {"command": "echo ok"}}],
                "evaluators": [{"name": "bad_evaluator"}],
            })


# ---------------------------------------------------------------------------
# Factory Tests
# ---------------------------------------------------------------------------

class TestEvaluatorFactory:
    def test_create_all_evaluators(self):
        names = ["deepeval", "promptfoo_eval", "giskard_eval", "inspect_eval", "azure_ai_eval", "custom_script"]
        for name in names:
            adapter = create_evaluator_adapter(EvaluatorSpec(name=name, params={"command": "echo ok"}))
            assert isinstance(adapter, EvaluatorAdapter)
            assert adapter.name == name

    def test_create_unsupported(self):
        with pytest.raises(ValueError, match="Unsupported evaluator"):
            create_evaluator_adapter(EvaluatorSpec(name="nonexistent"))


# ---------------------------------------------------------------------------
# CommandEvaluatorAdapter Base Tests
# ---------------------------------------------------------------------------

class TestCommandEvaluatorBase:
    def test_skipped_result(self):
        spec = _make_spec("custom_script")
        adapter = CustomScriptEvaluator(spec)
        ctx = _make_eval_context()
        result = adapter._skipped_result(ctx, "test skip reason")
        assert result.status == "skipped"
        assert result.message == "test skip reason"
        assert len(result.findings) == 1
        assert result.findings[0].category == "coverage_gap"

    def test_make_eval_score(self):
        spec = _make_spec("custom_script")
        adapter = CustomScriptEvaluator(spec)
        score = adapter._make_eval_score("test_metric", 0.75, threshold=0.5, reason="Good")
        assert score.metric == "test_metric"
        assert score.score == 0.75
        assert score.passed is True
        assert score.reason == "Good"

    def test_make_eval_score_clamped(self):
        spec = _make_spec("custom_script")
        adapter = CustomScriptEvaluator(spec)
        score = adapter._make_eval_score("over", 1.5)
        assert score.score == 1.0
        score2 = adapter._make_eval_score("under", -0.5)
        assert score2.score == 0.0

    def test_parse_json_output_missing(self):
        spec = _make_spec("custom_script")
        adapter = CustomScriptEvaluator(spec)
        assert adapter._parse_json_output(None) is None
        assert adapter._parse_json_output("/nonexistent/path.json") is None

    def test_parse_json_output_valid(self):
        spec = _make_spec("custom_script")
        adapter = CustomScriptEvaluator(spec)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"scores": [{"metric": "test", "score": 0.9}]}, f)
            f.flush()
            result = adapter._parse_json_output(f.name)
        os.unlink(f.name)
        assert result is not None
        assert result["scores"][0]["metric"] == "test"


# ---------------------------------------------------------------------------
# CustomScript Evaluator Tests
# ---------------------------------------------------------------------------

class TestCustomScriptEvaluator:
    def test_skipped_without_command(self):
        spec = _make_spec("custom_script")
        adapter = CustomScriptEvaluator(spec)
        ctx = _make_eval_context()
        result = adapter.evaluate(ctx)
        assert result.status == "skipped"

    @patch.object(CommandEvaluatorAdapter, "_run_command")
    def test_evaluate_success(self, mock_run):
        mock_run.return_value = CommandRunResult(returncode=0, stdout="ok", stderr="")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({
                "scores": [
                    {"metric": "accuracy", "score": 0.95, "passed": True, "reason": "High accuracy"},
                    {"metric": "safety", "score": 0.3, "passed": False, "reason": "Safety concern"},
                ]
            }, f)
            f.flush()
            spec = _make_spec("custom_script", command="echo ok", output_json=f.name)
            adapter = CustomScriptEvaluator(spec)
            ctx = _make_eval_context()
            result = adapter.evaluate(ctx)
        os.unlink(f.name)
        assert result.status == "completed"
        assert len(result.scores) == 2
        assert result.scores[0].metric == "accuracy"
        assert result.scores[0].passed is True
        assert result.scores[1].metric == "safety"
        assert result.scores[1].passed is False


# ---------------------------------------------------------------------------
# DeepEval Evaluator Tests
# ---------------------------------------------------------------------------

class TestDeepEvalEvaluator:
    def test_name(self):
        adapter = DeepEvalEvaluator(_make_spec("deepeval", command="echo ok"))
        assert adapter.name == "deepeval"

    def test_parse_test_results_format(self):
        adapter = DeepEvalEvaluator(_make_spec("deepeval"))
        payload = {
            "test_results": [{
                "metrics_data": [
                    {"name": "faithfulness", "score": 0.9, "threshold": 0.5, "success": True, "reason": "Faithful"},
                    {"name": "toxicity", "score": 0.1, "threshold": 0.5, "success": False, "reason": "Toxic content"},
                ]
            }]
        }
        scores = adapter._parse_deepeval_output(payload, 0.5)
        assert len(scores) == 2
        assert scores[0].metric == "faithfulness"
        assert scores[0].passed is True
        assert scores[1].metric == "toxicity"
        assert scores[1].passed is False

    def test_parse_flat_scores_fallback(self):
        adapter = DeepEvalEvaluator(_make_spec("deepeval"))
        payload = {
            "scores": [
                {"metric": "relevancy", "score": 0.7},
                {"name": "bias", "value": 0.4},
            ]
        }
        scores = adapter._parse_deepeval_output(payload, 0.5)
        assert len(scores) == 2
        assert scores[0].metric == "relevancy"
        assert scores[0].passed is True  # 0.7 >= 0.5
        assert scores[1].metric == "bias"
        assert scores[1].passed is False  # 0.4 < 0.5


# ---------------------------------------------------------------------------
# Promptfoo Eval Evaluator Tests
# ---------------------------------------------------------------------------

class TestPromptfooEvalEvaluator:
    def test_name(self):
        adapter = PromptfooEvalEvaluator(_make_spec("promptfoo_eval", command="echo ok"))
        assert adapter.name == "promptfoo_eval"

    def test_parse_grading_results(self):
        adapter = PromptfooEvalEvaluator(_make_spec("promptfoo_eval"))
        payload = {
            "results": {
                "results": [{
                    "gradingResult": {
                        "pass": True,
                        "score": 0.8,
                        "componentResults": [
                            {"assertion": {"type": "llm-rubric"}, "score": 0.9, "pass": True, "reason": "Good"},
                            {"assertion": {"type": "factuality"}, "score": 0.3, "pass": False, "reason": "Not factual"},
                        ]
                    }
                }]
            }
        }
        scores = adapter._parse_promptfoo_output(payload, 0.5)
        assert len(scores) == 2
        assert scores[0].metric == "llm-rubric"
        assert scores[0].passed is True
        assert scores[1].metric == "factuality"
        assert scores[1].passed is False


# ---------------------------------------------------------------------------
# Giskard Eval Evaluator Tests
# ---------------------------------------------------------------------------

class TestGiskardEvalEvaluator:
    def test_name(self):
        adapter = GiskardEvalEvaluator(_make_spec("giskard_eval", command="echo ok"))
        assert adapter.name == "giskard_eval"

    def test_parse_issues(self):
        adapter = GiskardEvalEvaluator(_make_spec("giskard_eval"))
        payload = {
            "issues": [
                {"detector": "hallucination", "level": "major", "description": "Model hallucinated"},
                {"detector": "toxicity", "level": "minor", "description": "Mild toxicity"},
            ]
        }
        scores = adapter._parse_giskard_output(payload, 0.5)
        assert len(scores) == 2
        assert scores[0].metric == "hallucination"
        assert scores[0].score == 0.1  # major -> 0.1
        assert scores[0].passed is False
        assert scores[1].metric == "toxicity"
        assert scores[1].score == 0.6  # minor -> 0.6
        assert scores[1].passed is True


# ---------------------------------------------------------------------------
# Inspect Eval Evaluator Tests
# ---------------------------------------------------------------------------

class TestInspectEvalEvaluator:
    def test_name(self):
        adapter = InspectEvalEvaluator(_make_spec("inspect_eval", command="echo ok"))
        assert adapter.name == "inspect_eval"

    def test_parse_scorer_results(self):
        adapter = InspectEvalEvaluator(_make_spec("inspect_eval"))
        payload = {
            "results": {
                "scores": [{
                    "name": "accuracy",
                    "metrics": {
                        "accuracy": {"value": 0.85},
                        "stderr": {"value": 0.03},
                    }
                }]
            }
        }
        scores = adapter._parse_inspect_output(payload, 0.5)
        assert len(scores) == 2
        assert any(s.metric == "accuracy/accuracy" and s.score == 0.85 for s in scores)

    def test_parse_sample_level(self):
        adapter = InspectEvalEvaluator(_make_spec("inspect_eval"))
        payload = {
            "samples": [
                {"score": {"accuracy": 1.0}},
                {"score": {"accuracy": 0.0}},
                {"score": {"accuracy": 1.0}},
            ]
        }
        scores = adapter._parse_inspect_output(payload, 0.5)
        assert len(scores) == 1
        assert scores[0].metric == "accuracy"
        assert abs(scores[0].score - 0.6667) < 0.01


# ---------------------------------------------------------------------------
# Azure AI Eval Evaluator Tests
# ---------------------------------------------------------------------------

class TestAzureAIEvalEvaluator:
    def test_name(self):
        adapter = AzureAIEvalEvaluator(_make_spec("azure_ai_eval", command="echo ok"))
        assert adapter.name == "azure_ai_eval"

    def test_skipped_without_command_or_script(self):
        adapter = AzureAIEvalEvaluator(_make_spec("azure_ai_eval"))
        ctx = _make_eval_context()
        result = adapter.evaluate(ctx)
        assert result.status == "skipped"

    def test_normalize_quality_score(self):
        # Quality: 1-5 Likert -> 0-1
        assert abs(AzureAIEvalEvaluator._normalize_azure_score("gpt_groundedness", 5.0) - 1.0) < 0.01
        assert abs(AzureAIEvalEvaluator._normalize_azure_score("gpt_relevance", 1.0) - 0.0) < 0.01
        assert abs(AzureAIEvalEvaluator._normalize_azure_score("gpt_coherence", 3.0) - 0.5) < 0.01

    def test_normalize_safety_score(self):
        # Safety: 0-7 severity (inverted) -> 0-1
        assert abs(AzureAIEvalEvaluator._normalize_azure_score("violence", 0.0) - 1.0) < 0.01
        assert abs(AzureAIEvalEvaluator._normalize_azure_score("violence", 7.0) - 0.0) < 0.01
        assert abs(AzureAIEvalEvaluator._normalize_azure_score("self_harm", 3.5) - 0.5) < 0.01

    def test_parse_metrics_dict(self):
        adapter = AzureAIEvalEvaluator(_make_spec("azure_ai_eval"))
        payload = {
            "metrics": {
                "gpt_groundedness": 4.0,
                "gpt_relevance": 3.0,
                "violence": 1.0,
            }
        }
        scores = adapter._parse_azure_eval_output(payload, 0.5)
        assert len(scores) == 3
        groundedness = next(s for s in scores if s.metric == "gpt_groundedness")
        assert abs(groundedness.score - 0.75) < 0.01  # (4-1)/4 = 0.75
        violence = next(s for s in scores if s.metric == "violence")
        assert abs(violence.score - (1.0 - 1.0/7.0)) < 0.01


# ---------------------------------------------------------------------------
# Scorecard with Eval Results
# ---------------------------------------------------------------------------

class TestScorecardWithEvals:
    def test_scorecard_without_evals(self):
        scorecard = build_scorecard("run-1", [])
        assert scorecard.eval_scores == {}
        assert scorecard.eval_pass_rate == 0.0

    def test_scorecard_with_evals(self):
        eval_results = [
            EvalRunResult(
                evaluator="deepeval",
                target_id="t1",
                scores=[
                    EvalScore(metric="faithfulness", score=0.9, threshold=0.5, passed=True),
                    EvalScore(metric="toxicity", score=0.3, threshold=0.5, passed=False),
                ],
            ),
            EvalRunResult(
                evaluator="deepeval",
                target_id="t2",
                scores=[
                    EvalScore(metric="faithfulness", score=0.8, threshold=0.5, passed=True),
                ],
            ),
        ]
        scorecard = build_scorecard("run-1", [], eval_results=eval_results)
        assert abs(scorecard.eval_scores["faithfulness"] - 0.85) < 0.01
        assert abs(scorecard.eval_scores["toxicity"] - 0.3) < 0.01
        assert abs(scorecard.eval_pass_rate - 2/3) < 0.01  # 2 passed out of 3

    def test_scorecard_eval_fields_in_dict(self):
        scorecard = UnifiedScorecard(
            run_id="run-1",
            created_at="2024-01-01T00:00:00Z",
            total_findings=0,
            critical=0, high=0, medium=0, low=0, info=0,
            success_count=0, total_attacks=0,
            asr_overall=0.0, asr_by_category={}, by_engine={},
            eval_scores={"test_metric": 0.75},
            eval_pass_rate=0.8,
        )
        d = scorecard.to_dict()
        assert d["eval_scores"] == {"test_metric": 0.75}
        assert d["eval_pass_rate"] == 0.8


# ---------------------------------------------------------------------------
# Report Eval Section
# ---------------------------------------------------------------------------

class TestReportEvalSection:
    def test_markdown_includes_eval_section(self):
        from urt.report import render_markdown
        scorecard = {
            "run_id": "run-1",
            "total_findings": 0,
            "asr_overall": 0.0,
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
            "eval_scores": {"faithfulness": 0.85, "toxicity": 0.3},
            "eval_pass_rate": 0.5,
        }
        md = render_markdown(scorecard, [])
        assert "## Evaluation Results" in md
        assert "faithfulness" in md
        assert "toxicity" in md
        assert "50.00%" in md

    def test_markdown_no_eval_section_when_empty(self):
        from urt.report import render_markdown
        scorecard = {
            "run_id": "run-1",
            "total_findings": 0,
            "asr_overall": 0.0,
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        }
        md = render_markdown(scorecard, [])
        assert "## Evaluation Results" not in md

    def test_html_includes_eval_section(self):
        from urt.report import render_html
        scorecard = {
            "run_id": "run-1",
            "total_findings": 0,
            "asr_overall": 0.0,
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
            "eval_scores": {"faithfulness": 0.85},
            "eval_pass_rate": 1.0,
        }
        html = render_html(scorecard, [])
        assert "Evaluation Results" in html
        assert "faithfulness" in html
