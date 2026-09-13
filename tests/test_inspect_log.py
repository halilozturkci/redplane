"""Shared Inspect EvalLog walking keeps adapter polarity/product mapping separate."""

from __future__ import annotations

from urt.adapters.inspect_log import (
    DIAGNOSTIC_METRIC_NAMES,
    as_number,
    iter_result_score_metrics,
    iter_sample_score_items,
    primary_result_metric,
)


def test_as_number_rejects_bool() -> None:
    assert as_number(True) is None
    assert as_number(0.75) == 0.75
    assert as_number("1.0") == 1.0


def test_iter_result_metrics_keeps_diagnostics_unless_skipped() -> None:
    results = {
        "scores": [
            {
                "name": "accuracy",
                "metrics": {
                    "accuracy": {"value": 0.85},
                    "stderr": {"value": 0.03},
                },
            }
        ]
    }
    kept = [(item.metric, item.raw_value) for item in iter_result_score_metrics(results)]
    assert kept == [
        ("accuracy", {"value": 0.85}),
        ("stderr", {"value": 0.03}),
    ]
    skipped = [item.metric for item in iter_result_score_metrics(results, skip_diagnostics=True)]
    assert skipped == ["accuracy"]
    assert "stderr" in DIAGNOSTIC_METRIC_NAMES


def test_primary_result_metric_drops_stderr_for_engine_aggregates() -> None:
    block = {
        "name": "accuracy",
        "metrics": {
            "accuracy": {"value": 0.75},
            "stderr": {"value": 0.2},
        },
    }
    assert primary_result_metric(block) == ("accuracy", "accuracy", {"value": 0.75})
    other = {
        "name": "custom",
        "metrics": {
            "stderr": {"value": 0.1},
            "f1": {"value": 0.4},
        },
    }
    assert primary_result_metric(other) == ("custom", "f1", {"value": 0.4})


def test_sample_score_items_engine_prefers_scores_key() -> None:
    sample = {
        "score": {"accuracy": 0.0},
        "scores": {"match": {"value": 1.0, "explanation": "ok"}},
    }
    engine_items = list(iter_sample_score_items(sample, prefer_scores=True))
    eval_items = list(iter_sample_score_items(sample, prefer_scores=False))
    assert engine_items == [("match", {"value": 1.0, "explanation": "ok"})]
    assert eval_items == [("accuracy", 0.0)]
