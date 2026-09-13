"""Inspect EvalLog value walking shared by the inspect engine and inspect_eval.

Adapters own polarity, pass thresholds, UnifiedFinding/EvalScore construction,
legacy ``tests[]`` handling, and flat ``scores``/``evaluations`` fallbacks.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterator

DIAGNOSTIC_METRIC_NAMES = frozenset({"stderr", "std", "std_err", "se", "bootstrap_std"})


def as_number(value: object) -> float | None:
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


@dataclass(frozen=True, slots=True)
class InspectResultMetric:
    scorer: str
    metric: str
    raw_value: object
    block: dict[str, Any]


def iter_results_score_blocks(results: object) -> Iterator[dict[str, Any]]:
    if not isinstance(results, dict):
        return
    scores = results.get("scores")
    if not isinstance(scores, list):
        return
    for block in scores:
        if isinstance(block, dict):
            yield block


def iter_block_metrics(
    block: dict[str, Any],
    *,
    skip_diagnostics: bool,
) -> Iterator[tuple[str, object]]:
    metrics = block.get("metrics")
    if not isinstance(metrics, dict):
        return
    for metric_name, metric_data in metrics.items():
        if skip_diagnostics and str(metric_name).lower() in DIAGNOSTIC_METRIC_NAMES:
            continue
        yield str(metric_name), metric_data


def primary_result_metric(block: dict[str, Any]) -> tuple[str, str, object] | None:
    """Pick one metric per ``results.scores[]`` block (engine aggregate path)."""
    primary = str(block.get("name") or block.get("scorer") or "accuracy")
    metrics = block.get("metrics")
    if isinstance(metrics, dict):
        if primary in metrics:
            return primary, primary, metrics[primary]
        for key, value in metrics.items():
            if str(key).lower() in DIAGNOSTIC_METRIC_NAMES:
                continue
            return primary, str(key), value
    if "value" in block or "score" in block:
        return primary, primary, block
    return None


def iter_result_score_metrics(
    results: object,
    *,
    skip_diagnostics: bool = False,
) -> Iterator[InspectResultMetric]:
    for block in iter_results_score_blocks(results):
        scorer = str(block.get("name") or block.get("scorer") or "unknown")
        for metric_name, metric_data in iter_block_metrics(block, skip_diagnostics=skip_diagnostics):
            yield InspectResultMetric(
                scorer=scorer,
                metric=metric_name,
                raw_value=metric_data,
                block=block,
            )


def result_scorer_block(results: object) -> dict[str, Any] | None:
    if not isinstance(results, dict):
        return None
    scorer = results.get("scorer")
    return scorer if isinstance(scorer, dict) else None


def iter_payload_samples(payload: object) -> Iterator[dict[str, Any]]:
    if not isinstance(payload, dict):
        return
    samples = payload.get("samples")
    if not isinstance(samples, list):
        return
    for sample in samples:
        if isinstance(sample, dict):
            yield sample


def iter_sample_score_items(
    sample: dict[str, Any],
    *,
    prefer_scores: bool,
) -> Iterator[tuple[str, object]]:
    """Yield ``(name, raw score object)`` from a sample.

    Engine prefers ``sample['scores']``. Evaluator prefers ``sample['score']``,
    then ``sample['scores']``.
    """
    if prefer_scores:
        scores = sample.get("scores")
        if isinstance(scores, dict) and scores:
            yield from scores.items()
        return
    blob = sample.get("score", sample.get("scores", {}))
    if isinstance(blob, dict):
        yield from blob.items()
