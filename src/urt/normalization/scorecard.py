"""Unified scorecard calculations."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import TYPE_CHECKING

from ..constants import SEVERITY_ORDER
from ..types import UnifiedFinding, UnifiedScorecard
from .kind import ASR_KINDS, finding_kind

if TYPE_CHECKING:
    from ..types import EvalRunResult


def build_scorecard(
    run_id: str,
    findings: list[UnifiedFinding],
    *,
    eval_results: list[EvalRunResult] | None = None,
) -> UnifiedScorecard:
    severity_counter = Counter(f.severity for f in findings)
    engine_counter = Counter(f.engine for f in findings)

    # ASR allowlist (idea 4): only `attack` kind findings describe the target's
    # behaviour; coverage gaps, launcher failures, healthchecks and evaluator
    # metrics must not move the attack success rate either way.
    attack_findings = [f for f in findings if finding_kind(f) in ASR_KINDS]
    success_count = sum(1 for f in attack_findings if f.success)
    total_attacks = len(attack_findings)

    per_category_counts: dict[str, list[bool]] = defaultdict(list)
    for item in attack_findings:
        per_category_counts[item.category].append(item.success)

    asr_by_category = {
        category: (sum(1 for ok in flags if ok) / len(flags) if flags else 0.0)
        for category, flags in per_category_counts.items()
    }

    asr_overall = success_count / total_attacks if total_attacks else 0.0

    # Aggregate evaluation scores
    eval_scores: dict[str, float] = {}
    eval_pass_rate = 0.0
    if eval_results:
        metric_values: dict[str, list[float]] = defaultdict(list)
        eval_passed = 0
        eval_total = 0
        for result in eval_results:
            for score in result.scores:
                metric_values[score.metric].append(score.score)
                eval_total += 1
                if score.passed:
                    eval_passed += 1
        eval_scores = {k: sum(v) / len(v) for k, v in metric_values.items()}
        eval_pass_rate = eval_passed / eval_total if eval_total > 0 else 0.0

    return UnifiedScorecard(
        run_id=run_id,
        created_at=UnifiedScorecard.now_timestamp(),
        total_findings=len(findings),
        critical=severity_counter.get("critical", 0),
        high=severity_counter.get("high", 0),
        medium=severity_counter.get("medium", 0),
        low=severity_counter.get("low", 0),
        info=severity_counter.get("info", 0),
        success_count=success_count,
        total_attacks=total_attacks,
        asr_overall=asr_overall,
        asr_by_category=asr_by_category,
        by_engine=dict(engine_counter),
        eval_scores=eval_scores,
        eval_pass_rate=eval_pass_rate,
    )


def violates_gate(findings: list[UnifiedFinding], threshold: str) -> bool:
    threshold_value = SEVERITY_ORDER.get(threshold.lower())
    if threshold_value is None:
        raise ValueError(f"Unsupported threshold: {threshold}")
    for finding in findings:
        level = SEVERITY_ORDER.get(finding.severity.lower(), -1)
        if level >= threshold_value:
            return True
    return False
