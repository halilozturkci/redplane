"""Golden parser fixtures for native Garak / Inspect / DeepTeam shapes.

These cases failed on the polarity bugs (numeric Garak `passed`, Inspect EvalLog
`results` as an object, DeepTeam high score forcing HIGH). Keep the fixtures
checked in so a regression cannot hide behind synthetic inline JSON.
"""

from __future__ import annotations

from pathlib import Path

from urt.adapters.engines.deepteam_engine import DeepTeamEngineAdapter
from urt.adapters.engines.garak_engine import GarakEngineAdapter
from urt.adapters.engines.inspect_engine import InspectEngineAdapter
from urt.report import evaluate_gate
from urt.types import EngineSpec

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "parsers"


def _engine(name: str) -> EngineSpec:
    return EngineSpec.from_dict({"name": name, "params": {}})


def test_garak_numeric_passed_count_is_not_coerced_to_bool() -> None:
    adapter = GarakEngineAdapter(_engine("garak"))
    findings = adapter._parse_jsonl(
        run_id="run-1",
        target_id="t-1",
        path=FIXTURES / "garak_eval_passed_count.jsonl",
    )
    by_key = {(item.attack_vector, item.sub_category): item for item in findings}

    partial = by_key[("dan.Dan_11_0", "mitigation.MitigationBypass")]
    assert partial.success is True
    assert partial.severity != "info"

    clean = by_key[("encoding.InjectBase64", "mitigation.MitigationBypass")]
    assert clean.success is False
    assert clean.severity == "info"

    evaluated = by_key[("continuation.ContinueSlursReclaimedSlurs", "always.Fail")]
    assert evaluated.success is True
    assert evaluated.severity == "high"

    boolean_hit = by_key[("lmrc.Profanity", "always.Fail")]
    assert boolean_hit.success is True
    assert boolean_hit.severity == "high"

    boolean_pass = by_key[("lmrc.SlurUsage", "always.Pass")]
    assert boolean_pass.success is False
    assert boolean_pass.severity == "info"

    string_score = by_key[("lmrc.Bullying", "always.Fail")]
    assert string_score.success is True
    assert string_score.severity == "high"


def test_inspect_evallog_with_samples_keeps_native_raw() -> None:
    adapter = InspectEngineAdapter(_engine("inspect"))
    findings = adapter._parse_output(
        run_id="run-1",
        target_id="t-1",
        path=FIXTURES / "inspect_evallog_results_object.json",
    )
    assert findings, "EvalLog with a results object must not parse as zero findings"
    by_id = {str(item.metadata["raw"].get("id")): item for item in findings}
    assert by_id["sample-pass"].success is False
    assert by_id["sample-pass"].severity == "info"
    assert by_id["sample-fail"].success is True
    assert by_id["sample-fail"].severity == "medium"
    assert "scores" in by_id["sample-fail"].metadata["raw"]
    assert all(item.category != "stderr" for item in findings)


def test_inspect_evallog_results_only_unwraps_primary_metric() -> None:
    adapter = InspectEngineAdapter(_engine("inspect"))
    findings = adapter._parse_output(
        run_id="run-1",
        target_id="t-1",
        path=FIXTURES / "inspect_evallog_results_only.json",
    )
    assert len(findings) == 1
    assert findings[0].success is True
    assert findings[0].severity == "medium"
    assert findings[0].category == "accuracy"
    assert findings[0].metadata["raw"]["name"] == "accuracy"
    assert all(item.category != "stderr" for item in findings)


def test_inspect_aggregate_accuracy_below_one_is_a_finding() -> None:
    adapter = InspectEngineAdapter(_engine("inspect"))
    findings = adapter._parse_output(
        run_id="run-1",
        target_id="t-1",
        path=FIXTURES / "inspect_evallog_aggregate_partial.json",
    )
    assert len(findings) == 1
    assert findings[0].success is True
    assert findings[0].severity == "medium"


def test_inspect_empty_tests_list_falls_back_to_results() -> None:
    adapter = InspectEngineAdapter(_engine("inspect"))
    findings = adapter._parse_output(
        run_id="run-1",
        target_id="t-1",
        path=FIXTURES / "inspect_empty_tests_with_results.json",
    )
    assert len(findings) == 1
    assert findings[0].category == "fallback_row"
    assert findings[0].success is True


def test_inspect_error_sample_without_scores_is_kept() -> None:
    adapter = InspectEngineAdapter(_engine("inspect"))
    findings = adapter._parse_output(
        run_id="run-1",
        target_id="t-1",
        path=FIXTURES / "inspect_sample_error_no_scores.json",
    )
    assert len(findings) == 1
    assert findings[0].category == "coverage_gap"
    assert findings[0].attack_vector == "engine_runtime"
    assert findings[0].success is False
    assert findings[0].severity != "medium"
    assert "model timeout" in findings[0].description


def test_inspect_null_primary_metric_is_not_scored_as_zero() -> None:
    adapter = InspectEngineAdapter(_engine("inspect"))
    findings = adapter._parse_output(
        run_id="run-1",
        target_id="t-1",
        path=FIXTURES / "inspect_null_primary_metric.json",
    )
    assert findings == []


def test_inspect_continuous_mean_aggregate_is_not_an_attack() -> None:
    adapter = InspectEngineAdapter(_engine("inspect"))
    findings = adapter._parse_output(
        run_id="run-1",
        target_id="t-1",
        path=FIXTURES / "inspect_mean_metric_not_accuracy.json",
    )
    assert findings == []
    assert all(item.success is not True for item in findings)


def test_inspect_accuracy_named_block_with_only_mean_is_not_an_attack() -> None:
    adapter = InspectEngineAdapter(_engine("inspect"))
    findings = adapter._parse_output(
        run_id="run-1",
        target_id="t-1",
        path=FIXTURES / "inspect_accuracy_name_mean_metric.json",
    )
    assert findings == []


def test_inspect_legacy_tests_list_still_parses() -> None:
    adapter = InspectEngineAdapter(_engine("inspect"))
    findings = adapter._parse_output(
        run_id="run-1",
        target_id="t-1",
        path=FIXTURES / "inspect_legacy_tests_list.json",
    )
    assert len(findings) == 2
    by_category = {item.category: item for item in findings}
    assert by_category["jailbreak_refusal"].success is True
    assert by_category["benign_qa"].success is False


def test_deepteam_high_score_not_issue_is_info_and_does_not_fail_gate() -> None:
    adapter = DeepTeamEngineAdapter(_engine("deepteam"))
    findings = adapter._parse_output(
        run_id="run-1",
        target_id="t-1",
        path=FIXTURES / "deepteam_high_score_not_issue.json",
    )
    assert len(findings) == 1
    assert findings[0].success is False
    assert findings[0].severity == "info"
    ok, message = evaluate_gate(findings, "high")
    assert ok is True
    assert "Gate passed" in message


def test_deepteam_high_score_issue_still_fails_high_gate() -> None:
    adapter = DeepTeamEngineAdapter(_engine("deepteam"))
    findings = adapter._parse_output(
        run_id="run-1",
        target_id="t-1",
        path=FIXTURES / "deepteam_high_score_issue.json",
    )
    assert len(findings) == 1
    assert findings[0].success is True
    assert findings[0].severity == "high"
    ok, message = evaluate_gate(findings, "high")
    assert ok is False
    assert "Gate failed" in message
