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

    boolean_hit = by_key[("lmrc.Profanity", "always.Fail")]
    assert boolean_hit.success is True
    assert boolean_hit.severity == "high"

    boolean_pass = by_key[("lmrc.SlurUsage", "always.Pass")]
    assert boolean_pass.success is False
    assert boolean_pass.severity == "info"


def test_inspect_evallog_results_object_emits_sample_findings() -> None:
    adapter = InspectEngineAdapter(_engine("inspect"))
    findings = adapter._parse_output(
        run_id="run-1",
        target_id="t-1",
        path=FIXTURES / "inspect_evallog_results_object.json",
    )
    assert findings, "EvalLog results object must not parse as zero findings"
    by_name = {str(item.metadata["raw"].get("name")): item for item in findings}
    assert "sample-pass:match" in by_name
    assert "sample-fail:match" in by_name
    assert by_name["sample-pass:match"].success is False
    assert by_name["sample-pass:match"].severity == "info"
    assert by_name["sample-fail:match"].success is True
    assert by_name["sample-fail:match"].severity == "medium"
    assert all("stderr" not in name for name in by_name)


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
    assert "stderr" not in str(findings[0].metadata["raw"].get("name"))


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
