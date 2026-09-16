"""v1 §4.5 / G8: `urt diff a b`, `GET /v1/runs/{a}/diff/{b}`, `GET /v1/targets/{id}/trend`
and the `/ui/diff`, `/ui/targets/{id}/trend` pages.

Cross-run finding identity is `category + sub_category + target_id` (`finding_id`
embeds the run id, so it cannot be compared across runs).
"""

from __future__ import annotations

import json
import re

from conftest import TARGET_ID, Bundle, bundle_spec, engine_findings, with_engine_findings
from fastapi.testclient import TestClient

from urt.api import create_app
from urt.cli import main
from urt.diff import RunDiff, diff_runs, finding_identity
from urt.types import RunSpec, UnifiedFinding


def _finding(fid: str, category: str, sub: str | None, severity: str, *, target: str = "t1", success: bool = True):
    return UnifiedFinding(
        finding_id=fid,
        run_id="r",
        target_id=target,
        engine="garak",
        category=category,
        sub_category=sub,
        severity=severity,
        confidence=0.5,
        attack_vector="probe",
        attack_complexity="unknown",
        success=success,
        description=f"{category} {sub}",
    )


def test_finding_identity_ignores_run_scoped_ids_and_engine():
    a = _finding("run-a:t1:garak:1", "prompt_injection", "dan", "high")
    b = _finding("run-b:t1:promptfoo:9", "prompt_injection", "dan", "low")
    assert finding_identity(a) == finding_identity(b) == "prompt_injection|dan|t1"
    assert finding_identity(_finding("x", "prompt_injection", None, "high")) == "prompt_injection||t1"
    assert finding_identity(_finding("x", "prompt_injection", "dan", "high", target="t2")) != finding_identity(a)


def test_diff_runs_classifies_new_resolved_persisting_and_deltas():
    findings_a = [
        _finding("a:1", "prompt_injection", "dan", "high"),
        _finding("a:2", "robustness", "bypass", "medium"),
        _finding("a:3", "robustness", "bypass", "low"),
    ]
    findings_b = [
        _finding("b:1", "prompt_injection", "dan", "critical"),
        _finding("b:2", "data_exfiltration", "leak", "high"),
    ]
    scorecard_a = {
        "total_findings": 3, "critical": 0, "high": 1, "medium": 1, "low": 1, "info": 0,
        "success_count": 3, "total_attacks": 3, "asr_overall": 1.0,
        "asr_by_category": {"prompt_injection": 1.0, "robustness": 1.0},
        "eval_scores": {"toxicity": 0.7, "relevancy": 0.8}, "eval_pass_rate": 0.5,
    }
    scorecard_b = {
        "total_findings": 2, "critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0,
        "success_count": 1, "total_attacks": 2, "asr_overall": 0.5,
        "asr_by_category": {"prompt_injection": 0.5, "data_exfiltration": 1.0},
        "eval_scores": {"toxicity": 0.9}, "eval_pass_rate": 1.0,
    }

    diff = diff_runs("run-a", findings_a, scorecard_a, "run-b", findings_b, scorecard_b)

    assert isinstance(diff, RunDiff)
    assert [g.key for g in diff.new] == ["data_exfiltration|leak|t1"]
    assert [g.key for g in diff.resolved] == ["robustness|bypass|t1"]
    assert diff.resolved[0].count_a == 2 and diff.resolved[0].max_severity_a == "medium"
    assert [g.key for g in diff.persisting] == ["prompt_injection|dan|t1"]
    persisting = diff.persisting[0]
    assert (persisting.max_severity_a, persisting.max_severity_b) == ("high", "critical")
    assert persisting.finding_ids_b == ["b:1"]

    assert diff.scorecard_delta["asr_overall"] == {"a": 1.0, "b": 0.5, "delta": -0.5}
    assert diff.scorecard_delta["critical"] == {"a": 0, "b": 1, "delta": 1}
    assert diff.asr_by_category_delta["robustness"] == {"a": 1.0, "b": None, "delta": None}
    assert diff.asr_by_category_delta["prompt_injection"]["delta"] == -0.5
    assert diff.eval_delta["toxicity"] == {"a": 0.7, "b": 0.9, "delta": 0.2}
    assert diff.eval_delta["relevancy"] == {"a": 0.8, "b": None, "delta": None}
    assert diff.summary == {"new": 1, "resolved": 1, "persisting": 1}
    assert RunDiff.from_dict(json.loads(json.dumps(diff.to_dict()))) == diff


def _second_run(bundle: Bundle, *, name: str = "mcs-agent-garak-real-20260923") -> str:
    """A later run on the same target with the prompt_injection findings but no garak DAN bypass."""
    result = bundle.orchestrator.execute(RunSpec.from_dict(bundle_spec(name)))
    assert result["status"] == "completed"
    later = Bundle(orchestrator=bundle.orchestrator, run_id=result["run_id"])
    keep = [f for f in engine_findings(later.run_id) if f.engine != "garak"]
    with_engine_findings(later, keep)
    return later.run_id


def test_diff_api_and_cli_on_real_bundles(rich_bundle: Bundle, capsys):
    client = TestClient(create_app(rich_bundle.orchestrator))
    a, b = rich_bundle.run_id, _second_run(rich_bundle)

    response = client.get(f"/v1/runs/{a}/diff/{b}")
    assert response.status_code == 200
    body = response.json()
    assert body["run_a"] == a and body["run_b"] == b
    assert body["identity_fields"] == ["category", "sub_category", "target_id"]
    resolved = {g["key"] for g in body["resolved"]}
    assert f"robustness|mitigation.MitigationBypass|{TARGET_ID}" in resolved
    assert f"prompt_injection|promptfoo:harmful:privacy|{TARGET_ID}" in {g["key"] for g in body["persisting"]}
    assert body["scorecard_delta"]["high"]["delta"] == -1
    assert body["eval_delta"]["toxicity"]["b"] is None  # second run has no evaluator scores

    assert client.get(f"/v1/runs/{a}/diff/nope").status_code == 404
    assert client.get(f"/v1/runs/nope/diff/{b}").status_code == 404

    orch = rich_bundle.orchestrator
    base = ["--artifact-root", str(orch.artifact_store.root_dir), "--metadata-db", str(orch.metadata_store.db_path)]
    assert main([*base, "diff", a, b]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["summary"] == body["summary"]
    assert main([*base, "diff", a, b, "--format", "text"]) == 0
    text = capsys.readouterr().out
    assert "resolved" in text and "robustness|mitigation.MitigationBypass" in text
    assert main([*base, "diff", a, "nope"]) == 1


def test_trend_api_lists_points_per_target_oldest_first(rich_bundle: Bundle):
    client = TestClient(create_app(rich_bundle.orchestrator))
    a, b = rich_bundle.run_id, _second_run(rich_bundle)
    other = rich_bundle.orchestrator.execute(RunSpec.from_dict({**bundle_spec("other"), "targets": [
        {"id": "other-agent", "type": "http", "endpoint": "http://localhost:9999/x", "config": {"skip_healthcheck": True}}
    ]}))
    assert other["status"] == "completed"

    response = client.get(f"/v1/targets/{TARGET_ID}/trend")
    assert response.status_code == 200
    body = response.json()
    assert body["target_id"] == TARGET_ID
    assert [p["run_id"] for p in body["points"]] == [a, b]
    first, second = body["points"]
    # Single-target runs: per-target numbers equal the run scorecard.
    scorecard = rich_bundle.read_json("scorecard.json")
    assert first["critical_high"] == scorecard["critical"] + scorecard["high"]
    assert first["asr_overall"] == scorecard["asr_overall"]
    assert second["critical_high"] == first["critical_high"] - 1  # garak DAN bypass (high) is gone
    assert first["eval_pass_rate_run"] == 0.5 and second["eval_pass_rate_run"] is None
    assert set(first) >= {"run_id", "name", "created_at", "status", "total_findings", "critical", "high", "asr_overall"}

    assert client.get("/v1/targets/unknown-target/trend").status_code == 404


def test_name_prefix_strips_the_date_suffix_of_the_naming_convention():
    from urt.diff import name_prefix

    assert name_prefix("mcs-agent-garak-real-20260916") == "mcs-agent-garak-real"
    assert name_prefix("mcs-agent-garak-real-20260916-143000") == "mcs-agent-garak-real"
    assert name_prefix("foundry-copilot-smoke") == "foundry-copilot-smoke"
    assert name_prefix("") == ""


def test_ui_diff_picker_is_scoped_to_same_target_or_name_prefix(rich_bundle: Bundle):
    """§4.5: pick two runs of the same target or the same name prefix; unrelated runs are not offered."""
    client = TestClient(create_app(rich_bundle.orchestrator))
    a, b = rich_bundle.run_id, _second_run(rich_bundle)
    same_prefix_other_target = rich_bundle.orchestrator.execute(RunSpec.from_dict({
        **bundle_spec("mcs-agent-garak-real-20260930"),
        "targets": [{"id": "staging-agent", "type": "http", "endpoint": "http://localhost:9999/x", "config": {"skip_healthcheck": True}}],
    }))["run_id"]
    unrelated = rich_bundle.orchestrator.execute(RunSpec.from_dict({
        **bundle_spec("other-thing"),
        "targets": [{"id": "other-agent", "type": "http", "endpoint": "http://localhost:9999/x", "config": {"skip_healthcheck": True}}],
    }))["run_id"]

    # No A yet: A offers everything, B offers nothing until A is chosen.
    picker = client.get("/ui/diff").text
    a_options = re.search(r'<select name="a">(.*?)</select>', picker, flags=re.S).group(1)
    b_options = re.search(r'<select name="b">(.*?)</select>', picker, flags=re.S).group(1)
    assert all(f'value="{r}"' in a_options for r in (a, b, same_prefix_other_target, unrelated))
    assert "choose A first" in b_options and f'value="{b}"' not in b_options

    scoped = client.get("/ui/diff", params={"a": a}).text
    b_options = re.search(r'<select name="b">(.*?)</select>', scoped, flags=re.S).group(1)
    assert f'value="{b}"' in b_options  # same target
    assert f'value="{same_prefix_other_target}"' in b_options  # same name prefix
    assert f'value="{unrelated}"' not in b_options
    assert f'value="{a}"' not in b_options  # not itself
    assert "same target or same name prefix" in scoped

    # Forcing an unrelated pair through the URL still renders, but says so.
    forced = client.get("/ui/diff", params={"a": a, "b": unrelated})
    assert forced.status_code == 200
    assert "share no target and no name prefix" in forced.text
    assert "share no target" not in client.get("/ui/diff", params={"a": a, "b": b}).text


def test_ui_diff_and_trend_pages(rich_bundle: Bundle):
    client = TestClient(create_app(rich_bundle.orchestrator))
    a, b = rich_bundle.run_id, _second_run(rich_bundle)

    listing = client.get("/ui").text
    assert f'href="/ui/targets/{TARGET_ID}/trend"' in listing
    assert 'href="/ui/diff' in listing

    picker = client.get("/ui/diff")
    assert picker.status_code == 200
    assert f'<option value="{a}"' in picker.text

    page = client.get("/ui/diff", params={"a": a, "b": b})
    assert page.status_code == 200
    assert "Resolved (1)" in page.text or "Resolved (" in page.text
    assert f"robustness|mitigation.MitigationBypass|{TARGET_ID}" not in page.text  # keys are rendered as columns
    assert "mitigation.MitigationBypass" in page.text
    assert "ASR by category" in page.text
    assert "toxicity" in page.text
    assert "−" in page.text or "-1" in page.text
    assert client.get("/ui/diff", params={"a": a, "b": "nope"}).status_code == 404

    trend = client.get(f"/ui/targets/{TARGET_ID}/trend")
    assert trend.status_code == 200
    assert "<svg" in trend.text and "<polyline" in trend.text
    assert "style=" not in trend.text  # CSP: no inline styles
    assert not re.search(r"<[^>]*\son[a-z]+=", trend.text)
    assert f'href="/ui/runs/{a}"' in trend.text and f'href="/ui/runs/{b}"' in trend.text
    assert f'href="/ui/diff?a={a}&amp;b={b}"' in trend.text
    assert client.get("/ui/targets/unknown/trend").status_code == 404
