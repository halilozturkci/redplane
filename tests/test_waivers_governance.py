"""v1 §4.6 / G9 / idea 2: waiver governance and the eval pass-rate gate option.

Seams: `gate_result()` / `GateResult`, `Orchestrator` waiver methods, the JSON API
(`/v1/waivers`, `/v1/runs/{id}/waiver-preview`, `/v1/runs/{id}/gate`), `urt gate`
and the `/ui/waivers` pages (create-from-finding, revoke, CSRF).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from conftest import TARGET_ID, Bundle
from fastapi.testclient import TestClient

from urt.api import create_app
from urt.cli import main
from urt.policy.waivers import parse_expiry
from urt.report import GateResult, gate_result
from urt.types import UnifiedFinding

FUTURE = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()


def _finding(finding_id: str, severity: str, *, category: str = "prompt_injection") -> UnifiedFinding:
    return UnifiedFinding(
        finding_id=finding_id,
        run_id="r1",
        target_id="t1",
        engine="pyrit",
        category=category,
        sub_category=None,
        severity=severity,
        confidence=0.9,
        attack_vector="jailbreak",
        attack_complexity="low",
        success=True,
        description=f"{severity} finding",
    )


# --- gate: eval_min_pass_rate (idea 2) -------------------------------------------


def test_gate_fails_when_eval_pass_rate_is_below_the_requested_minimum():
    result = gate_result([_finding("f-low", "low")], "high", eval_min_pass_rate=0.8, eval_pass_rate=0.7)

    assert result.ok is False
    assert result.blocking == []
    assert result.eval_min_pass_rate == 0.8
    assert result.eval_pass_rate == 0.7
    assert result.eval_ok is False
    assert result.message == "Gate failed: eval pass rate 70.0% below minimum 80.0% (no findings severity >= HIGH)"
    assert GateResult.from_dict(result.to_dict()) == result


def test_gate_passes_when_eval_pass_rate_meets_the_minimum_and_nothing_blocks():
    result = gate_result([], "high", eval_min_pass_rate=0.8, eval_pass_rate=0.8)
    assert result.ok is True
    assert result.eval_ok is True
    assert result.message == "Gate passed: no findings severity >= HIGH; eval pass rate 80.0% >= minimum 80.0%"


def test_gate_reports_both_causes_when_findings_block_and_eval_is_low():
    result = gate_result([_finding("f-critical", "critical")], "high", eval_min_pass_rate=0.9, eval_pass_rate=0.5)
    assert result.ok is False
    assert result.message == (
        "Gate failed: at least one finding severity >= HIGH; eval pass rate 50.0% below minimum 90.0%"
    )


def test_gate_with_eval_minimum_but_no_evaluator_scores_fails_honestly():
    result = gate_result([], "high", eval_min_pass_rate=0.5, eval_pass_rate=None)
    assert result.ok is False
    assert result.eval_ok is False
    assert "eval pass rate unavailable (no evaluator scores)" in result.message
    assert "minimum 50.0%" in result.message


def test_gate_without_eval_minimum_is_unchanged():
    result = gate_result([], "high", eval_pass_rate=0.1)
    assert result.ok is True
    assert result.eval_ok is None
    assert result.message == "Gate passed: no findings severity >= HIGH"


@pytest.mark.parametrize("bad", [-0.1, 1.5])
def test_gate_rejects_eval_minimum_outside_zero_one(bad: float):
    with pytest.raises(ValueError):
        gate_result([], "high", eval_min_pass_rate=bad, eval_pass_rate=1.0)


def test_gate_api_and_cli_accept_eval_min_pass_rate(rich_bundle: Bundle, capsys):
    # rich_bundle has evaluator scores 1/2 passed -> eval_pass_rate 0.5
    client = TestClient(create_app(rich_bundle.orchestrator))
    run_id = rich_bundle.run_id

    passing = client.get(f"/v1/runs/{run_id}/gate", params={"threshold": "critical", "eval_min_pass_rate": 0.5})
    assert passing.status_code == 200
    # the critical promptfoo finding blocks at threshold critical, so ok is False either way
    assert passing.json()["eval_ok"] is True
    assert passing.json()["eval_pass_rate"] == 0.5

    failing = client.get(f"/v1/runs/{run_id}/gate", params={"threshold": "critical", "eval_min_pass_rate": 0.9})
    assert failing.json()["eval_ok"] is False
    assert "eval pass rate 50.0% below minimum 90.0%" in failing.json()["message"]

    assert client.get(f"/v1/runs/{run_id}/gate", params={"eval_min_pass_rate": 2}).status_code == 400

    root = rich_bundle.orchestrator.artifact_store.root_dir
    db = rich_bundle.orchestrator.metadata_store.db_path
    code = main(
        [
            "--artifact-root", str(root), "--metadata-db", str(db),
            "gate", "--run-id", run_id, "--threshold", "info", "--eval-min-pass-rate", "0.9",
        ]
    )
    assert code == 2
    assert "eval pass rate 50.0% below minimum 90.0%" in capsys.readouterr().out


# --- waivers: preview, revoke, history (G9) ---------------------------------------


def _waiver(**overrides) -> dict:
    payload = {
        "waiver_id": "w-1",
        "target_id": TARGET_ID,
        "control_id": "mitigation.MitigationBypass",
        "reason": "known DAN bypass, ticket SEC-142",
        "owner": "sec-lead@example.test",
        "expires_at": FUTURE,
    }
    payload.update(overrides)
    return payload


def test_waiver_preview_reuses_control_matches_semantics(rich_bundle: Bundle):
    client = TestClient(create_app(rich_bundle.orchestrator))
    run_id = rich_bundle.run_id

    by_sub_category = client.get(
        f"/v1/runs/{run_id}/waiver-preview", params={"control_id": "mitigation.MitigationBypass", "target_id": TARGET_ID}
    )
    assert by_sub_category.status_code == 200
    body = by_sub_category.json()
    assert body["count"] == 1
    assert [row["finding_id"] for row in body["matches"]] == [f"{run_id}:{TARGET_ID}:garak:3"]
    assert body["matches"][0]["severity"] == "high"

    # Prefix rule from control_matches(): "LLM01" matches "LLM01:2025 Prompt Injection".
    by_mapping = client.get(f"/v1/runs/{run_id}/waiver-preview", params={"control_id": "LLM01", "target_id": "*"})
    ids = {row["finding_id"] for row in by_mapping.json()["matches"]}
    assert ids == {f"{run_id}:{TARGET_ID}:promptfoo:test:0", f"{run_id}:{TARGET_ID}:deepteam:0"}

    other_target = client.get(
        f"/v1/runs/{run_id}/waiver-preview", params={"control_id": "LLM01", "target_id": "someone-else"}
    )
    assert other_target.json()["count"] == 0

    assert client.get(f"/v1/runs/{run_id}/waiver-preview").status_code == 400
    assert client.get("/v1/runs/nope/waiver-preview", params={"control_id": "x"}).status_code == 404


def test_waiver_create_validates_expiry_and_lists_active_flag(rich_bundle: Bundle):
    client = TestClient(create_app(rich_bundle.orchestrator))
    created = client.post("/v1/waivers", json=_waiver())
    assert created.status_code == 200
    assert created.json()["active"] is True

    expired = client.post("/v1/waivers", json=_waiver(waiver_id="w-old", expires_at="2001-01-01T00:00:00+00:00"))
    assert expired.json()["active"] is False

    bad = client.post("/v1/waivers", json=_waiver(waiver_id="w-bad", expires_at="next tuesday"))
    assert bad.status_code == 400
    assert "expires_at" in bad.json()["detail"]

    listing = client.get("/v1/waivers").json()
    assert {(w["waiver_id"], w["active"]) for w in listing} == {("w-1", True), ("w-old", False)}
    assert [w["waiver_id"] for w in client.get("/v1/waivers", params={"active": "true"}).json()] == ["w-1"]

    one = client.get("/v1/waivers/w-1")
    assert one.status_code == 200
    assert one.json()["events"][0]["event"] == "created"
    assert client.get("/v1/waivers/none").status_code == 404


def test_waiver_revoke_sets_expiry_to_now_and_keeps_history(rich_bundle: Bundle):
    client = TestClient(create_app(rich_bundle.orchestrator))
    run_id = rich_bundle.run_id
    client.post("/v1/waivers", json=_waiver())
    assert client.get(f"/v1/runs/{run_id}/gate", params={"threshold": "high"}).json()["waived"]

    revoked = client.patch("/v1/waivers/w-1", json={"revoke": True})
    assert revoked.status_code == 200
    body = revoked.json()
    assert body["active"] is False
    assert parse_expiry(body["expires_at"]) <= datetime.now(timezone.utc)
    assert body["reason"] == "known DAN bypass, ticket SEC-142"  # nothing else changes

    # The gate no longer applies it, the row still exists (append-only, no delete).
    assert client.get(f"/v1/runs/{run_id}/gate", params={"threshold": "high"}).json()["waived"] == []
    assert [w["waiver_id"] for w in client.get("/v1/waivers").json()] == ["w-1"]
    events = client.get("/v1/waivers/w-1").json()["events"]
    assert [e["event"] for e in events] == ["created", "revoked"]
    assert events[1]["expires_at_before"] == FUTURE

    extended = client.patch("/v1/waivers/w-1", json={"expires_at": FUTURE})
    assert extended.json()["active"] is True
    assert [e["event"] for e in client.get("/v1/waivers/w-1").json()["events"]] == [
        "created", "revoked", "expiry_changed"
    ]

    assert client.patch("/v1/waivers/w-1", json={"expires_at": "soon"}).status_code == 400
    assert client.patch("/v1/waivers/w-1", json={"owner": "someone"}).status_code == 400
    assert client.patch("/v1/waivers/missing", json={"revoke": True}).status_code == 404
    assert client.delete("/v1/waivers/w-1").status_code == 405


def test_urt_waivers_revoke_cli(rich_bundle: Bundle, capsys):
    orch = rich_bundle.orchestrator
    orch.create_waiver(_waiver())
    base = ["--artifact-root", str(orch.artifact_store.root_dir), "--metadata-db", str(orch.metadata_store.db_path)]
    assert main([*base, "waivers", "revoke", "--waiver-id", "w-1"]) == 0
    out = capsys.readouterr().out
    assert '"active": false' in out
    assert main([*base, "waivers", "revoke", "--waiver-id", "nope"]) == 1


def test_ui_gate_fragment_reflects_eval_min_pass_rate(rich_bundle: Bundle):
    client = TestClient(create_app(rich_bundle.orchestrator))
    run_id = rich_bundle.run_id
    fragment = client.get(f"/ui/runs/{run_id}/gate", params={"threshold": "info", "eval_min_pass_rate": "0.9"})
    assert fragment.status_code == 200
    assert "eval pass rate 50.0% below minimum 90.0%" in fragment.text
    assert 'name="eval_min_pass_rate"' in client.get(f"/ui/runs/{run_id}").text
    assert client.get(f"/ui/runs/{run_id}/gate", params={"eval_min_pass_rate": "abc"}).status_code == 400
