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


# --- /ui/waivers ---------------------------------------------------------------------


def _csrf(client: TestClient, path: str = "/ui/waivers/new") -> str:
    page = client.get(path)
    assert page.status_code == 200
    import re

    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    assert client.cookies.get("urt_csrf") == token
    return token


def test_ui_waivers_list_shows_state_and_match_preview_for_a_run(rich_bundle: Bundle):
    client = TestClient(create_app(rich_bundle.orchestrator))
    orch = rich_bundle.orchestrator
    orch.create_waiver(_waiver(reason="<b>bold</b> reason"))
    orch.create_waiver(_waiver(waiver_id="w-old", control_id="LLM01", expires_at="2001-01-01T00:00:00+00:00"))

    page = client.get("/ui/waivers")
    assert page.status_code == 200
    assert "&lt;b&gt;bold&lt;/b&gt; reason" in page.text and "<b>bold</b>" not in page.text
    assert 'class="badge ok">active' in page.text
    assert 'class="badge skipped">expired' in page.text
    assert "finding in this run" not in page.text  # no run selected: no preview column

    scoped = client.get("/ui/waivers", params={"run_id": rich_bundle.run_id})
    assert scoped.status_code == 200
    assert "matches 1 finding in this run" in scoped.text  # w-1 -> garak:3
    assert "matches 2 findings in this run" in scoped.text  # w-old (expired, still previewed) -> LLM01 prefix
    assert f'action="/ui/waivers/w-1/revoke"' in scoped.text
    assert f'action="/ui/waivers/w-old/revoke"' not in scoped.text  # already expired
    assert client.get("/ui/waivers", params={"run_id": "nope"}).status_code == 404


def test_ui_create_waiver_from_finding_prefills_and_previews(rich_bundle: Bundle):
    client = TestClient(create_app(rich_bundle.orchestrator))
    run_id = rich_bundle.run_id
    finding_id = f"{run_id}:{TARGET_ID}:promptfoo:test:0"

    drawer = client.get(f"/ui/runs/{run_id}/findings/detail", params={"finding_id": finding_id})
    link = f"/ui/waivers/new?run_id={run_id}&amp;finding_id="
    assert link in drawer.text

    form = client.get("/ui/waivers/new", params={"run_id": run_id, "finding_id": finding_id})
    assert form.status_code == 200
    assert f'name="target_id" value="{TARGET_ID}"' in form.text
    for choice in ("prompt_injection", "promptfoo:harmful:privacy", "LLM01:2025 Prompt Injection", finding_id):
        assert f'name="control_id" value="{choice}"' in form.text, choice
    assert 'name="reason" required' in form.text and 'name="owner" required' in form.text
    default_expiry = parse_expiry(
        __import__("re").search(r'name="expires_at" value="([^"]+)" required', form.text).group(1)
    )
    delta = default_expiry - datetime.now(timezone.utc)
    assert timedelta(days=29, hours=23) < delta < timedelta(days=30, hours=1)
    assert "No Run button" not in form.text

    preview = client.get(
        f"/ui/runs/{run_id}/waiver-preview", params={"control_id": "prompt_injection", "target_id": TARGET_ID}
    )
    assert preview.status_code == 200
    assert preview.text.lstrip().startswith('<div id="waiver-preview"')
    assert "matches 2 findings in this run" in preview.text
    assert f"{run_id}:{TARGET_ID}:deepteam:0" in preview.text
    assert client.get("/ui/waivers/new", params={"run_id": run_id, "finding_id": "nope"}).status_code == 404


def test_ui_waiver_create_and_revoke_require_csrf(rich_bundle: Bundle):
    client = TestClient(create_app(rich_bundle.orchestrator))
    run_id = rich_bundle.run_id
    payload = {
        "run_id": run_id,
        "target_id": TARGET_ID,
        "control_id": "mitigation.MitigationBypass",
        "reason": "ticket SEC-142",
        "owner": "sec-lead",
        "expires_at": FUTURE,
    }
    # No token at all.
    assert client.post("/ui/waivers", data=payload).status_code == 403
    token = _csrf(client)
    # Wrong token.
    assert client.post("/ui/waivers", data={**payload, "csrf_token": "x" * 43}).status_code == 403
    # Cross-site origin with a valid token.
    cross = client.post(
        "/ui/waivers", data={**payload, "csrf_token": token}, headers={"Origin": "https://evil.example"}
    )
    assert cross.status_code == 403
    # JSON / multipart bodies are not accepted on the form route.
    assert client.post("/ui/waivers", json={**payload, "csrf_token": token}).status_code == 415
    assert rich_bundle.orchestrator.list_waivers() == []

    created = client.post("/ui/waivers", data={**payload, "csrf_token": token}, follow_redirects=False)
    assert created.status_code == 303
    assert created.headers["location"] == f"/ui/waivers?run_id={run_id}"
    stored = rich_bundle.orchestrator.list_waivers()
    assert len(stored) == 1 and stored[0]["control_id"] == "mitigation.MitigationBypass"
    waiver_id = stored[0]["waiver_id"]
    assert "(1 waived)" in client.get(f"/v1/runs/{run_id}/gate").json()["message"]

    missing_reason = client.post("/ui/waivers", data={**payload, "reason": " ", "csrf_token": token})
    assert missing_reason.status_code == 400
    assert "reason" in missing_reason.text

    assert client.post(f"/ui/waivers/{waiver_id}/revoke", data={}).status_code == 403
    revoked = client.post(
        f"/ui/waivers/{waiver_id}/revoke", data={"csrf_token": token, "run_id": run_id}, follow_redirects=False
    )
    assert revoked.status_code == 303
    assert rich_bundle.orchestrator.get_waiver(waiver_id)["active"] is False
    assert "waived" not in client.get(f"/v1/runs/{run_id}/gate").json()["message"]
    assert client.post("/ui/waivers/none/revoke", data={"csrf_token": token}).status_code == 404
    # Nothing on the UI deletes.
    assert client.delete(f"/ui/waivers/{waiver_id}").status_code in {404, 405}


def test_ui_gate_fragment_reflects_eval_min_pass_rate(rich_bundle: Bundle):
    client = TestClient(create_app(rich_bundle.orchestrator))
    run_id = rich_bundle.run_id
    fragment = client.get(f"/ui/runs/{run_id}/gate", params={"threshold": "info", "eval_min_pass_rate": "0.9"})
    assert fragment.status_code == 200
    assert "eval pass rate 50.0% below minimum 90.0%" in fragment.text
    assert 'name="eval_min_pass_rate"' in client.get(f"/ui/runs/{run_id}").text
    assert client.get(f"/ui/runs/{run_id}/gate", params={"eval_min_pass_rate": "abc"}).status_code == 400
