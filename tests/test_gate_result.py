"""G3: the gate verdict must say which findings block and which were waived."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from urt.api import create_app
from urt.cli import main
from urt.orchestrator import Orchestrator
from urt.report import GateResult, evaluate_gate, gate_result
from urt.types import RunSpec, UnifiedFinding

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
        mappings={"owasp_llm": ["LLM01:2025 Prompt Injection"]},
    )


def test_gate_result_lists_blocking_and_waived_findings():
    findings = [
        _finding("f-critical", "critical"),
        _finding("f-high", "high", category="data_leak"),
        _finding("f-medium", "medium"),
    ]
    waiver = {
        "waiver_id": "w1",
        "target_id": "t1",
        "control_id": "data_leak",
        "owner": "sec-lead",
        "expires_at": FUTURE,
    }

    result = gate_result(findings, "high", waivers=[waiver])

    assert isinstance(result, GateResult)
    assert result.ok is False
    assert result.threshold == "high"
    assert [item["finding_id"] for item in result.blocking] == ["f-critical"]
    assert result.blocking[0]["severity"] == "critical"
    assert result.blocking[0]["target_id"] == "t1"
    assert result.blocking[0]["category"] == "prompt_injection"
    assert [item["finding_id"] for item in result.waived] == ["f-high"]
    assert result.waived[0]["waiver_id"] == "w1"
    assert result.waived[0]["control_id"] == "data_leak"
    assert result.waived[0]["owner"] == "sec-lead"
    assert result.message == "Gate failed: at least one finding severity >= HIGH (1 waived)"

    as_dict = result.to_dict()
    assert set(as_dict) >= {"ok", "threshold", "message", "blocking", "waived", "waivers_considered"}
    assert as_dict["blocking"][0]["finding_id"] == "f-critical"
    # "considered" = waivers were supplied to the evaluation, not "a waiver matched".
    assert result.waivers_considered is True
    assert gate_result(findings, "high").waivers_considered is False
    assert "waivers_applied" not in as_dict
    assert GateResult.from_dict(as_dict) == result


def test_gate_result_blocking_is_sorted_by_severity_then_id():
    findings = [
        _finding("b-high", "high"),
        _finding("a-critical", "critical"),
        _finding("a-high", "high"),
    ]
    result = gate_result(findings, "high")
    assert [item["finding_id"] for item in result.blocking] == ["a-critical", "a-high", "b-high"]


def test_gate_result_passes_when_everything_is_waived_or_below_threshold():
    findings = [_finding("f-high", "high"), _finding("f-low", "low")]
    waiver = {"waiver_id": "w1", "target_id": "*", "control_id": "LLM01", "expires_at": FUTURE}

    result = gate_result(findings, "high", waivers=[waiver])

    assert result.ok is True
    assert result.blocking == []
    assert [item["finding_id"] for item in result.waived] == ["f-high"]
    assert result.message.startswith("Gate passed: 1 finding(s) waived")

    ok, message = evaluate_gate(findings, "high", waivers=[waiver])
    assert (ok, message) == (result.ok, result.message)


def test_gate_result_rejects_unknown_threshold():
    with pytest.raises(ValueError):
        gate_result([], "severe")


def _completed_run(tmp_path: Path) -> tuple[Orchestrator, str]:
    orchestrator = Orchestrator(
        artifact_root=str(tmp_path / "artifacts"),
        metadata_db=str(tmp_path / "meta.sqlite3"),
    )
    spec = RunSpec.from_dict(
        {
            "name": "gate-smoke",
            "run_profile": "pr_gate",
            "targets": [
                {
                    "id": "local-http",
                    "type": "http",
                    "endpoint": "http://localhost:9999/invoke",
                    "config": {"skip_healthcheck": True},
                }
            ],
            "engines": [
                {"name": "garak", "params": {"command": f"{sys.executable} -c \"print('ok')\""}}
            ],
        }
    )
    result = orchestrator.execute(spec)
    assert result["status"] == "completed"
    return orchestrator, result["run_id"]


def test_cli_gate_explain_prints_blocking_and_waived_findings(tmp_path: Path, capsys):
    orchestrator, run_id = _completed_run(tmp_path)
    findings = orchestrator.get_findings(run_id)
    assert findings
    common = ["--artifact-root", str(tmp_path / "artifacts"), "--metadata-db", str(tmp_path / "meta.sqlite3")]

    exit_code = main([*common, "gate", "--run-id", run_id, "--threshold", "info", "--explain"])
    out = capsys.readouterr().out
    assert exit_code == 2
    assert out.startswith("Gate failed:")
    assert f"Blocking findings ({len(findings)}):" in out
    for item in findings:
        assert item["finding_id"] in out
    assert "Waived findings (0)" in out

    orchestrator.create_waiver(
        {
            "waiver_id": "w-exec",
            "target_id": "local-http",
            "control_id": "execution",
            "reason": "launcher smoke",
            "owner": "sec-lead",
            "expires_at": FUTURE,
        }
    )
    exit_code = main([*common, "gate", "--run-id", run_id, "--threshold", "info", "--explain"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert out.startswith("Gate passed:")
    assert "Blocking findings (0)" in out
    assert f"Waived findings ({len(findings)}):" in out
    assert "waiver=w-exec" in out
    assert "owner=sec-lead" in out

    exit_code = main([*common, "gate", "--run-id", run_id, "--threshold", "info"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "Blocking findings" not in out


def test_api_gate_endpoint_returns_structured_verdict(tmp_path: Path):
    orchestrator, run_id = _completed_run(tmp_path)
    client = TestClient(create_app(orchestrator))
    findings = orchestrator.get_findings(run_id)

    response = client.get(f"/v1/runs/{run_id}/gate", params={"threshold": "info"})
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is False
    assert body["threshold"] == "info"
    assert sorted(item["finding_id"] for item in body["blocking"]) == sorted(
        item["finding_id"] for item in findings
    )
    assert body["waived"] == []

    client.post(
        "/v1/waivers",
        json={
            "waiver_id": "w-exec",
            "target_id": "local-http",
            "control_id": "execution",
            "reason": "launcher smoke",
            "owner": "sec-lead",
            "expires_at": FUTURE,
        },
    )
    waived = client.get(f"/v1/runs/{run_id}/gate", params={"threshold": "info"}).json()
    assert waived["ok"] is True
    assert waived["blocking"] == []
    assert {item["waiver_id"] for item in waived["waived"]} == {"w-exec"}

    ignored = client.get(
        f"/v1/runs/{run_id}/gate", params={"threshold": "info", "ignore_waivers": "true"}
    ).json()
    assert ignored["ok"] is False
    assert ignored["waived"] == []

    default_threshold = client.get(f"/v1/runs/{run_id}/gate").json()
    assert default_threshold["threshold"] == "high"

    assert client.get(f"/v1/runs/{run_id}/gate", params={"threshold": "severe"}).status_code == 400
    assert client.get("/v1/runs/missing/gate").status_code == 404


def test_api_gate_endpoint_404s_when_findings_are_not_available(tmp_path: Path):
    orchestrator = Orchestrator(
        artifact_root=str(tmp_path / "artifacts"),
        metadata_db=str(tmp_path / "meta.sqlite3"),
    )
    failing = RunSpec.from_dict(
        {
            "name": "gate-fail",
            "run_profile": "pr_gate",
            "targets": [
                {
                    "id": "local-http",
                    "type": "http",
                    "endpoint": "http://localhost:9999/invoke",
                    "config": {"skip_healthcheck": True},
                }
            ],
            "engines": [
                {
                    "name": "garak",
                    "fail_open": False,
                    "params": {"command": f'{sys.executable} -c "raise SystemExit(3)"'},
                }
            ],
        }
    )
    result = orchestrator.execute(failing)
    assert result["status"] == "failed"

    client = TestClient(create_app(orchestrator))
    response = client.get(f"/v1/runs/{result['run_id']}/gate")
    assert response.status_code == 404
    assert "findings" in response.json()["detail"].lower()
    assert json.loads(response.text)["detail"] != "Run not found"
