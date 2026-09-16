"""FastAPI control-plane contract tests (G12, #17).

`POST /v1/runs` is synchronous: validation errors are 400 before anything is
persisted, execution failures are 500 after the run was recorded as failed.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from urt.api import create_app
from urt.orchestrator import Orchestrator

PYTHON = sys.executable


def _spec(*, engine_command: str, fail_open: bool = True, name: str = "api-smoke") -> dict:
    return {
        "name": name,
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
            {"name": "garak", "fail_open": fail_open, "params": {"command": engine_command}},
        ],
    }


def passing_spec(name: str = "api-smoke") -> dict:
    return _spec(engine_command=f"{PYTHON} -c \"print('garak-ok')\"", name=name)


def failing_spec() -> dict:
    return _spec(engine_command=f'{PYTHON} -c "raise SystemExit(3)"', fail_open=False, name="api-fail")


@pytest.fixture
def orchestrator(tmp_path: Path) -> Orchestrator:
    return Orchestrator(
        artifact_root=str(tmp_path / "artifacts"),
        metadata_db=str(tmp_path / "meta.sqlite3"),
    )


@pytest.fixture
def client(orchestrator: Orchestrator) -> TestClient:
    return TestClient(create_app(orchestrator))


def test_healthz(client: TestClient):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_create_run_rejects_invalid_spec_with_400_and_persists_nothing(client: TestClient):
    response = client.post("/v1/runs", json={"name": "no-targets", "engines": [{"name": "garak"}]})
    assert response.status_code == 400
    assert "target" in response.json()["detail"].lower()

    response = client.post(
        "/v1/runs",
        json={**passing_spec(), "engines": [{"name": "not-an-engine"}]},
    )
    assert response.status_code == 400
    assert "Unsupported engine" in response.json()["detail"]

    assert client.get("/v1/runs").json() == []


def test_create_run_reports_execution_failure_with_500_and_records_the_run(client: TestClient):
    response = client.post("/v1/runs", json=failing_spec())
    assert response.status_code == 500

    detail = response.json()["detail"]
    assert detail["status"] == "failed"
    assert detail["run_id"].startswith("run-api-fail-")
    assert "fail_open=false" in detail["error"]

    recorded = client.get(f"/v1/runs/{detail['run_id']}")
    assert recorded.status_code == 200
    assert recorded.json()["status"] == "failed"
    assert recorded.json()["error_message"] == detail["error"]


def test_create_run_completes_synchronously_and_is_readable(client: TestClient):
    response = client.post("/v1/runs", json=passing_spec())
    assert response.status_code == 200

    body = response.json()
    run_id = body["run_id"]
    assert body["status"] == "completed"
    assert body["scorecard"]["run_id"] == run_id
    assert body["scorecard"]["total_findings"] >= 1

    listed = client.get("/v1/runs")
    assert listed.status_code == 200
    assert [row["run_id"] for row in listed.json()] == [run_id]

    single = client.get(f"/v1/runs/{run_id}")
    assert single.status_code == 200
    assert single.json()["status"] == "completed"
    assert single.json()["name"] == "api-smoke"

    findings = client.get(f"/v1/runs/{run_id}/findings")
    assert findings.status_code == 200
    assert findings.json()
    assert all(item["run_id"] == run_id for item in findings.json())
    assert findings.json()[0]["engine"] == "garak"

    artifacts = client.get(f"/v1/runs/{run_id}/artifacts")
    assert artifacts.status_code == 200
    paths = {item["path"] for item in artifacts.json()}
    assert {"run_manifest.json", "findings.json", "scorecard.json", "report.html"} <= paths
    assert all({"path", "size_bytes", "sha256"} <= set(item) for item in artifacts.json())


@pytest.mark.parametrize("suffix", ["", "/findings", "/artifacts"])
def test_unknown_run_is_404(client: TestClient, suffix: str):
    response = client.get(f"/v1/runs/does-not-exist{suffix}")
    assert response.status_code == 404
    assert response.json()["detail"] == "Run not found"


def test_waivers_validate_create_and_filter(client: TestClient):
    missing = client.post("/v1/waivers", json={"target_id": "t1", "control_id": "prompt_injection"})
    assert missing.status_code == 400
    assert "reason" in missing.json()["detail"]
    assert "owner" in missing.json()["detail"]
    assert "expires_at" in missing.json()["detail"]

    payload = {
        "target_id": "t1",
        "control_id": "prompt_injection",
        "reason": "accepted risk during pilot",
        "owner": "sec-lead",
        "expires_at": "2099-01-01T00:00:00+00:00",
    }
    created = client.post("/v1/waivers", json=payload)
    assert created.status_code == 200
    assert created.json()["waiver_id"]
    assert {k: created.json()[k] for k in payload} == payload

    other = client.post("/v1/waivers", json={**payload, "target_id": "t2", "waiver_id": "w-t2"})
    assert other.status_code == 200
    assert other.json()["waiver_id"] == "w-t2"

    assert len(client.get("/v1/waivers").json()) == 2
    filtered = client.get("/v1/waivers", params={"target_id": "t2"}).json()
    assert [item["waiver_id"] for item in filtered] == ["w-t2"]
