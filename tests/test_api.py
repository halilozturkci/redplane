"""FastAPI control-plane contract tests (G12, #17).

`POST /v1/runs` is synchronous: validation errors are 400 before anything is
persisted, execution failures are 500 after the run was recorded as failed.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import sys
import zipfile
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


@pytest.fixture
def completed_run(client: TestClient) -> str:
    response = client.post("/v1/runs", json=passing_spec())
    assert response.status_code == 200
    return response.json()["run_id"]


def test_bundle_read_endpoints_return_file_content(client: TestClient, completed_run: str, orchestrator: Orchestrator):
    run_dir = Path(orchestrator.artifact_store.root_dir) / completed_run

    scorecard = client.get(f"/v1/runs/{completed_run}/scorecard")
    assert scorecard.status_code == 200
    assert scorecard.json() == json.loads((run_dir / "scorecard.json").read_text(encoding="utf-8"))
    assert scorecard.json()["run_id"] == completed_run

    summary = client.get(f"/v1/runs/{completed_run}/summary")
    assert summary.status_code == 200
    assert summary.json()["engines"] == ["garak"]
    assert summary.json()["targets"] == ["local-http"]
    assert summary.json()["engine_summaries"][0]["status"] == "completed"

    manifest = client.get(f"/v1/runs/{completed_run}/manifest")
    assert manifest.status_code == 200
    assert manifest.json()["bundle_format_version"] == "1.1"
    assert manifest.json()["status"] == "completed"
    assert "duration_seconds" in manifest.json()

    invocations = client.get(f"/v1/runs/{completed_run}/invocations")
    assert invocations.status_code == 200
    assert [item["engine"] for item in invocations.json()] == ["garak"]
    assert {"started_at", "ended_at", "duration_seconds", "status", "fail_open"} <= set(invocations.json()[0])


@pytest.mark.parametrize("name", ["scorecard", "summary", "manifest", "invocations"])
def test_bundle_read_endpoints_404_for_unknown_run(client: TestClient, name: str):
    response = client.get(f"/v1/runs/missing/{name}")
    assert response.status_code == 404
    assert response.json()["detail"] == "Run not found"


def test_bundle_read_endpoints_404_when_file_is_absent_for_failed_run(client: TestClient):
    failed = client.post("/v1/runs", json=failing_spec()).json()["detail"]
    run_id = failed["run_id"]

    assert client.get(f"/v1/runs/{run_id}/manifest").status_code == 200
    assert client.get(f"/v1/runs/{run_id}/manifest").json()["status"] == "failed"
    for name in ("scorecard", "summary", "invocations"):
        response = client.get(f"/v1/runs/{run_id}/{name}")
        assert response.status_code == 404, name
        assert "not available" in response.json()["detail"]


def test_artifact_download_serves_bundle_files_with_safe_headers(client: TestClient, completed_run: str, orchestrator: Orchestrator):
    run_dir = Path(orchestrator.artifact_store.root_dir) / completed_run

    scorecard = client.get(f"/v1/runs/{completed_run}/artifacts/scorecard.json")
    assert scorecard.status_code == 200
    assert scorecard.headers["content-type"].startswith("application/json")
    assert scorecard.headers["x-content-type-options"] == "nosniff"
    assert scorecard.content == (run_dir / "scorecard.json").read_bytes()

    report_md = client.get(f"/v1/runs/{completed_run}/artifacts/report.md")
    assert report_md.status_code == 200
    assert report_md.headers["content-type"].startswith("text/")

    nested = client.get(f"/v1/runs/{completed_run}/artifacts/raw/garak/local-http_stdout.log")
    assert nested.status_code == 200
    assert b"garak-ok" in nested.content

    html = client.get(f"/v1/runs/{completed_run}/artifacts/report.html")
    assert html.status_code == 200
    assert "attachment" in html.headers["content-disposition"]

    unknown = orchestrator.artifact_store.write_bytes(completed_run, "raw/blob.bin", b"\x00\x01")
    assert Path(unknown).exists()
    blob = client.get(f"/v1/runs/{completed_run}/artifacts/raw/blob.bin")
    assert blob.status_code == 200
    assert blob.headers["content-type"] == "application/octet-stream"
    assert "attachment" in blob.headers["content-disposition"]


@pytest.mark.parametrize(
    "relative_path",
    # `./x` is normalized away by the HTTP client before it reaches the server; the
    # server-side rejection of "." segments is covered in test_artifact_path_guard.py.
    ["../other/report.md", "raw/../../x", "raw//x", "%2e%2e/x", "raw/%2e%2e/%2e%2e/x"],
)
def test_artifact_download_rejects_traversal(client: TestClient, completed_run: str, relative_path: str):
    response = client.get(f"/v1/runs/{completed_run}/artifacts/{relative_path}")
    assert response.status_code in {400, 404}
    if response.status_code == 400:
        assert "artifact path" in response.json()["detail"].lower()


def test_artifact_download_404s_for_missing_file_and_unknown_run(client: TestClient, completed_run: str):
    missing = client.get(f"/v1/runs/{completed_run}/artifacts/nope.json")
    assert missing.status_code == 404
    assert missing.json()["detail"] == "Artifact not found"
    assert client.get("/v1/runs/missing/artifacts/scorecard.json").status_code == 404


def test_artifact_zip_matches_the_index(client: TestClient, completed_run: str):
    response = client.get(f"/v1/runs/{completed_run}/artifacts.zip")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    assert f'filename="{completed_run}.zip"' in response.headers["content-disposition"]

    index = {item["path"]: item for item in client.get(f"/v1/runs/{completed_run}/artifacts").json()}
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        names = archive.namelist()
        assert all(name.startswith(f"{completed_run}/") for name in names)
        relative = {name.split("/", 1)[1] for name in names}
        assert relative == set(index)
        for rel, meta in index.items():
            if rel == "artifacts_index.json":
                continue  # the index cannot contain its own final hash
            assert hashlib.sha256(archive.read(f"{completed_run}/{rel}")).hexdigest() == meta["sha256"]

    assert client.get("/v1/runs/missing/artifacts.zip").status_code == 404


def test_findings_expose_bundle_relative_evidence_paths(client: TestClient, completed_run: str):
    findings = client.get(f"/v1/runs/{completed_run}/findings").json()
    execution = next(item for item in findings if item["sub_category"] == "engine_runtime")

    assert len(execution["evidence_artifacts"]) == len(execution["evidence_refs"])
    assert execution["evidence_artifacts"] == [
        "raw/garak/local-http_stdout.log",
        "raw/garak/local-http_stderr.log",
    ]
    for rel in execution["evidence_artifacts"]:
        assert client.get(f"/v1/runs/{completed_run}/artifacts/{rel}").status_code == 200


LEGACY_SECRET = "legacy-bearer-token-from-a-1.0-bundle"


@pytest.fixture
def legacy_run(client: TestClient, orchestrator: Orchestrator, completed_run: str) -> str:
    """A pre-1.1 bundle as found on an operator's disk: version 1.0, credentials on disk
    and in SQLite finding metadata (the `env_overrides` shape that 1.0 wrote)."""
    run_dir = Path(orchestrator.artifact_store.root_dir) / completed_run
    manifest = json.loads((run_dir / "run_manifest.json").read_text(encoding="utf-8"))
    manifest["bundle_format_version"] = "1.0"
    manifest["targets"][0]["auth"] = {"headers": {"Authorization": f"Bearer {LEGACY_SECRET}"}}
    (run_dir / "run_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    resolved = json.loads((run_dir / "resolved_spec.json").read_text(encoding="utf-8"))
    resolved["targets"][0]["auth"] = {"headers": {"Authorization": f"Bearer {LEGACY_SECRET}"}}
    (run_dir / "resolved_spec.json").write_text(json.dumps(resolved), encoding="utf-8")

    summary = json.loads((run_dir / "run_summary.json").read_text(encoding="utf-8"))
    summary["engine_summaries"][0]["metrics"]["api_key"] = LEGACY_SECRET
    summary["engine_summaries"][0]["metrics"]["command"] = ["tool", "--api-key", LEGACY_SECRET]
    (run_dir / "run_summary.json").write_text(json.dumps(summary), encoding="utf-8")

    invocations = json.loads((run_dir / "engine_invocations.json").read_text(encoding="utf-8"))
    invocations[0]["metrics"]["bearer_token"] = LEGACY_SECRET
    invocations[0]["metrics"]["command"] = ["tool", "--api-key", LEGACY_SECRET]
    (run_dir / "engine_invocations.json").write_text(json.dumps(invocations), encoding="utf-8")

    sidecar = run_dir / "raw" / "custom_script" / "local-http_engine_findings.json"
    sidecar.parent.mkdir(parents=True, exist_ok=True)
    sidecar.write_text(json.dumps({"engine_findings": [{"metadata": {"env_overrides": {"ECHO": LEGACY_SECRET}}}]}), encoding="utf-8")
    (run_dir / "raw" / "garak" / "local-http_stdout.log").write_text(f"tool printed {LEGACY_SECRET}\n", encoding="utf-8")

    findings = orchestrator.metadata_store.get_findings(completed_run)
    # 1.0 wrote the env dict; `ECHO` matches no key heuristic, only its position does.
    findings[0]["metadata"]["env_overrides"] = {"OPENAI_API_KEY": LEGACY_SECRET, "ECHO": LEGACY_SECRET}
    findings[0]["metadata"]["command"] = ["tool", "--api-key", LEGACY_SECRET]
    from urt.types import UnifiedFinding

    orchestrator.metadata_store.insert_findings(
        [UnifiedFinding(**{k: v for k, v in findings[0].items() if k != "evidence_artifacts"})]
    )
    return completed_run


def test_bundle_json_endpoints_redact_legacy_content_at_read_time(client: TestClient, legacy_run: str):
    manifest = client.get(f"/v1/runs/{legacy_run}/manifest")
    assert manifest.status_code == 200
    assert LEGACY_SECRET not in manifest.text
    assert manifest.json()["targets"][0]["auth"]["headers"]["Authorization"] == "***REDACTED***"
    assert manifest.json()["bundle_format_version"] == "1.0"

    summary = client.get(f"/v1/runs/{legacy_run}/summary")
    assert LEGACY_SECRET not in summary.text
    assert summary.json()["engine_summaries"][0]["metrics"]["api_key"] == "***REDACTED***"
    # Pre-1.1 argv was never scrubbed, so it is masked by position on read.
    assert summary.json()["engine_summaries"][0]["metrics"]["command"] == ["***REDACTED***"] * 3

    invocations = client.get(f"/v1/runs/{legacy_run}/invocations")
    assert LEGACY_SECRET not in invocations.text
    assert invocations.json()[0]["metrics"]["bearer_token"] == "***REDACTED***"
    assert invocations.json()[0]["metrics"]["command"] == ["***REDACTED***"] * 3

    findings = client.get(f"/v1/runs/{legacy_run}/findings")
    assert LEGACY_SECRET not in findings.text
    leaked = next(f for f in findings.json() if "env_overrides" in f["metadata"])
    # The whole legacy env dict is masked by position, whatever the key names.
    assert leaked["metadata"]["env_overrides"] == {"OPENAI_API_KEY": "***REDACTED***", "ECHO": "***REDACTED***"}
    assert leaked["metadata"]["command"] == ["***REDACTED***"] * 3

    runs = client.get("/v1/runs")
    assert LEGACY_SECRET not in runs.text


def test_current_bundles_keep_argv_visible_on_read(client: TestClient, completed_run: str):
    summary = client.get(f"/v1/runs/{completed_run}/summary").json()
    assert summary["engine_summaries"][0]["metrics"]["command"][0] == PYTHON
    findings = client.get(f"/v1/runs/{completed_run}/findings").json()
    execution = next(item for item in findings if item["sub_category"] == "engine_runtime")
    assert execution["metadata"]["command"][0] == PYTHON


@pytest.mark.parametrize(
    "relative_path",
    [
        "resolved_spec.json",
        "run_manifest.json",
        "findings.json",
        "run_summary.json",
        "engine_invocations.json",
        "raw/custom_script/local-http_engine_findings.json",
        "raw/garak/local-http_stdout.log",
    ],
)
def test_raw_download_is_refused_for_legacy_bundles_unless_allowlisted(
    client: TestClient, legacy_run: str, relative_path: str
):
    response = client.get(f"/v1/runs/{legacy_run}/artifacts/{relative_path}")
    assert response.status_code == 409
    assert "1.0" in response.json()["detail"]
    assert "1.1" in response.json()["detail"]
    assert LEGACY_SECRET not in response.text


@pytest.mark.parametrize(
    "relative_path", ["scorecard.json", "artifacts_index.json", "report.md", "report.html", "report.csv"]
)
def test_legacy_bundle_allowlisted_files_still_download(client: TestClient, legacy_run: str, relative_path: str):
    response = client.get(f"/v1/runs/{legacy_run}/artifacts/{relative_path}")
    assert response.status_code == 200
    assert LEGACY_SECRET not in response.text


def test_zip_is_refused_for_legacy_bundles(client: TestClient, legacy_run: str):
    archive = client.get(f"/v1/runs/{legacy_run}/artifacts.zip")
    assert archive.status_code == 409
    assert LEGACY_SECRET not in archive.text


def test_run_rows_mask_sqlite_error_message_for_legacy_runs(legacy_failed_bundle, failed_bundle):
    from conftest import LEGACY_SECRET

    # legacy_failed_bundle mutates failed_bundle in place, so this client sees one
    # legacy (1.0) failed run whose SQLite error_message carries argv with a secret.
    api = TestClient(create_app(legacy_failed_bundle.orchestrator))
    run_id = legacy_failed_bundle.run_id

    listed = api.get("/v1/runs")
    assert listed.status_code == 200
    assert LEGACY_SECRET not in listed.text
    [row] = [r for r in listed.json() if r["run_id"] == run_id]
    assert row["error_message"] == "***REDACTED***"
    assert row["bundle_format_version"] == "1.0"

    single = api.get(f"/v1/runs/{run_id}")
    assert single.status_code == 200
    assert LEGACY_SECRET not in single.text
    assert single.json()["error_message"] == "***REDACTED***"


def test_run_rows_keep_error_message_for_current_bundles(client: TestClient):
    failed = client.post("/v1/runs", json=failing_spec()).json()["detail"]
    row = client.get(f"/v1/runs/{failed['run_id']}").json()
    assert "fail_open=false" in row["error_message"]
    [listed] = client.get("/v1/runs").json()
    assert listed["error_message"] == row["error_message"]


def test_inline_artifact_responses_carry_csp_and_no_store(client: TestClient, completed_run: str):
    for rel in ("scorecard.json", "report.md", "raw/garak/local-http_stdout.log"):
        response = client.get(f"/v1/runs/{completed_run}/artifacts/{rel}")
        assert response.status_code == 200, rel
        assert response.headers["content-security-policy"] == "default-src 'none'; sandbox", rel
        assert response.headers["cache-control"] == "no-store", rel
        assert response.headers["x-content-type-options"] == "nosniff", rel


def test_run_id_slug_is_filesystem_and_header_safe(client: TestClient):
    response = client.post("/v1/runs", json=passing_spec(name='Weird "Name"/with\\odd chars\n'))
    assert response.status_code == 200
    run_id = response.json()["run_id"]
    assert re.fullmatch(r"run-[a-z0-9._-]+", run_id), run_id

    archive = client.get(f"/v1/runs/{run_id}/artifacts.zip")
    assert archive.status_code == 200
    assert archive.headers["content-disposition"] == f'attachment; filename="{run_id}.zip"'


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
