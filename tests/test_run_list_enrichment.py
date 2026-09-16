"""G6: run rows carry what the runs screen needs; findings sort by severity rank."""

from __future__ import annotations

import sys
from pathlib import Path

from fastapi.testclient import TestClient

from urt.api import create_app
from urt.orchestrator import Orchestrator
from urt.storage.metadata_store import MetadataStore
from urt.types import RunRecord, RunSpec, UnifiedFinding

PYTHON = sys.executable


def _finding(finding_id: str, severity: str) -> UnifiedFinding:
    return UnifiedFinding(
        finding_id=finding_id,
        run_id="r1",
        target_id="t1",
        engine="pyrit",
        category="prompt_injection",
        sub_category=None,
        severity=severity,
        confidence=0.5,
        attack_vector="x",
        attack_complexity="x",
        success=True,
        description=severity,
    )


def test_get_findings_orders_by_severity_rank_not_lexically(tmp_path: Path):
    store = MetadataStore(tmp_path / "meta.sqlite3")
    store.create_run(
        RunRecord(run_id="r1", name="n", profile="nightly", status="completed", created_at="t", updated_at="t")
    )
    store.insert_findings(
        [
            _finding("b-info", "info"),
            _finding("a-low", "low"),
            _finding("z-medium", "medium"),
            _finding("b-high", "high"),
            _finding("a-high", "high"),
            _finding("c-critical", "critical"),
        ]
    )

    ordered = [item["finding_id"] for item in store.get_findings("r1")]

    # Lexical DESC would give medium > low > info > high > critical.
    assert ordered == ["c-critical", "a-high", "b-high", "z-medium", "a-low", "b-info"]


def _spec(name: str, *, engines: list[dict]) -> RunSpec:
    return RunSpec.from_dict(
        {
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
            "engines": engines,
        }
    )


def test_list_runs_is_enriched_from_the_bundle(tmp_path: Path):
    orchestrator = Orchestrator(
        artifact_root=str(tmp_path / "artifacts"),
        metadata_db=str(tmp_path / "meta.sqlite3"),
    )
    completed = orchestrator.execute(
        _spec(
            "enriched",
            engines=[
                {"name": "garak", "params": {"command": f"{PYTHON} -c \"print('ok')\""}},
                {"name": "promptfoo", "params": {"command": "urt-missing-launcher-xyz --version"}},
            ],
        )
    )
    assert completed["status"] == "completed"
    failed = orchestrator.execute(
        _spec(
            "broken",
            engines=[
                {
                    "name": "garak",
                    "fail_open": False,
                    "params": {"command": f'{PYTHON} -c "raise SystemExit(3)"'},
                }
            ],
        )
    )
    assert failed["status"] == "failed"

    rows = orchestrator.list_runs()
    assert [row["run_id"] for row in rows] == [failed["run_id"], completed["run_id"]]  # newest first
    by_id = {row["run_id"] for row in rows}
    assert by_id == {failed["run_id"], completed["run_id"]}

    ok_row = next(row for row in rows if row["run_id"] == completed["run_id"])
    scorecard = completed["scorecard"]
    # Base SQLite columns are still there.
    assert {"run_id", "name", "profile", "status", "created_at", "updated_at", "scorecard_path", "findings_path", "error_message"} <= set(ok_row)
    assert ok_row["targets"] == ["local-http"]
    assert ok_row["engines"] == ["garak", "promptfoo"]
    assert ok_row["evaluators"] == []
    assert ok_row["engines_executed"] == ["garak"]
    assert ok_row["engines_skipped"] == ["promptfoo"]
    assert ok_row["finding_count"] == scorecard["total_findings"]
    assert ok_row["severity_counts"] == {
        level: scorecard[level] for level in ("critical", "high", "medium", "low", "info")
    }
    assert ok_row["asr_overall"] == scorecard["asr_overall"]
    assert ok_row["eval_pass_rate"] == scorecard["eval_pass_rate"]
    assert isinstance(ok_row["duration_seconds"], float)
    assert ok_row["bundle_format_version"] == "1.1"
    assert ok_row["gate"] == {"threshold": "high", "ok": True, "blocking_count": 0, "waived_count": 0}

    failed_row = next(row for row in rows if row["run_id"] == failed["run_id"])
    assert failed_row["status"] == "failed"
    assert failed_row["error_message"]
    # No scorecard was produced: report absence, never invented numbers.
    assert failed_row["finding_count"] is None
    assert failed_row["severity_counts"] is None
    assert failed_row["asr_overall"] is None
    assert failed_row["gate"] is None
    assert failed_row["targets"] == ["local-http"]
    assert failed_row["engines"] == ["garak"]
    assert failed_row["bundle_format_version"] == "1.1"


def test_list_runs_gate_summary_reflects_threshold_and_waivers(tmp_path: Path):
    orchestrator = Orchestrator(
        artifact_root=str(tmp_path / "artifacts"),
        metadata_db=str(tmp_path / "meta.sqlite3"),
    )
    result = orchestrator.execute(
        _spec("gated", engines=[{"name": "garak", "params": {"command": f"{PYTHON} -c \"print('ok')\""}}])
    )
    finding_count = result["scorecard"]["total_findings"]

    orchestrator.create_waiver(
        {
            "waiver_id": "w-exec",
            "target_id": "local-http",
            "control_id": "execution",
            "reason": "smoke",
            "owner": "sec-lead",
            "expires_at": "2099-01-01T00:00:00+00:00",
        }
    )

    [row] = orchestrator.list_runs(gate_threshold="info")
    assert row["gate"] == {
        "threshold": "info",
        "ok": True,
        "blocking_count": 0,
        "waived_count": finding_count,
    }

    client = TestClient(create_app(orchestrator))
    listed = client.get("/v1/runs").json()
    assert listed[0]["gate"]["threshold"] == "high"
    assert listed[0]["engines_executed"] == ["garak"]

    listed_info = client.get("/v1/runs", params={"gate_threshold": "info"}).json()
    assert listed_info[0]["gate"]["waived_count"] == finding_count
    assert client.get("/v1/runs", params={"gate_threshold": "severe"}).status_code == 400
