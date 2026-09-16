"""Async `POST /v1/runs` (G7 / #18): 202 + run_id, one worker thread, SQLite status,
incremental stage events, stale-`running` recovery. `urt run` stays synchronous.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from urt.api import create_app
from urt.constants import TERMINAL_RUN_STATUSES
from urt.jobs import RunWorker, worker_is_alive
from urt.orchestrator import Orchestrator
from urt.types import RunSpec

PYTHON = sys.executable


def _spec(*, engine_command: str, fail_open: bool = True, name: str = "async-smoke") -> dict:
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
        "engines": [{"name": "garak", "fail_open": fail_open, "params": {"command": engine_command}}],
    }


def passing_spec(name: str = "async-smoke") -> dict:
    return _spec(engine_command=f"{PYTHON} -c \"print('garak-ok')\"", name=name)


def failing_spec() -> dict:
    return _spec(engine_command=f'{PYTHON} -c "raise SystemExit(3)"', fail_open=False, name="async-fail")


def slow_spec(seconds: float = 2.0) -> dict:
    return _spec(engine_command=f'{PYTHON} -c "import time; time.sleep({seconds}); print(1)"', name="async-slow")


@pytest.fixture
def orchestrator(tmp_path: Path) -> Orchestrator:
    return Orchestrator(artifact_root=str(tmp_path / "artifacts"), metadata_db=str(tmp_path / "meta.sqlite3"))


@pytest.fixture
def client(orchestrator: Orchestrator):
    app = create_app(orchestrator)
    with TestClient(app) as test_client:
        yield test_client
    app.state.run_worker.stop(timeout=10)


def wait_terminal(client: TestClient, run_id: str, timeout: float = 30.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        row = client.get(f"/v1/runs/{run_id}").json()
        if row["status"] in TERMINAL_RUN_STATUSES:
            return row
        time.sleep(0.05)
    raise AssertionError(f"run {run_id} did not finish in {timeout}s")


def test_post_runs_returns_202_and_the_run_completes_in_the_background(client: TestClient, orchestrator: Orchestrator):
    response = client.post("/v1/runs", json=passing_spec())
    assert response.status_code == 202
    body = response.json()
    run_id = body["run_id"]
    assert body["status"] in {"queued", "running"}
    assert body["location"] == f"/v1/runs/{run_id}"
    assert response.headers["location"] == f"/v1/runs/{run_id}"
    assert "scorecard" not in body

    queued = client.get(f"/v1/runs/{run_id}").json()
    assert queued["status"] in {"queued", "running", "completed"}
    assert queued["terminal"] is (queued["status"] in TERMINAL_RUN_STATUSES)

    row = wait_terminal(client, run_id)
    assert row["status"] == "completed"
    assert row["terminal"] is True
    assert row["started_at"]
    assert row["worker_id"]
    assert client.get(f"/v1/runs/{run_id}/scorecard").json()["run_id"] == run_id

    stages = client.get(f"/v1/runs/{run_id}/stages").json()
    kinds = [(event["stage"], event["status"]) for event in stages]
    assert ("run", "started") == kinds[0]
    assert ("engine", "started") in kinds
    assert ("engine", "completed") in kinds
    assert kinds[-1] == ("run", "completed")
    engine_started = next(e for e in stages if e["stage"] == "engine" and e["status"] == "started")
    assert engine_started["engine"] == "garak"
    assert engine_started["target_id"] == "local-http"
    assert engine_started["at"]
    # The row itself carries the count so a poller does not need the file.
    assert client.get(f"/v1/runs/{run_id}").json()["stage_event_count"] == len(stages)


def test_failed_async_run_is_recorded_with_its_error(client: TestClient):
    run_id = client.post("/v1/runs", json=failing_spec()).json()["run_id"]
    row = wait_terminal(client, run_id)
    assert row["status"] == "failed"
    assert "fail_open=false" in row["error_message"]
    stages = client.get(f"/v1/runs/{run_id}/stages").json()
    assert stages[-1]["stage"] == "run" and stages[-1]["status"] == "failed"
    manifest = client.get(f"/v1/runs/{run_id}/manifest").json()
    assert manifest["status"] == "failed"


def test_invalid_spec_is_rejected_before_anything_is_queued(client: TestClient):
    response = client.post("/v1/runs", json={"name": "no-targets", "engines": [{"name": "garak"}]})
    assert response.status_code == 400
    assert client.get("/v1/runs").json() == []


def test_wait_flag_keeps_the_synchronous_contract(client: TestClient):
    completed = client.post("/v1/runs", params={"wait": "true"}, json=passing_spec())
    assert completed.status_code == 200
    assert completed.json()["status"] == "completed"
    assert completed.json()["scorecard"]["run_id"] == completed.json()["run_id"]

    failed = client.post("/v1/runs", params={"wait": "true"}, json=failing_spec())
    assert failed.status_code == 500
    assert failed.json()["detail"]["status"] == "failed"


def test_runs_are_executed_one_at_a_time_in_submission_order(client: TestClient):
    first = client.post("/v1/runs", json=slow_spec(1.0)).json()["run_id"]
    second = client.post("/v1/runs", json=passing_spec("async-second")).json()["run_id"]
    # While the first run holds the single worker, the second stays queued.
    assert client.get(f"/v1/runs/{second}").json()["status"] == "queued"
    wait_terminal(client, first)
    row = wait_terminal(client, second)
    assert row["status"] == "completed"
    first_row = client.get(f"/v1/runs/{first}").json()
    assert first_row["started_at"] <= row["started_at"]


def test_stage_events_are_visible_while_the_run_is_still_running(client: TestClient, orchestrator: Orchestrator):
    run_id = client.post("/v1/runs", json=slow_spec(2.0)).json()["run_id"]
    deadline = time.monotonic() + 10
    stages: list[dict] = []
    while time.monotonic() < deadline:
        row = client.get(f"/v1/runs/{run_id}").json()
        if row["status"] == "running":
            response = client.get(f"/v1/runs/{run_id}/stages")
            if response.status_code == 200 and any(e["stage"] == "engine" for e in response.json()):
                stages = response.json()
                break
        time.sleep(0.05)
    assert stages, "expected an engine 'started' stage event before the engine finished"
    assert [e["status"] for e in stages if e["stage"] == "engine"] == ["started"]
    wait_terminal(client, run_id)


def test_stale_running_and_queued_rows_are_recovered_when_the_server_starts(tmp_path: Path):
    """A control-plane process that died mid-run leaves `running` (and `queued`) rows behind.
    A new process marks them failed instead of re-executing them or leaving them forever."""
    orchestrator = Orchestrator(artifact_root=str(tmp_path / "artifacts"), metadata_db=str(tmp_path / "meta.sqlite3"))
    dead_worker = f"{socket.gethostname()}:999999999"  # this host, no such pid
    orchestrator.metadata_store.create_run(
        orchestrator.metadata_store.new_record(run_id="run-stale-running", name="stale", profile="pr_gate", status="running", worker_id=dead_worker)
    )
    orchestrator.metadata_store.create_run(
        orchestrator.metadata_store.new_record(run_id="run-stale-queued", name="stale", profile="pr_gate", status="queued", worker_id=dead_worker)
    )
    orchestrator.artifact_store.write_json("run-stale-running", "resolved_spec.json", {"name": "stale"})

    with TestClient(create_app(orchestrator)) as client:
        for run_id in ("run-stale-running", "run-stale-queued"):
            row = client.get(f"/v1/runs/{run_id}").json()
            assert row["status"] == "failed", run_id
            assert "interrupted" in row["error_message"]
        manifest = client.get("/v1/runs/run-stale-running/manifest").json()
        assert manifest["status"] == "failed"
        assert "interrupted" in manifest["error"]
        assert (tmp_path / "artifacts" / "run-stale-running" / "run_error.log").exists()
        assert client.get("/v1/runs/run-stale-queued/manifest").status_code == 200


def test_recovery_leaves_runs_owned_by_a_live_process_alone(tmp_path: Path):
    orchestrator = Orchestrator(artifact_root=str(tmp_path / "artifacts"), metadata_db=str(tmp_path / "meta.sqlite3"))
    live_worker = RunWorker.current_worker_id()
    assert worker_is_alive(live_worker)
    orchestrator.metadata_store.create_run(
        orchestrator.metadata_store.new_record(run_id="run-live", name="live", profile="pr_gate", status="running", worker_id=live_worker)
    )
    recovered = orchestrator.recover_interrupted_runs()
    assert recovered == []
    assert orchestrator.get_run("run-live")["status"] == "running"
    assert orchestrator.get_run("run-live")["stale"] is False


def test_run_rows_flag_stale_running_when_the_worker_process_is_gone(tmp_path: Path):
    orchestrator = Orchestrator(artifact_root=str(tmp_path / "artifacts"), metadata_db=str(tmp_path / "meta.sqlite3"))
    orchestrator.metadata_store.create_run(
        orchestrator.metadata_store.new_record(run_id="run-gone", name="gone", profile="pr_gate", status="running", worker_id=f"{socket.gethostname()}:999999999")
    )
    [row] = orchestrator.list_runs()
    assert row["stale"] is True
    assert orchestrator.get_run("run-gone")["stale"] is True


def test_cli_run_is_still_synchronous_and_writes_stage_events(tmp_path: Path, capsys):
    import urt.cli as cli

    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(passing_spec("cli-sync")), encoding="utf-8")
    code = cli.main(
        ["--artifact-root", str(tmp_path / "a"), "--metadata-db", str(tmp_path / "m.sqlite3"), "run", "--spec", str(spec_path)]
    )
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "completed"
    stages = json.loads((tmp_path / "a" / out["run_id"] / "stage_events.json").read_text(encoding="utf-8"))
    assert stages[-1] == {**stages[-1], "stage": "run", "status": "completed"}


ENGINE_WITH_GRANDCHILD = """
import os, subprocess, sys, time
marker = sys.argv[1]
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
open(marker, "w").write(f"{os.getpid()} {child.pid}")
time.sleep(60)
"""


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # A zombie still answers kill(0); read its state to tell.
    try:
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
    except OSError:
        return False
    return state != "Z"


def test_stopping_the_worker_kills_the_engine_process_group_and_marks_the_run_interrupted(tmp_path: Path):
    """S1: stopping `serve-api` must not orphan the attack tool. The engine and anything it
    spawned run in their own process group; `RunWorker.stop()` kills that group, the run is
    recorded `failed: interrupted`, and a run still queued is not started during shutdown."""
    orchestrator = Orchestrator(artifact_root=str(tmp_path / "artifacts"), metadata_db=str(tmp_path / "meta.sqlite3"))
    script = tmp_path / "engine.py"
    script.write_text(ENGINE_WITH_GRANDCHILD, encoding="utf-8")
    marker = tmp_path / "pids.txt"
    spec = _spec(engine_command=f"{PYTHON} {script} {marker}", name="orphan-check")
    app = create_app(orchestrator)
    with TestClient(app) as client:
        running = client.post("/v1/runs", json=spec).json()["run_id"]
        queued = client.post("/v1/runs", json=passing_spec("never-started")).json()["run_id"]
        deadline = time.monotonic() + 15
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert marker.exists(), "engine never started"
        leader_pid, grandchild_pid = (int(p) for p in marker.read_text().split())
        assert _pid_alive(leader_pid) and _pid_alive(grandchild_pid)
        assert os.getpgid(leader_pid) == leader_pid  # its own session/process group
        assert os.getpgid(leader_pid) != os.getpgid(os.getpid())

        app.state.run_worker.stop(timeout=15)

    deadline = time.monotonic() + 10
    while (_pid_alive(leader_pid) or _pid_alive(grandchild_pid)) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not _pid_alive(leader_pid), "engine leader survived the worker stop"
    assert not _pid_alive(grandchild_pid), "engine grandchild survived the worker stop"

    row = orchestrator.get_run(running)
    assert row["status"] == "failed"
    assert "interrupted" in row["error_message"]
    stages = json.loads((tmp_path / "artifacts" / running / "stage_events.json").read_text(encoding="utf-8"))
    assert stages[-1]["stage"] == "run" and stages[-1]["status"] == "failed"
    manifest = json.loads((tmp_path / "artifacts" / running / "run_manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "failed" and "interrupted" in manifest["error"]

    never = orchestrator.get_run(queued)
    assert never["status"] == "failed"
    assert never["started_at"] is None  # never promoted to running
    assert "interrupted" in never["error_message"] and "queued" in never["error_message"]


def test_mark_run_failed_never_flips_a_terminal_row(orchestrator: Orchestrator):
    result = orchestrator.execute(RunSpec.from_dict(passing_spec("done")))
    orchestrator.mark_run_failed(result["run_id"], "late error")
    assert orchestrator.get_run(result["run_id"])["status"] == "completed"


def test_orchestrator_execute_reuses_a_queued_record_instead_of_creating_a_second_run(orchestrator: Orchestrator):
    spec = RunSpec.from_dict(passing_spec("queued-first"))
    run_id = orchestrator.enqueue_run(spec, worker_id="this-host:1")
    assert orchestrator.get_run(run_id)["status"] == "queued"
    result = orchestrator.execute(spec, run_id=run_id)
    assert result["run_id"] == run_id
    assert [row["run_id"] for row in orchestrator.list_runs()] == [run_id]
    assert orchestrator.get_run(run_id)["status"] == "completed"
