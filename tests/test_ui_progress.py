"""§4.10 live run progress on `/ui`: the detail page polls the stage-events fragment only
while the run is not terminal, renders discrete orchestrator stages, and never shows a
percentage bar or a token stream."""

from __future__ import annotations

import re
import socket
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from urt.api import create_app
from urt.constants import TERMINAL_RUN_STATUSES
from urt.orchestrator import Orchestrator

PYTHON = sys.executable


def spec(seconds: float, name: str = "ui-progress") -> dict:
    return {
        "name": name,
        "run_profile": "pr_gate",
        "targets": [
            {"id": "local-http", "type": "http", "endpoint": "http://localhost:9999/invoke", "config": {"skip_healthcheck": True}}
        ],
        "engines": [
            {"name": "garak", "params": {"command": f'{PYTHON} -c "import time; time.sleep({seconds}); print(1)"'}}
        ],
    }


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
    raise AssertionError("run did not finish")


def test_run_detail_polls_stage_events_only_while_the_run_is_not_terminal(client: TestClient):
    run_id = client.post("/v1/runs", json=spec(2.0)).json()["run_id"]

    # Before the bundle exists the page still renders, from the SQLite row.
    pending = client.get(f"/ui/runs/{run_id}")
    assert pending.status_code == 200
    assert "Stage events" in pending.text
    status = client.get(f"/v1/runs/{run_id}").json()["status"]
    assert status in {"queued", "running"}
    assert re.search(r'hx-get="/ui/runs/[^"]+/progress\?since=(queued|running)"', pending.text)
    assert 'hx-trigger="every 3s"' in pending.text
    assert "<progress" not in pending.text
    assert "No scorecard" in pending.text
    first_fragment = client.get(f"/ui/runs/{run_id}/progress", params={"since": status}).text
    assert "<progress" not in first_fragment and "%" not in first_fragment

    # The fragment while running lists the engine start as a stage, not a fraction.
    fragment = None
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        candidate = client.get(f"/ui/runs/{run_id}/progress", params={"since": "running"})
        assert candidate.status_code == 200
        if "engine" in candidate.text and "started" in candidate.text:
            fragment = candidate
            break
        time.sleep(0.05)
    assert fragment is not None
    assert fragment.text.lstrip().startswith('<div id="run-progress"')
    assert "hx-refresh" not in {k.lower() for k in fragment.headers}
    assert "garak" in fragment.text and "local-http" in fragment.text

    wait_terminal(client, run_id)
    # A poll that started while the run was running gets told to reload the page.
    finished = client.get(f"/ui/runs/{run_id}/progress", params={"since": "running"})
    assert finished.status_code == 200
    assert finished.headers["hx-refresh"] == "true"
    assert 'hx-trigger="every' not in finished.text

    detail = client.get(f"/ui/runs/{run_id}")
    assert 'hx-trigger="every' not in detail.text
    assert "Stage events" in detail.text
    assert "run completed" in detail.text.lower() or ">completed<" in detail.text
    assert '<span class="tile-value">' in detail.text  # scorecard rendered once terminal


def test_runs_list_shows_queue_state_and_flags_stale_rows(client: TestClient, orchestrator: Orchestrator):
    orchestrator.metadata_store.create_run(
        orchestrator.metadata_store.new_record(
            run_id="run-gone", name="gone", profile="pr_gate", status="running", worker_id=f"{socket.gethostname()}:999999999"
        )
    )
    run_id = client.post("/v1/runs", json=spec(1.5, "queued-visible")).json()["run_id"]
    listing = client.get("/ui")
    assert listing.status_code == 200
    assert f'href="/ui/runs/{run_id}"' in listing.text
    assert re.search(r'<span class="badge [^"]*">(queued|running)</span>', listing.text)
    assert "stale" in listing.text  # run-gone: worker pid is dead
    assert 'href="/ui/runs/run-gone"' in listing.text
    wait_terminal(client, run_id)


def test_progress_fragment_404s_for_unknown_run(client: TestClient):
    assert client.get("/ui/runs/nope/progress").status_code == 404
