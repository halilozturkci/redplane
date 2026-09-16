"""§4.7 Run button on `/ui/specs` (only now that async runs exist).

Rules under test: the post is CSRF-protected and session-gated like every other
`/ui` mutation; the browser posts `${VAR}` references, never an expanded value, and a
literal credential is refused before anything is queued; a queued run lands on its
own detail page with live stage events.
"""

from __future__ import annotations

import re
import sys
import time
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from urt import auth
from urt.api import create_app
from urt.constants import TERMINAL_RUN_STATUSES
from urt.orchestrator import Orchestrator

PYTHON = sys.executable
SECRET = "sk-live-0123456789abcdef"
KEY = "correct-horse-battery-staple"


def _spec(auth_block: dict | None = None) -> dict:
    return {
        "name": "ui-launched",
        "run_profile": "pr_gate",
        "targets": [
            {
                "id": "agent",
                "type": "http",
                "endpoint": "http://localhost:9999/invoke",
                "auth": auth_block if auth_block is not None else {"headers": {"Authorization": "Bearer ${REDPLANE_TEST_TOKEN}"}},
                "config": {"skip_healthcheck": True},
            }
        ],
        "engines": [{"name": "garak", "params": {"command": f"{PYTHON} -c \"print('garak-ok')\""}}],
    }


@pytest.fixture
def orchestrator(tmp_path: Path) -> Orchestrator:
    return Orchestrator(artifact_root=str(tmp_path / "artifacts"), metadata_db=str(tmp_path / "meta.sqlite3"))


@pytest.fixture
def client(orchestrator: Orchestrator, monkeypatch):
    monkeypatch.setenv("REDPLANE_TEST_TOKEN", SECRET)
    app = create_app(orchestrator)
    with TestClient(app) as test_client:
        yield test_client
    app.state.run_worker.stop(timeout=10)


def _csrf(client: TestClient) -> str:
    page = client.get("/ui/specs")
    assert page.status_code == 200
    return re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)


def wait_terminal(client: TestClient, run_id: str, timeout: float = 30.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        row = client.get(f"/v1/runs/{run_id}").json()
        if row["status"] in TERMINAL_RUN_STATUSES:
            return row
        time.sleep(0.05)
    raise AssertionError("run did not finish")


def test_spec_builder_offers_a_run_button_that_queues_the_spec(client: TestClient, orchestrator: Orchestrator):
    page = client.get("/ui/specs")
    assert 'formaction="/ui/specs/run"' in page.text
    assert "Run" in page.text
    token = _csrf(client)

    response = client.post("/ui/specs/run", data={"yaml": yaml.safe_dump(_spec()), "csrf_token": token}, follow_redirects=False)
    assert response.status_code == 303
    location = response.headers["location"]
    match = re.fullmatch(r"/ui/runs/(run-ui-launched-[a-z0-9-]+)", location)
    assert match, location
    run_id = match.group(1)

    row = client.get(f"/v1/runs/{run_id}").json()
    assert row["status"] in {"queued", "running", "completed"}
    # htmx cannot follow a 303 into a page swap; it gets HX-Redirect instead.
    boosted = client.post(
        "/ui/specs/run",
        data={"yaml": yaml.safe_dump(_spec()), "csrf_token": token},
        headers={"HX-Request": "true"},
        follow_redirects=False,
    )
    assert boosted.status_code == 200
    assert boosted.headers["hx-redirect"].startswith("/ui/runs/run-ui-launched-")
    wait_terminal(client, boosted.headers["hx-redirect"].rsplit("/", 1)[1])
    detail = client.get(location)
    assert detail.status_code == 200
    assert "Stage events" in detail.text

    wait_terminal(client, run_id)
    # The expanded credential never reached the browser or the bundle.
    run_dir = Path(orchestrator.artifact_store.root_dir) / run_id
    for path in run_dir.rglob("*"):
        if path.is_file():
            assert SECRET not in path.read_text(encoding="utf-8", errors="replace"), path
    assert SECRET not in client.get(f"/ui/runs/{run_id}").text
    resolved = client.get(f"/v1/runs/{run_id}/manifest").json()
    assert resolved["targets"][0]["auth"]["headers"]["Authorization"] == "***REDACTED***"


def test_run_button_refuses_literal_credentials_and_invalid_specs_before_queueing(client: TestClient):
    token = _csrf(client)
    literal = client.post(
        "/ui/specs/run",
        data={"yaml": yaml.safe_dump(_spec({"headers": {"Authorization": f"Bearer {SECRET}"}})), "csrf_token": token},
        follow_redirects=False,
    )
    assert literal.status_code == 400
    assert "literal credentials are not accepted" in literal.text
    # The editor echoes what the operator typed (the browser already holds it); the
    # validation result must not repeat the literal.
    result_block = literal.text.split('<div id="spec-result"', 1)[1]
    assert SECRET not in result_block
    assert client.get("/v1/runs").json() == []

    invalid = client.post("/ui/specs/run", data={"yaml": "name: ''\n", "csrf_token": token}, follow_redirects=False)
    assert invalid.status_code == 400
    assert "Validation failed" in invalid.text
    assert client.get("/v1/runs").json() == []

    unparseable = client.post("/ui/specs/run", data={"yaml": "a: [", "csrf_token": token}, follow_redirects=False)
    assert unparseable.status_code == 400
    assert client.get("/v1/runs").json() == []


def test_run_button_requires_csrf_and_a_form_body(client: TestClient):
    token = _csrf(client)
    payload = {"yaml": yaml.safe_dump(_spec())}
    assert client.post("/ui/specs/run", data=payload).status_code == 403
    assert client.post("/ui/specs/run", data={**payload, "csrf_token": "x" * 43}).status_code == 403
    assert (
        client.post("/ui/specs/run", data={**payload, "csrf_token": token}, headers={"Origin": "https://evil.example"}).status_code
        == 403
    )
    assert client.post("/ui/specs/run", json={**payload, "csrf_token": token}).status_code == 415
    assert client.get("/v1/runs").json() == []


def test_run_button_needs_a_session_when_the_api_key_is_set(orchestrator: Orchestrator, monkeypatch):
    monkeypatch.setattr(auth, "FAILED_AUTH_DELAY_SECONDS", 0.0)
    monkeypatch.setenv("REDPLANE_TEST_TOKEN", SECRET)
    app = create_app(orchestrator, api_key=KEY)
    with TestClient(app) as client:
        anonymous = client.post("/ui/specs/run", data={"yaml": "name: x\n", "csrf_token": "t"}, follow_redirects=False)
        assert anonymous.status_code == 401
        assert client.get("/v1/runs", headers={"Authorization": f"Bearer {KEY}"}).json() == []

        login = client.get("/ui/login")
        token = re.search(r'name="csrf_token" value="([^"]+)"', login.text).group(1)
        assert client.post("/ui/login", data={"api_key": KEY, "next": "/ui/specs", "csrf_token": token}, follow_redirects=False).status_code == 303
        token = _csrf(client)
        queued = client.post(
            "/ui/specs/run",
            data={"yaml": yaml.safe_dump(_spec()), "csrf_token": token},
            headers={"Origin": "http://testserver"},
            follow_redirects=False,
        )
        assert queued.status_code == 303
        run_id = queued.headers["location"].rsplit("/", 1)[1]
        wait_terminal_with_key(client, run_id)
    app.state.run_worker.stop(timeout=10)


def wait_terminal_with_key(client: TestClient, run_id: str, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        row = client.get(f"/v1/runs/{run_id}", headers={"Authorization": f"Bearer {KEY}"}).json()
        if row["status"] in TERMINAL_RUN_STATUSES:
            return
        time.sleep(0.05)
    raise AssertionError("run did not finish")
