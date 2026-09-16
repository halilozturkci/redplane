"""G13: optional shared-secret auth on `urt serve-api` (bearer for the API, cookie for /ui).

One `URT_API_KEY` is the ceiling: no users, no roles. Without a key nothing changes
and the CLI refuses a non-loopback bind unless `--unsafe-allow-unauthenticated`.
"""

from __future__ import annotations

import re

import pytest
from conftest import Bundle
from fastapi.testclient import TestClient

from urt.api import create_app
from urt.auth import SESSION_COOKIE, session_token

KEY = "correct-horse-battery-staple"


@pytest.fixture
def client(rich_bundle: Bundle) -> TestClient:
    return TestClient(create_app(rich_bundle.orchestrator, api_key=KEY))


def test_api_requires_bearer_when_key_is_set(client: TestClient, rich_bundle: Bundle):
    assert client.get("/healthz").status_code == 200
    assert client.get("/ui/static/app.css").status_code == 200
    assert client.get("/ui/static/htmx.min.js").status_code == 200

    denied = client.get("/v1/runs")
    assert denied.status_code == 401
    assert denied.headers["www-authenticate"].startswith("Bearer")
    assert client.get("/v1/runs", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert client.get("/v1/runs", headers={"Authorization": "Basic abc"}).status_code == 401
    assert client.get(f"/v1/runs/{rich_bundle.run_id}/findings").status_code == 401
    assert client.post("/v1/waivers", json={}).status_code == 401
    assert client.get("/openapi.json").status_code == 401

    ok = client.get("/v1/runs", headers={"Authorization": f"Bearer {KEY}"})
    assert ok.status_code == 200 and ok.json()


def test_ui_login_sets_httponly_cookie_and_protects_pages(client: TestClient, rich_bundle: Bundle):
    redirect = client.get("/ui", follow_redirects=False)
    assert redirect.status_code == 303
    assert redirect.headers["location"] == "/ui/login?next=%2Fui"
    assert client.get(f"/ui/runs/{rich_bundle.run_id}/gate", follow_redirects=False).status_code == 303
    assert client.get("/ui/login?next=https://evil.example", follow_redirects=False).status_code == 200

    login = client.get("/ui/login")
    assert login.status_code == 200
    assert 'type="password"' in login.text
    assert "shared secret" in login.text
    token = re.search(r'name="csrf_token" value="([^"]+)"', login.text).group(1)

    wrong = client.post("/ui/login", data={"api_key": "nope", "next": "/ui", "csrf_token": token})
    assert wrong.status_code == 401
    assert SESSION_COOKIE not in client.cookies
    assert client.post("/ui/login", data={"api_key": KEY, "next": "/ui"}).status_code == 403  # CSRF applies here too

    good = client.post("/ui/login", data={"api_key": KEY, "next": "https://evil.example", "csrf_token": token}, follow_redirects=False)
    assert good.status_code == 303
    assert good.headers["location"] == "/ui"  # open redirect refused, falls back to /ui
    set_cookie = good.headers["set-cookie"]
    assert "HttpOnly" in set_cookie and "SameSite=strict" in set_cookie.replace("Strict", "strict")
    assert KEY not in set_cookie  # the cookie is a derived token, not the key
    assert client.cookies.get(SESSION_COOKIE) == session_token(KEY)

    assert client.get("/ui").status_code == 200
    assert client.get(f"/ui/runs/{rich_bundle.run_id}").status_code == 200
    # The session cookie also lets the browser follow evidence/JSON links (safe methods only).
    assert client.get(f"/v1/runs/{rich_bundle.run_id}/scorecard").status_code == 200
    assert client.post("/v1/waivers", json={"target_id": "t"}).status_code == 401
    assert client.patch("/v1/waivers/x", json={"revoke": True}).status_code == 401

    logout = client.post("/ui/logout", data={"csrf_token": token}, follow_redirects=False)
    assert logout.status_code == 303
    assert client.get("/ui", follow_redirects=False).status_code == 303


def test_forged_session_cookie_is_rejected(client: TestClient):
    client.cookies.set(SESSION_COOKIE, "0" * 64)
    assert client.get("/ui", follow_redirects=False).status_code == 303
    client.cookies.set(SESSION_COOKIE, session_token("wrong-key"))
    assert client.get("/v1/runs").status_code == 401


def test_without_a_key_nothing_is_gated_and_login_says_so(rich_bundle: Bundle, monkeypatch):
    monkeypatch.delenv("URT_API_KEY", raising=False)
    client = TestClient(create_app(rich_bundle.orchestrator))
    assert client.get("/v1/runs").status_code == 200
    assert client.get("/ui").status_code == 200
    login = client.get("/ui/login")
    assert login.status_code == 200
    assert "no <code>URT_API_KEY</code>" in login.text


def test_create_app_reads_key_from_environment(rich_bundle: Bundle, monkeypatch):
    monkeypatch.setenv("URT_API_KEY", KEY)
    client = TestClient(create_app(rich_bundle.orchestrator))
    assert client.get("/v1/runs").status_code == 401
    assert client.get("/v1/runs", headers={"Authorization": f"Bearer {KEY}"}).status_code == 200


def test_serve_api_non_loopback_needs_key_or_explicit_unsafe_flag(monkeypatch, capsys):
    import sys

    import urt.cli as cli

    calls: list[dict] = []
    fake_uvicorn = type("U", (), {"run": staticmethod(lambda *a, **kw: calls.append(kw))})
    monkeypatch.setitem(sys.modules, "uvicorn", fake_uvicorn)
    monkeypatch.delenv("URT_API_KEY", raising=False)

    assert cli.main(["serve-api", "--host", "0.0.0.0"]) == 2
    err = capsys.readouterr().err
    assert "URT_API_KEY" in err and "--unsafe-allow-unauthenticated" in err
    assert calls == []

    assert cli.main(["serve-api", "--host", "0.0.0.0", "--unsafe-allow-unauthenticated"]) == 0
    assert calls[-1]["host"] == "0.0.0.0"
    # The MVP flag name keeps working as an alias.
    assert cli.main(["serve-api", "--host", "0.0.0.0", "--unsafe-allow-non-loopback"]) == 0

    monkeypatch.setenv("URT_API_KEY", KEY)
    assert cli.main(["serve-api", "--host", "0.0.0.0"]) == 0
    assert calls[-1]["host"] == "0.0.0.0"
    assert cli.main(["serve-api"]) == 0
    assert calls[-1]["host"] == "127.0.0.1"


def test_serve_api_passes_store_paths_to_the_app_factory(monkeypatch):
    """`urt --artifact-root X --metadata-db Y serve-api` must serve those stores, not the
    defaults: the uvicorn factory can only see them through the environment."""
    import os
    import sys

    import urt.cli as cli

    calls: list[dict] = []
    fake_uvicorn = type("U", (), {"run": staticmethod(lambda *a, **kw: calls.append(kw))})
    monkeypatch.setitem(sys.modules, "uvicorn", fake_uvicorn)
    monkeypatch.delenv("URT_ARTIFACT_ROOT", raising=False)
    monkeypatch.delenv("URT_METADATA_DB", raising=False)

    assert cli.main(["--artifact-root", "/tmp/x/artifacts", "--metadata-db", "/tmp/x/meta.sqlite3", "serve-api"]) == 0
    assert os.environ["URT_ARTIFACT_ROOT"] == "/tmp/x/artifacts"
    assert os.environ["URT_METADATA_DB"] == "/tmp/x/meta.sqlite3"

    monkeypatch.setenv("URT_ARTIFACT_ROOT", "/from/env")
    assert cli.main(["serve-api"]) == 0  # CLI defaults never override an explicit environment
    assert os.environ["URT_ARTIFACT_ROOT"] == "/from/env"
