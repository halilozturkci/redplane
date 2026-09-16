"""`urt view <run_id>`: a loopback-only server over one run directory.

Model: Inspect's `inspect view`. No SQLite, no API — just the bundle files with
the same path confinement, media-type and legacy-bundle rules as the API.
"""

from __future__ import annotations

import threading
from http.client import HTTPConnection

import pytest
from conftest import LEGACY_SECRET, TARGET_ID, Bundle

from urt.ui.view_server import LoopbackOnlyError, build_view_server


@pytest.fixture
def served(request):
    servers = []

    def start(bundle: Bundle):
        server = build_view_server(bundle.run_dir, host="127.0.0.1", port=0)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        servers.append(server)
        return server.server_address[1]

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


def _get(port: int, path: str):
    conn = HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", path)
    response = conn.getresponse()
    body = response.read()
    headers = {k.lower(): v for k, v in response.getheaders()}
    conn.close()
    return response.status, headers, body


def test_root_serves_the_viewer_and_relative_evidence_links_resolve(rich_bundle: Bundle, served):
    port = served(rich_bundle)

    status, headers, body = _get(port, "/")
    assert status == 200
    assert headers["content-type"].startswith("text/html")
    assert headers["x-content-type-options"] == "nosniff"
    assert b'id="redplane-data"' in body
    assert b"Redplane report" in body

    status, headers, body = _get(port, f"/raw/garak/{TARGET_ID}_stdout.log")
    assert status == 200
    assert headers["content-type"].startswith("text/plain")
    assert b"garak-ok" in body
    assert headers["content-security-policy"] == "default-src 'none'; sandbox"

    status, headers, _ = _get(port, "/findings.json")
    assert status == 200
    assert headers["content-type"].startswith("application/json")

    status, headers, _ = _get(port, "/report.html")
    assert status == 200
    assert headers["content-type"].startswith("text/html")


@pytest.mark.parametrize("path", ["/../other.json", "/raw/../../x", "/raw//x", "/%2e%2e/x", "/nope.json"])
def test_traversal_and_missing_files_are_refused(rich_bundle: Bundle, served, path: str):
    port = served(rich_bundle)
    status, _, body = _get(port, path)
    assert status in {400, 404}
    assert b"<" not in body  # plain-text error, never reflected markup


def test_legacy_bundle_serves_only_the_allowlist(legacy_bundle: Bundle, served):
    port = served(legacy_bundle)

    status, _, body = _get(port, "/")
    assert status == 200
    assert LEGACY_SECRET.encode() not in body

    for path in ("/resolved_spec.json", "/findings.json", f"/raw/garak/{TARGET_ID}_stdout.log"):
        status, _, body = _get(port, path)
        assert status == 409, path
        assert LEGACY_SECRET.encode() not in body
        assert b"1.0" in body and b"1.1" in body

    for path in ("/scorecard.json", "/report.md", "/report.csv"):
        status, _, body = _get(port, path)
        assert status == 200, path
        assert LEGACY_SECRET.encode() not in body


def test_non_loopback_bind_is_refused(rich_bundle: Bundle):
    with pytest.raises(LoopbackOnlyError):
        build_view_server(rich_bundle.run_dir, host="0.0.0.0", port=0)
    with pytest.raises(LoopbackOnlyError):
        build_view_server(rich_bundle.run_dir, host="192.168.1.20", port=0)
    for host in ("127.0.0.1", "localhost", "::1", "127.0.0.5"):
        server = build_view_server(rich_bundle.run_dir, host=host, port=0)
        server.server_close()


def test_missing_run_directory_is_an_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        build_view_server(tmp_path / "missing", host="127.0.0.1", port=0)


def test_cli_view_prints_the_url_and_serves(rich_bundle: Bundle, capsys, monkeypatch):
    from urt.cli import main

    started = {}

    def fake_serve(server):
        started["port"] = server.server_address[1]
        server.server_close()

    monkeypatch.setattr("urt.cli._serve_view", fake_serve)
    rc = main(
        [
            "--artifact-root",
            str(rich_bundle.orchestrator.artifact_store.root_dir),
            "view",
            rich_bundle.run_id,
            "--port",
            "0",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert f"http://127.0.0.1:{started['port']}/" in out
    assert rich_bundle.run_id in out

    rc = main(["--artifact-root", str(rich_bundle.orchestrator.artifact_store.root_dir), "view", "missing-run"])
    assert rc == 1
