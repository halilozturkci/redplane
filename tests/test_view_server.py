"""`urt view <run_id>`: a loopback-only server over one run directory.

Model: Inspect's `inspect view`. No SQLite, no API — just the bundle files with
the same path confinement, media-type and legacy-bundle rules as the API.
"""

from __future__ import annotations

import re
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


def test_only_report_html_renders_inline_other_html_is_an_attachment(rich_bundle: Bundle, served):
    digest = rich_bundle.run_dir / "raw" / "garak" / "digest.html"
    digest.write_text("<script>document.title='pwned-'+location.origin</script>", encoding="utf-8")
    port = served(rich_bundle)

    status, headers, body = _get(port, "/raw/garak/digest.html")
    assert status == 200
    assert headers["content-disposition"] == 'attachment; filename="digest.html"'
    assert headers["content-security-policy"] == "default-src 'none'; sandbox"
    assert headers["x-content-type-options"] == "nosniff"
    assert b"pwned" in body  # served as a download, never rendered in the viewer origin

    # The viewer itself carries its meta CSP as a header too (plus frame-ancestors,
    # which a meta tag cannot express).
    status, headers, body = _get(port, "/")
    assert status == 200
    assert "content-disposition" not in headers
    meta = re.search(rb'<meta http-equiv="Content-Security-Policy" content="([^"]+)"', body).group(1).decode()
    assert headers["content-security-policy"] == f"{meta}; frame-ancestors 'none'"
    assert "script-src 'sha256-" in headers["content-security-policy"]
    # /report.html is the same file and gets the same treatment.
    status, headers, _ = _get(port, "/report.html")
    assert "content-disposition" not in headers
    assert headers["content-security-policy"].startswith("default-src 'none'; script-src 'sha256-")


SPOOFED_LEGACY_REPORT = (
    "<!doctype html><html><head><title>URT Report</title></head><body><h1>URT Report</h1>"
    "<table><tr><td>"
    "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; script-src 'unsafe-inline'\">"
    "<script>document.title='pwned-'+location.origin</script>"
    "</td></tr></table></body></html>"
)


def test_legacy_report_with_attacker_supplied_csp_meta_gets_the_strict_fallback_header(legacy_bundle: Bundle, served):
    from urt.ui.view_server import LEGACY_REPORT_CSP

    # A pre-Phase-0 report.html (unescaped render_html) carrying attacker text that
    # includes its own permissive CSP meta inside the body.
    (legacy_bundle.run_dir / "report.html").write_text(SPOOFED_LEGACY_REPORT, encoding="utf-8")
    port = served(legacy_bundle)

    status, headers, body = _get(port, "/")
    assert status == 200
    assert b"unsafe-inline" in body  # served as-is (allowlisted), but…
    assert headers["content-security-policy"] == f"{LEGACY_REPORT_CSP}; frame-ancestors 'none'"
    assert "unsafe-inline" not in headers["content-security-policy"].replace("style-src 'unsafe-inline'", "")
    assert "script-src" not in headers["content-security-policy"]  # default-src 'none' governs scripts


def test_viewer_csp_header_only_trusts_our_own_head_meta():
    from urt.ui.view_server import LEGACY_REPORT_CSP, viewer_csp_header

    ours = (
        b"<!doctype html><html><head><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; "
        b"script-src 'sha256-AAAA='; style-src 'sha256-BBBB='; base-uri 'none'; form-action 'none'\"></head><body></body></html>"
    )
    assert viewer_csp_header(ours) == (
        "default-src 'none'; script-src 'sha256-AAAA='; style-src 'sha256-BBBB='; base-uri 'none'; "
        "form-action 'none'; frame-ancestors 'none'"
    )
    fallback = f"{LEGACY_REPORT_CSP}; frame-ancestors 'none'"
    # Meta in the body (attacker text) is ignored.
    assert viewer_csp_header(SPOOFED_LEGACY_REPORT.encode()) == fallback
    # Meta in the head but not in the exact shape the viewer emits is ignored too.
    loose = b"<head><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; script-src 'unsafe-inline'\"></head><body>"
    assert viewer_csp_header(loose) == fallback
    # No meta at all: fallback.
    assert viewer_csp_header(b"<html><head></head><body>x</body></html>") == fallback


def test_failed_run_is_viewable(failed_bundle: Bundle, served):
    port = served(failed_bundle)
    status, headers, body = _get(port, "/")
    assert status == 200
    assert b"fail_open=false" in body


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

    for bad in ("missing-run", "..", "."):
        rc = main(["--artifact-root", str(rich_bundle.orchestrator.artifact_store.root_dir), "view", bad])
        assert rc == 1, bad
        assert "Run directory not found" in capsys.readouterr().err
