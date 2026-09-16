"""`urt view <run_id>`: serve one run directory on loopback (Inspect `view` model).

Stdlib only, no SQLite, no API. `/` is `report.html` (the self-contained viewer,
the only file rendered inline as HTML); every other path is a bundle file
resolved with the same confinement rules as the API (`ArtifactStore.resolve_artifact`),
served under the same `artifact_policy` (text inline under a sandboxing CSP, any
other `.html` and binaries as attachments), and subject to the same pre-1.1
allowlist: a legacy bundle may hold expanded credentials, so only aggregates and
rendered reports are served.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

from ..artifact_policy import artifact_response_policy, is_viewer_file
from ..constants import LEGACY_RAW_DOWNLOAD_ALLOWLIST, REDACTED_BUNDLE_MIN_VERSION
from ..storage.artifact_store import ArtifactPathError, ArtifactStore

LOOPBACK_NAMES = {"localhost", "ip6-localhost", "ip6-loopback"}
VIEWER_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
}
# Strict fallback for any report.html the viewer did not recognisably render itself
# (pre-viewer pages: inline style only, no script). Scripts stay blocked by default-src.
LEGACY_REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'"
_CSP_META = re.compile(rb'<meta http-equiv="Content-Security-Policy" content="([^"]*)"', re.I)
# The exact shape `render.static_csp` emits; anything else is not ours.
_VIEWER_CSP_SHAPE = re.compile(
    r"^default-src 'none'; script-src 'sha256-[A-Za-z0-9+/]+=*'; style-src 'sha256-[A-Za-z0-9+/]+=*'; "
    r"base-uri 'none'; form-action 'none'$"
)


def viewer_csp_header(page: bytes) -> str:
    """The page's own CSP meta as a response header, plus `frame-ancestors 'none'`.

    Only a meta in the `<head>` (before the first `<body`) that matches the exact
    policy shape the viewer renders is echoed — the hashes belong to that file's
    inline script/style. Attacker text lives in the body of pre-Phase-0 pages and
    may carry its own permissive meta; that never becomes the header. Anything
    else falls back to `LEGACY_REPORT_CSP`.
    """
    head = page.split(b"<body", 1)[0]
    match = _CSP_META.search(head)
    policy = LEGACY_REPORT_CSP
    if match:
        candidate = match.group(1).decode("utf-8", errors="replace")
        if _VIEWER_CSP_SHAPE.match(candidate):
            policy = candidate
    return f"{policy}; frame-ancestors 'none'"


class LoopbackOnlyError(ValueError):
    """Raised when a viewer is asked to bind anything but a loopback address."""


def is_loopback_host(host: str) -> bool:
    candidate = host.strip().strip("[]").lower()
    if candidate in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        return False


def _parse_version(value: object) -> tuple[int, ...]:
    if value is None:
        return (0,)
    try:
        return tuple(int(part) for part in str(value).split("."))
    except ValueError:
        return (0,)


def bundle_format_version(run_dir: Path) -> str | None:
    manifest = run_dir / "run_manifest.json"
    if not manifest.is_file():
        return None
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    version = payload.get("bundle_format_version") if isinstance(payload, dict) else None
    return None if version is None else str(version)


class RunDirHandler(BaseHTTPRequestHandler):
    server_version = "RedplaneView/0.1"
    sys_version = ""
    # Set by build_view_server.
    store: ArtifactStore
    run_id: str
    legacy: bool
    version: str | None

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        # Quiet by default; the CLI prints the URL. Requests carry finding ids.
        return

    def do_GET(self) -> None:  # noqa: N802
        relative = unquote(urlsplit(self.path).path).lstrip("/") or "report.html"
        if self.legacy and relative not in LEGACY_RAW_DOWNLOAD_ALLOWLIST:
            self._text(
                HTTPStatus.CONFLICT,
                f"Bundle format version {self.version or 'unknown'} predates write-time redaction "
                f"({REDACTED_BUNDLE_MIN_VERSION}); only {', '.join(LEGACY_RAW_DOWNLOAD_ALLOWLIST)} are served "
                "for such bundles because other files may contain expanded credentials.",
            )
            return
        try:
            path = self.store.resolve_artifact(self.run_id, relative)
        except ArtifactPathError:
            self._text(HTTPStatus.BAD_REQUEST, "Invalid artifact path")
            return
        except FileNotFoundError:
            self._text(HTTPStatus.NOT_FOUND, "Not found")
            return
        self._file(path, relative)

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def _text(self, status: HTTPStatus, message: str) -> None:
        body = (message + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for key, value in VIEWER_HEADERS.items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _file(self, path: Path, relative: str) -> None:
        payload = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        if is_viewer_file(relative):
            # The one file rendered by us: inline, with its own CSP meta echoed as a
            # header (plus frame-ancestors, which a meta tag cannot express).
            self.send_header("Content-Type", "text/html; charset=utf-8")
            headers = {**VIEWER_HEADERS, "Content-Security-Policy": viewer_csp_header(payload)}
        else:
            # Every other file — including any other .html under raw/ — follows the
            # API policy: text inline under a sandboxing CSP, the rest as attachments.
            policy = artifact_response_policy(relative)
            self.send_header("Content-Type", policy.media_type)
            disposition = policy.content_disposition
            if disposition:
                self.send_header("Content-Disposition", disposition)
            headers = policy.headers
        self.send_header("Content-Length", str(len(payload)))
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)


class ViewServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class ViewServer6(ViewServer):
    address_family = socket.AF_INET6


def build_view_server(run_dir: str | Path, *, host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    """Bind a viewer for `run_dir`. Refuses non-loopback hosts; there is no override."""
    root = Path(run_dir)
    if not root.is_dir():
        raise FileNotFoundError(f"Run directory not found: {root}")
    if not is_loopback_host(host):
        raise LoopbackOnlyError(
            f"urt view binds loopback only; refusing host {host!r}. Use an SSH tunnel to reach it remotely."
        )
    version = bundle_format_version(root)

    class Handler(RunDirHandler):
        pass

    Handler.store = ArtifactStore(root.parent)
    Handler.run_id = root.name
    Handler.legacy = _parse_version(version) < _parse_version(REDACTED_BUNDLE_MIN_VERSION)
    Handler.version = version

    bind_host = host.strip().strip("[]")
    server_cls: type[ThreadingHTTPServer] = ViewServer
    try:
        if ipaddress.ip_address(bind_host).version == 6:
            server_cls = ViewServer6
    except ValueError:
        pass
    return server_cls((bind_host, port), Handler)
