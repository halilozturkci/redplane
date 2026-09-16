"""Optional shared-secret authentication for `urt serve-api` (G13).

One `URT_API_KEY` is the whole model: no users, roles or tenants (the roadmap's
stated non-goal). When the key is set:

- `/v1/*` (and everything else not listed as public) requires
  `Authorization: Bearer <key>`, compared with `hmac.compare_digest`.
- `/ui/*` accepts either the bearer header or a session cookie that `/ui/login`
  sets after the operator types the key into a form. The cookie value is an
  HMAC of a fixed label under the key, so it never carries the key itself, and it
  is `HttpOnly; SameSite=Strict`.
- The session cookie also authenticates **safe** (`GET`/`HEAD`) requests to
  `/v1/*`, so evidence and JSON links on the pages keep working in a browser.
  Writes to the JSON API still need the bearer header.
- `/healthz`, `/ui/static/*` and `/ui/login` stay public.

Without a key nothing is gated; the CLI then refuses a non-loopback bind unless
`--unsafe-allow-unauthenticated` is passed (see `cli.cmd_serve_api`).
"""

from __future__ import annotations

import hashlib
import hmac
import os
from urllib.parse import quote

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

API_KEY_ENV = "URT_API_KEY"
SESSION_COOKIE = "urt_session"
_SESSION_LABEL = b"urt-ui-session-v1"
PUBLIC_PATHS = ("/healthz", "/ui/login")
PUBLIC_PREFIXES = ("/ui/static/",)
SAFE_METHODS = {"GET", "HEAD"}


def api_key_from_env() -> str | None:
    value = os.environ.get(API_KEY_ENV, "").strip()
    return value or None


def session_token(api_key: str) -> str:
    """Cookie value derived from the key (never the key): HMAC-SHA256 over a fixed label."""
    return hmac.new(api_key.encode("utf-8"), _SESSION_LABEL, hashlib.sha256).hexdigest()


def bearer_matches(request: Request, api_key: str) -> bool:
    header = request.headers.get("authorization", "")
    scheme, _, credential = header.partition(" ")
    if scheme.lower() != "bearer" or not credential:
        return False
    return hmac.compare_digest(credential.strip(), api_key)


def session_matches(request: Request, api_key: str) -> bool:
    cookie = request.cookies.get(SESSION_COOKIE, "")
    return bool(cookie) and hmac.compare_digest(cookie, session_token(api_key))


def is_public(path: str) -> bool:
    return path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES)


def is_authenticated(request: Request, api_key: str) -> bool:
    if bearer_matches(request, api_key):
        return True
    if not session_matches(request, api_key):
        return False
    path = request.url.path
    return path.startswith("/ui") or request.method in SAFE_METHODS


def safe_next(target: str | None) -> str:
    """Only same-app `/ui...` paths are honoured after login (no open redirect)."""
    if target and target.startswith("/ui") and not target.startswith("//") and "\\" not in target:
        return target
    return "/ui"


def set_session_cookie(response: Response, api_key: str, *, secure: bool = False) -> None:
    response.set_cookie(SESSION_COOKIE, session_token(api_key), httponly=True, samesite="strict", secure=secure, path="/")


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")


def install_auth(app: FastAPI, api_key: str | None) -> None:
    """Gate every request behind the key when one is configured."""
    app.state.api_key = api_key
    if not api_key:
        return

    @app.middleware("http")
    async def _require_key(request: Request, call_next):  # type: ignore[no-untyped-def]
        path = request.url.path
        if is_public(path) or is_authenticated(request, api_key):
            return await call_next(request)
        if path.startswith("/ui") and request.method in SAFE_METHODS:
            target = path + (f"?{request.url.query}" if request.url.query else "")
            return RedirectResponse(f"/ui/login?next={quote(target, safe='')}", status_code=303)
        return JSONResponse(
            {"detail": "Authentication required: send Authorization: Bearer <URT_API_KEY>"},
            status_code=401,
            headers={"WWW-Authenticate": 'Bearer realm="redplane"'},
        )
