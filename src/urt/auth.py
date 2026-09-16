"""Optional shared-secret authentication for `urt serve-api` (G13).

One `URT_API_KEY` is the whole model: no users, roles or tenants (the roadmap's
stated non-goal). When the key is set:

- `/v1/*` (and everything else not listed as public) requires
  `Authorization: Bearer <key>`, compared with `hmac.compare_digest`.
- `/ui/*` accepts either the bearer header or a session cookie that `/ui/login`
  sets after the operator types the key into a form. The cookie value is
  `<issued_at>.<nonce>.<HMAC-SHA256(key || per-process secret, issued_at.nonce)>`: it never
  carries the key, every login issues a different value, a server restart
  invalidates all outstanding cookies (fresh process secret), `POST /ui/logout`
  revokes the nonce server-side (a captured copy stops working at logout), and
  `Max-Age` / `SESSION_MAX_AGE_SECONDS` bound one that was never logged out. It is
  `HttpOnly; SameSite=Strict`.
- The session cookie also authenticates **safe** (`GET`/`HEAD`) requests to
  `/v1/*`, so evidence and JSON links on the pages keep working in a browser.
  Writes to the JSON API still need the bearer header.
- `/healthz`, `/ui/static/*` and `/ui/login` stay public.
- Keys shorter than `MIN_API_KEY_LENGTH` are refused at startup, and every request
  that *offers* a wrong credential (bad bearer, bad login, forged cookie) is delayed
  by `FAILED_AUTH_DELAY_SECONDS` before the 401 — a constant cost per guess.

Without a key nothing is gated; the CLI then refuses a non-loopback bind unless
`--unsafe-allow-unauthenticated` is passed (see `cli.cmd_serve_api`).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import secrets
import time
from urllib.parse import quote

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

from .ui.csrf import SESSION_COOKIE as CSRF_SESSION_COOKIE

API_KEY_ENV = "URT_API_KEY"
SESSION_COOKIE = CSRF_SESSION_COOKIE  # one name, defined once (the CSRF binding reads it too)
MIN_API_KEY_LENGTH = 16
SESSION_MAX_AGE_SECONDS = 12 * 60 * 60
FAILED_AUTH_DELAY_SECONDS = 0.5
KEY_GENERATION_HINT = "generate one with `openssl rand -hex 32`"
_SESSION_LABEL = b"urt-ui-session-v2"
# Fresh on every process start: a restart invalidates every outstanding session cookie.
_PROCESS_SECRET = secrets.token_bytes(32)
PUBLIC_PATHS = ("/healthz", "/ui/login")
PUBLIC_PREFIXES = ("/ui/static/",)
SAFE_METHODS = {"GET", "HEAD"}


class WeakApiKeyError(ValueError):
    pass


def check_api_key_strength(api_key: str) -> None:
    if len(api_key) < MIN_API_KEY_LENGTH:
        raise WeakApiKeyError(
            f"{API_KEY_ENV} must be at least {MIN_API_KEY_LENGTH} characters "
            f"(got {len(api_key)}); {KEY_GENERATION_HINT}"
        )


def api_key_from_env() -> str | None:
    value = os.environ.get(API_KEY_ENV, "").strip()
    return value or None


def _session_mac(api_key: str, issued_at: int, nonce: str) -> str:
    secret = api_key.encode("utf-8") + _PROCESS_SECRET
    message = _SESSION_LABEL + f"{issued_at}.{nonce}".encode("ascii")
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def issue_session_token(api_key: str, *, now: float | None = None) -> str:
    """Cookie value: `<issued_at>.<nonce>.<mac>`; never the key, different on every login."""
    issued_at = int(time.time() if now is None else now)
    nonce = secrets.token_hex(16)
    return f"{issued_at}.{nonce}.{_session_mac(api_key, issued_at, nonce)}"


# Sessions revoked by `POST /ui/logout`: nonce -> issued_at. In-process like the
# secret that signs them (a restart invalidates everything anyway); pruned of entries
# older than SESSION_MAX_AGE_SECONDS, which could no longer validate regardless.
_REVOKED_NONCES: dict[str, int] = {}


def _split_token(token: str | None) -> tuple[int, str, str] | None:
    parts = (token or "").split(".")
    if len(parts) != 3 or not parts[0].isdigit():
        return None
    return int(parts[0]), parts[1], parts[2]


def revoke_session(token: str | None, *, now: float | None = None) -> None:
    """Server-side logout: the token's nonce is refused from now on."""
    current = int(time.time() if now is None else now)
    for nonce, issued_at in list(_REVOKED_NONCES.items()):
        if current - issued_at > SESSION_MAX_AGE_SECONDS:
            del _REVOKED_NONCES[nonce]
    parsed = _split_token(token)
    if parsed is None:
        return
    issued_at, nonce, _ = parsed
    _REVOKED_NONCES[nonce] = issued_at


def session_is_valid(token: str | None, api_key: str, *, now: float | None = None) -> bool:
    parsed = _split_token(token)
    if parsed is None:
        return False
    issued_at, nonce, mac = parsed
    current = time.time() if now is None else now
    if issued_at > current or current - issued_at > SESSION_MAX_AGE_SECONDS:
        return False
    if nonce in _REVOKED_NONCES:
        return False
    return hmac.compare_digest(mac, _session_mac(api_key, issued_at, nonce))


def key_matches(submitted: str | None, api_key: str) -> bool:
    return bool(submitted) and hmac.compare_digest(str(submitted), api_key)


def bearer_offered(request: Request) -> bool:
    return bool(request.headers.get("authorization"))


def bearer_matches(request: Request, api_key: str) -> bool:
    header = request.headers.get("authorization", "")
    scheme, _, credential = header.partition(" ")
    if scheme.lower() != "bearer" or not credential:
        return False
    return hmac.compare_digest(credential.strip(), api_key)


def session_matches(request: Request, api_key: str) -> bool:
    return session_is_valid(request.cookies.get(SESSION_COOKIE), api_key)


def is_public(path: str) -> bool:
    return path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES)


def is_authenticated(request: Request, api_key: str) -> bool:
    if bearer_matches(request, api_key):
        return True
    if not session_matches(request, api_key):
        return False
    path = request.url.path
    return path.startswith("/ui") or request.method in SAFE_METHODS


def credential_offered(request: Request) -> bool:
    """True when the request carried something that could have been a valid credential."""
    return bearer_offered(request) or SESSION_COOKIE in request.cookies


async def failed_auth_delay() -> None:
    if FAILED_AUTH_DELAY_SECONDS > 0:
        await asyncio.sleep(FAILED_AUTH_DELAY_SECONDS)


def safe_next(target: str | None) -> str:
    """Only same-app `/ui...` paths are honoured after login (no open redirect, no loop)."""
    if (
        target
        and target.startswith("/ui")
        and not target.startswith("//")
        and "\\" not in target
        and not target.startswith(("/ui/login", "/ui/logout"))
    ):
        return target
    return "/ui"


def set_session_cookie(response: Response, api_key: str, *, secure: bool = False) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        issue_session_token(api_key),
        max_age=SESSION_MAX_AGE_SECONDS,
        httponly=True,
        samesite="strict",
        secure=secure,
        path="/",
    )


def clear_session_cookie(response: Response, *, request: Request | None = None) -> None:
    """Delete the client cookie and revoke the session it carried, so a copy of the
    value made before logout fails `session_is_valid` from here on."""
    if request is not None:
        revoke_session(request.cookies.get(SESSION_COOKIE))
    response.delete_cookie(SESSION_COOKIE, path="/")


def install_auth(app: FastAPI, api_key: str | None) -> None:
    """Gate every request behind the key when one is configured."""
    if api_key:
        check_api_key_strength(api_key)
    app.state.api_key = api_key
    if not api_key:
        return

    @app.middleware("http")
    async def _require_key(request: Request, call_next):  # type: ignore[no-untyped-def]
        path = request.url.path
        if is_public(path) or is_authenticated(request, api_key):
            return await call_next(request)
        if credential_offered(request):
            await failed_auth_delay()
        if path.startswith("/ui") and request.method in SAFE_METHODS:
            target = path + (f"?{request.url.query}" if request.url.query else "")
            return RedirectResponse(f"/ui/login?next={quote(target, safe='')}", status_code=303)
        return JSONResponse(
            {"detail": "Authentication required: send Authorization: Bearer <URT_API_KEY>"},
            status_code=401,
            headers={"WWW-Authenticate": 'Bearer realm="redplane"'},
        )
