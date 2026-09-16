"""CSRF protection for the state-changing `/ui` routes (waiver create / revoke, login).

Double-submit cookie, bound to the session when there is one:

- `urt_csrf` (`HttpOnly; SameSite=Strict; Path=/ui`) holds a random **nonce**.
- The form carries `csrf_token` = the nonce when no session cookie exists, or
  `HMAC-SHA256(session_cookie_value, nonce)` when it does. Cookies ignore ports, so
  another localhost app could toss its own `urt_csrf` for `127.0.0.1`; binding the
  form token to the `HttpOnly` session value means a tossed nonce alone never
  matches (`hmac.compare_digest` both ways).
- Same-origin checks on `Origin`, `Referer` and `Sec-Fetch-Site`. When a session
  exists, a POST that carries **neither** `Origin` nor `Sec-Fetch-Site` is refused:
  no current browser omits both on a form submission, so that shape is a non-browser
  client that should use the JSON API with a bearer token.

HTMX form posts send the hidden field like a plain form, so no JavaScript is needed
to pass the check. The JSON API is not cookie-authenticated for writes and only
parses `application/json` bodies, so a cross-site HTML form cannot reach it.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from urllib.parse import urlsplit

from fastapi import HTTPException, Request, Response

CSRF_COOKIE = "urt_csrf"
CSRF_FIELD = "csrf_token"
# Name of the auth session cookie (set by `urt.auth` when URT_API_KEY is configured);
# defined here so the CSRF binding does not depend on the auth module.
SESSION_COOKIE = "urt_session"
_TOKEN_BYTES = 32


def issue_nonce() -> str:
    return secrets.token_urlsafe(_TOKEN_BYTES)


def csrf_nonce_for(request: Request) -> str:
    """The nonce this request's cookie carries, or a fresh one to set on the response."""
    return request.cookies.get(CSRF_COOKIE) or issue_nonce()


def form_token(nonce: str, session: str | None) -> str:
    """Token to embed in a form: the nonce alone, or HMAC(session, nonce) when a session exists."""
    if not session:
        return nonce
    return hmac.new(session.encode("utf-8"), nonce.encode("utf-8"), hashlib.sha256).hexdigest()


def csrf_token_for(request: Request) -> tuple[str, str]:
    """(nonce to set as cookie, token to embed in the form) for this request."""
    nonce = csrf_nonce_for(request)
    return nonce, form_token(nonce, request.cookies.get(SESSION_COOKIE))


def set_csrf_cookie(response: Response, nonce: str, *, secure: bool = False) -> None:
    response.set_cookie(
        CSRF_COOKIE,
        nonce,
        httponly=True,
        samesite="strict",
        secure=secure,
        path="/ui",
    )


def _same_origin(request: Request, url: str) -> bool:
    parts = urlsplit(url)
    if not parts.netloc:
        return False
    return parts.netloc.lower() == str(request.headers.get("host", "")).lower()


def verify_csrf(request: Request, submitted: str | None) -> None:
    """Raise 403 unless the form token matches the (session-bound) cookie nonce and the
    request is same-origin."""
    nonce = request.cookies.get(CSRF_COOKIE, "")
    session = request.cookies.get(SESSION_COOKIE)
    expected = form_token(nonce, session) if nonce else ""
    if not nonce or not submitted or not hmac.compare_digest(expected, submitted):
        raise HTTPException(status_code=403, detail="CSRF token missing or invalid; reload the form and retry")

    origin = request.headers.get("origin")
    fetch_site = request.headers.get("sec-fetch-site")
    if session and not origin and not fetch_site:
        raise HTTPException(
            status_code=403,
            detail="Cross-site request refused: browsers send Origin or Sec-Fetch-Site on form posts; "
            "non-browser clients should use the JSON API with a bearer token",
        )
    if fetch_site and fetch_site not in {"same-origin", "none"}:
        raise HTTPException(status_code=403, detail=f"Cross-site request refused (Sec-Fetch-Site: {fetch_site})")
    if origin and origin != "null" and not _same_origin(request, origin):
        raise HTTPException(status_code=403, detail="Cross-origin request refused")
    if origin in (None, "null"):
        referer = request.headers.get("referer")
        if referer and not _same_origin(request, referer):
            raise HTTPException(status_code=403, detail="Cross-origin request refused")
