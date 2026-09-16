"""CSRF protection for the state-changing `/ui` routes (waiver create / revoke).

Double-submit cookie: the page that renders a form also sets an `HttpOnly;
SameSite=Strict` cookie holding a random token and embeds the same token as a
hidden field; a POST is accepted only when both are present and equal
(`hmac.compare_digest`). On top of that, a request carrying `Origin` or
`Sec-Fetch-Site` must come from this origin. HTMX form posts send the hidden
field like a plain form, so no JavaScript is needed to pass the check.

The JSON API is not cookie-authenticated and only parses `application/json`
bodies, so browsers cannot be made to submit to it from a cross-site form.
"""

from __future__ import annotations

import hmac
import secrets
from urllib.parse import urlsplit

from fastapi import HTTPException, Request, Response

CSRF_COOKIE = "urt_csrf"
CSRF_FIELD = "csrf_token"
_TOKEN_BYTES = 32


def issue_token() -> str:
    return secrets.token_urlsafe(_TOKEN_BYTES)


def csrf_token_for(request: Request) -> str:
    """The token this request's cookie carries, or a fresh one to set on the response."""
    return request.cookies.get(CSRF_COOKIE) or issue_token()


def set_csrf_cookie(response: Response, token: str, *, secure: bool = False) -> None:
    response.set_cookie(
        CSRF_COOKIE,
        token,
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
    """Raise 403 unless the form token matches the cookie and the request is same-origin."""
    cookie = request.cookies.get(CSRF_COOKIE, "")
    if not cookie or not submitted or not hmac.compare_digest(cookie, submitted):
        raise HTTPException(status_code=403, detail="CSRF token missing or invalid; reload the form and retry")

    fetch_site = request.headers.get("sec-fetch-site")
    if fetch_site and fetch_site not in {"same-origin", "none"}:
        raise HTTPException(status_code=403, detail=f"Cross-site request refused (Sec-Fetch-Site: {fetch_site})")

    origin = request.headers.get("origin")
    if origin and origin != "null" and not _same_origin(request, origin):
        raise HTTPException(status_code=403, detail="Cross-origin request refused")
    if origin in (None, "null"):
        referer = request.headers.get("referer")
        if referer and not _same_origin(request, referer):
            raise HTTPException(status_code=403, detail="Cross-origin request refused")
