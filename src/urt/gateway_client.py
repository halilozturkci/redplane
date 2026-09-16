"""Read-only view of a running gateway from the control plane (sessions, §4.8).

The gateway is a separate stdlib process; its `SessionStore` lives in that process's
memory. The only way to list sessions is to ask it: `GET /v1/sessions` on the gateway
(`UniversalGateway.sessions_payload`). This module fetches that server-side — so the
browser never needs CORS or a second origin — when `URT_GATEWAY_URL` names the
gateway, optionally with `URT_GATEWAY_API_KEY` as the bearer.
"""

from __future__ import annotations

import json
import os
from typing import Any
from urllib import error, request
from urllib.parse import urlsplit

from .constants import GATEWAY_API_KEY_ENV, GATEWAY_URL_ENV

SESSIONS_TIMEOUT_SECONDS = 5.0


class GatewayUnavailable(RuntimeError):
    """The gateway URL is not configured (`configured=False`) or did not answer."""

    def __init__(self, message: str, *, configured: bool) -> None:
        super().__init__(message)
        self.configured = configured


def gateway_url() -> str | None:
    value = os.environ.get(GATEWAY_URL_ENV, "").strip()
    if not value:
        return None
    parts = urlsplit(value)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        return None
    return value.rstrip("/")


def fetch_sessions(*, timeout: float = SESSIONS_TIMEOUT_SECONDS) -> dict[str, Any]:
    """`{count, ttl_seconds, sessions[]}` from the gateway. Raises `GatewayUnavailable`."""
    base = gateway_url()
    if base is None:
        raise GatewayUnavailable(
            f"{GATEWAY_URL_ENV} is not set (or not an http(s) URL); the sessions view needs a running "
            "`urt serve-gateway` to ask, because live sessions exist only in that process",
            configured=False,
        )
    headers = {"Accept": "application/json"}
    api_key = os.environ.get(GATEWAY_API_KEY_ENV, "").strip()
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    try:
        with request.urlopen(request.Request(f"{base}/v1/sessions", headers=headers), timeout=timeout) as resp:  # noqa: S310
            payload = json.loads(resp.read().decode("utf-8"))
    except error.HTTPError as exc:
        raise GatewayUnavailable(f"gateway answered {exc.code} for /v1/sessions", configured=True) from exc
    except (error.URLError, OSError, ValueError) as exc:
        raise GatewayUnavailable(f"gateway at {base} did not answer: {exc}", configured=True) from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("sessions"), list):
        raise GatewayUnavailable("gateway /v1/sessions returned an unexpected payload", configured=True)
    return payload
