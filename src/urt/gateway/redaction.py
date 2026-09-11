"""Redaction helpers for gateway audit trails."""

from __future__ import annotations

from typing import Any


DEFAULT_SENSITIVE_KEYS = (
    "authorization",
    "api-key",
    "api_key",
    "x-api-key",
    "token",
    "secret",
    "password",
    "client_secret",
    "bearer_token",
)


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in DEFAULT_SENSITIVE_KEYS)


def redact_headers(headers: dict[str, str], *, extra: set[str] | None = None) -> dict[str, str]:
    """Mask sensitive header values."""
    extra_keys = {item.lower() for item in (extra or set())}
    masked: dict[str, str] = {}
    for key, value in headers.items():
        lowered = key.lower()
        if lowered in extra_keys or _is_sensitive_key(lowered):
            masked[key] = "***REDACTED***"
        else:
            masked[key] = value
    return masked


def redact_payload(payload: Any) -> Any:
    """Recursively redact sensitive keys from dict/list payloads."""
    if isinstance(payload, dict):
        out: dict[str, Any] = {}
        for key, value in payload.items():
            if _is_sensitive_key(str(key)):
                out[str(key)] = "***REDACTED***"
            else:
                out[str(key)] = redact_payload(value)
        return out
    if isinstance(payload, list):
        return [redact_payload(item) for item in payload]
    return payload


def truncate_text(value: str, *, max_bytes: int) -> str:
    """Limit audit text size while preserving valid UTF-8."""
    raw = value.encode("utf-8", errors="replace")
    if len(raw) <= max_bytes:
        return value
    clipped = raw[:max_bytes]
    return clipped.decode("utf-8", errors="ignore") + "...[TRUNCATED]"
