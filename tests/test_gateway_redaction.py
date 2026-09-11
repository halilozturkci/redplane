from __future__ import annotations

from urt.gateway.redaction import redact_headers, redact_payload, truncate_text


def test_redact_headers_masks_sensitive_values() -> None:
    headers = {
        "Authorization": "Bearer abc",
        "api-key": "xyz",
        "X-Test": "ok",
    }
    masked = redact_headers(headers, extra={"x-custom-secret"})
    assert masked["Authorization"] == "***REDACTED***"
    assert masked["api-key"] == "***REDACTED***"
    assert masked["X-Test"] == "ok"


def test_redact_payload_masks_nested_keys() -> None:
    payload = {
        "token": "abc",
        "nested": {
            "client_secret": "xyz",
            "value": "visible",
        },
        "items": [{"password": "p1"}, {"safe": "p2"}],
    }
    redacted = redact_payload(payload)
    assert redacted["token"] == "***REDACTED***"
    assert redacted["nested"]["client_secret"] == "***REDACTED***"
    assert redacted["nested"]["value"] == "visible"
    assert redacted["items"][0]["password"] == "***REDACTED***"
    assert redacted["items"][1]["safe"] == "p2"


def test_truncate_text_limits_size() -> None:
    text = "x" * 100
    truncated = truncate_text(text, max_bytes=12)
    assert truncated.startswith("x" * 12)
    assert truncated.endswith("...[TRUNCATED]")
