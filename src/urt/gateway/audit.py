"""Audit artifact writer for gateway request traces."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import GatewayAuditConfig
from .redaction import redact_headers, redact_payload, truncate_text


class GatewayAuditStore:
    """Persists per-request gateway traces under artifact root."""

    def __init__(self, config: GatewayAuditConfig):
        self._config = config
        self._root = Path(config.artifact_root)
        self._root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _utc_day() -> str:
        return datetime.now(timezone.utc).strftime("%Y%m%d")

    @staticmethod
    def _utc_timestamp() -> str:
        return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")

    def write_trace(self, trace_id: str, payload: dict[str, Any]) -> str:
        day_dir = self._root / self._utc_day()
        day_dir.mkdir(parents=True, exist_ok=True)
        path = day_dir / f"trace-{self._utc_timestamp()}-{trace_id}.json"

        sanitized = self._sanitize(payload)
        path.write_text(json.dumps(sanitized, indent=2, ensure_ascii=False), encoding="utf-8")
        return str(path)

    def _sanitize(self, payload: dict[str, Any]) -> dict[str, Any]:
        body = redact_payload(payload)
        request_block = body.get("request")
        if isinstance(request_block, dict):
            headers = request_block.get("headers")
            if isinstance(headers, dict):
                request_block["headers"] = redact_headers(
                    {str(k): str(v) for k, v in headers.items()},
                    extra=set(self._config.redact_headers),
                )
            if self._config.capture_bodies:
                request_block["body"] = self._truncate_block(request_block.get("body"))
            else:
                request_block["body"] = {"captured": False}

        response_block = body.get("response")
        if isinstance(response_block, dict):
            headers = response_block.get("headers")
            if isinstance(headers, dict):
                response_block["headers"] = redact_headers(
                    {str(k): str(v) for k, v in headers.items()},
                    extra=set(self._config.redact_headers),
                )
            if self._config.capture_bodies:
                response_block["body"] = self._truncate_block(response_block.get("body"))
            else:
                response_block["body"] = {"captured": False}

        return body

    def _truncate_block(self, value: Any) -> Any:
        max_bytes = self._config.max_body_bytes
        if value is None:
            return None
        if isinstance(value, str):
            return truncate_text(value, max_bytes=max_bytes)
        serialized = json.dumps(value, ensure_ascii=False)
        return truncate_text(serialized, max_bytes=max_bytes)
