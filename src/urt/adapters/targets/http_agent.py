"""Generic HTTP target adapter."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any
from urllib import request, error

from ..target_base import TargetAdapter
from ...runtime import RequestRateLimiter
from ...types import TargetResponse


class HttpTargetAdapter(TargetAdapter):
    """Generic HTTP callback target.

    Expected default contract:
    - Request JSON: {"messages": [...], "context": {...}, "session_id": "..."}
    - Response JSON can include one of:
      - {"content": "..."}
      - {"messages": [{"role": "assistant", "content": "..."}]}
      - {"output": "..."}
    """

    def __init__(self, spec):
        super().__init__(spec)
        self._rate_limiter = RequestRateLimiter()

    @property
    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        auth_headers = self.spec.auth.get("headers", {})
        if isinstance(auth_headers, dict):
            for key, value in auth_headers.items():
                headers[str(key)] = str(value)
        return headers

    def _extract_content(self, payload: dict[str, Any]) -> str:
        if isinstance(payload.get("content"), str):
            return payload["content"]
        if isinstance(payload.get("output"), str):
            return payload["output"]
        messages = payload.get("messages")
        if isinstance(messages, list):
            for msg in reversed(messages):
                if isinstance(msg, dict) and msg.get("role") == "assistant" and isinstance(msg.get("content"), str):
                    return msg["content"]
        return json.dumps(payload, ensure_ascii=False)

    def healthcheck(self) -> tuple[bool, str]:
        if not self.spec.endpoint:
            return False, "target.endpoint is required for http target"

        if self.spec.config.get("skip_healthcheck", False):
            return True, "healthcheck skipped by config"

        probe_path = self.spec.config.get("healthcheck_path")
        url = self.spec.endpoint if not probe_path else self.spec.endpoint.rstrip("/") + "/" + str(probe_path).lstrip("/")

        try:
            req = request.Request(url=url, method="GET", headers=self._headers)
            timeout = int(self.spec.config.get("healthcheck_timeout", self.connect_timeout_seconds))
            with request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                code = int(resp.status)
            if 200 <= code < 400:
                return True, f"healthcheck OK ({code})"
            return False, f"healthcheck returned HTTP {code}"
        except Exception as exc:  # noqa: BLE001
            return False, f"healthcheck failed: {exc}"

    def start_session(self) -> str:
        return str(uuid.uuid4())

    def send(self, session_id: str, messages: list[dict[str, str]], context: dict[str, Any] | None = None) -> TargetResponse:
        if not self.spec.endpoint:
            raise ValueError("target.endpoint is required")

        body_template = self.spec.config.get("request_template")
        if isinstance(body_template, dict):
            payload = dict(body_template)
            payload["messages"] = messages
            payload["session_id"] = session_id
            payload["context"] = context or {}
        else:
            payload = {
                "messages": messages,
                "session_id": session_id,
                "context": context or {},
            }

        self._rate_limiter.wait(self.spec.rate_limits)
        timeout_seconds = int(self.spec.config.get("timeout_seconds", self.request_timeout_seconds))
        retry_attempts = int(self.spec.config.get("retry_attempts", 1))
        retry_backoff_seconds = float(self.spec.config.get("retry_backoff_seconds", 1.0))
        retry_on_status = set(self.spec.config.get("retry_on_status", [429, 500, 502, 503, 504]))

        raw_payload: dict[str, Any] = {}
        raw_text = ""
        last_exception: Exception | None = None

        for attempt in range(1, retry_attempts + 1):
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            req = request.Request(
                url=self.spec.endpoint,
                data=body,
                method=str(self.spec.config.get("method", "POST")),
                headers=self._headers,
            )

            try:
                with request.urlopen(req, timeout=timeout_seconds) as resp:  # noqa: S310
                    raw_text = resp.read().decode("utf-8")
                    raw_payload = json.loads(raw_text)
                break
            except error.HTTPError as exc:
                raw_text = exc.read().decode("utf-8", errors="replace")
                raw_payload = {
                    "error": "http_error",
                    "status": exc.code,
                    "body": raw_text,
                    "attempt": attempt,
                }
                if attempt < retry_attempts and exc.code in retry_on_status:
                    time.sleep(retry_backoff_seconds * attempt)
                    continue
                break
            except json.JSONDecodeError:
                raw_payload = {"output": raw_text, "attempt": attempt}
                break
            except Exception as exc:  # noqa: BLE001
                last_exception = exc
                raw_payload = {"error": "request_failed", "detail": str(exc), "attempt": attempt}
                if attempt < retry_attempts:
                    time.sleep(retry_backoff_seconds * attempt)
                    continue
                break

        if last_exception is not None:
            raw_payload.setdefault("detail", str(last_exception))

        content = self._extract_content(raw_payload)
        return TargetResponse(content=content, raw=raw_payload)

    def end_session(self, session_id: str) -> None:  # noqa: ARG002
        return
