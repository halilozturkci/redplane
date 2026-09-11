"""Base connector implementation for URT Universal Gateway."""

from __future__ import annotations

import json
import time
import uuid
from abc import ABC, abstractmethod
from typing import Any
from urllib import error, request

from ..config import GatewayTargetConfig
from ..contracts import ChatRequest, ChatResult, ConnectorError


class GatewayConnector(ABC):
    """Abstract base class for gateway connectors."""

    connector_name: str = "base"

    def __init__(self, target: GatewayTargetConfig, *, timeout_seconds: int):
        self.target = target
        self.timeout_seconds = timeout_seconds

    @abstractmethod
    def chat_completion(self, chat_request: ChatRequest) -> ChatResult:
        """Execute chat request against backend and return normalized result."""

    def healthcheck(self) -> tuple[bool, str]:
        if self.target.endpoint or self.target.config.get("base_url"):
            return True, "connector configuration looks valid"
        return True, "healthcheck skipped (no endpoint/base_url requirement)"

    @staticmethod
    def latest_user_message(messages: list[dict[str, Any]]) -> str:
        for msg in reversed(messages):
            if not isinstance(msg, dict):
                continue
            if str(msg.get("role")) != "user":
                continue
            content = msg.get("content")
            if isinstance(content, str):
                return content
            if isinstance(content, list):
                parts: list[str] = []
                for item in content:
                    if isinstance(item, dict):
                        text = item.get("text")
                        if isinstance(text, str):
                            parts.append(text)
                        elif isinstance(text, dict) and isinstance(text.get("value"), str):
                            parts.append(text["value"])
                if parts:
                    return "\n".join(parts).strip()
        return ""

    @staticmethod
    def build_auth_headers(auth: dict[str, Any]) -> dict[str, str]:
        headers: dict[str, str] = {}
        raw_headers = auth.get("headers")
        if isinstance(raw_headers, dict):
            for key, value in raw_headers.items():
                headers[str(key)] = str(value)

        bearer = auth.get("bearer_token")
        if bearer:
            headers.setdefault("Authorization", f"Bearer {bearer}")

        api_key = auth.get("api_key")
        if api_key:
            header_name = str(auth.get("api_key_header", "api-key"))
            headers.setdefault(header_name, str(api_key))

        return headers

    def request_json(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        payload: dict[str, Any] | None = None,
        timeout_seconds: int | None = None,
        retry_attempts: int = 1,
        retry_backoff_seconds: float = 1.0,
    ) -> tuple[int, dict[str, Any], str, dict[str, str]]:
        req_headers = {"Accept": "application/json"}
        if headers:
            req_headers.update(headers)

        if payload is not None:
            req_headers.setdefault("Content-Type", "application/json")

        timeout = timeout_seconds or self.timeout_seconds
        retry_on_status = {429, 500, 502, 503, 504}
        last_exc: Exception | None = None

        for attempt in range(1, retry_attempts + 1):
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else b""
            req = request.Request(
                url=url,
                data=body if payload is not None else None,
                method=method.upper(),
                headers=req_headers,
            )
            try:
                with request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                    raw_bytes = resp.read()
                    raw_text = raw_bytes.decode("utf-8", errors="replace")
                    parsed = self._parse_response_json(raw_text)
                    response_headers = {str(k): str(v) for k, v in resp.headers.items()}
                    return int(resp.status), parsed, raw_text, response_headers
            except error.HTTPError as exc:
                raw_text = exc.read().decode("utf-8", errors="replace")
                parsed = self._parse_response_json(raw_text)
                connector_exc = ConnectorError(
                    f"{self.connector_name} backend returned HTTP {exc.code}",
                    code="http_error",
                    status_code=int(exc.code),
                    detail={"url": url, "response": parsed or raw_text},
                )
                if attempt < retry_attempts and int(exc.code) in retry_on_status:
                    time.sleep(retry_backoff_seconds * attempt)
                    last_exc = connector_exc
                    continue
                raise connector_exc from exc
            except ConnectorError:
                raise
            except Exception as exc:  # noqa: BLE001
                connector_exc = ConnectorError(
                    f"{self.connector_name} request failed: {exc}",
                    code="request_failed",
                    status_code=502,
                    detail={"url": url},
                )
                if attempt < retry_attempts:
                    time.sleep(retry_backoff_seconds * attempt)
                    last_exc = connector_exc
                    continue
                raise connector_exc from exc

        # Should only reach here if all retries exhausted via continue path
        raise last_exc or ConnectorError(  # type: ignore[misc]
            f"{self.connector_name} all retry attempts exhausted",
            code="request_failed",
            status_code=502,
            detail={"url": url},
        )

    @staticmethod
    def _parse_response_json(raw_text: str) -> dict[str, Any]:
        try:
            parsed = json.loads(raw_text)
        except json.JSONDecodeError:
            return {"output": raw_text}
        if isinstance(parsed, dict):
            return parsed
        if isinstance(parsed, list):
            return {"items": parsed}
        return {"output": str(parsed)}

    @staticmethod
    def extract_openai_content(payload: dict[str, Any]) -> str:
        choices = payload.get("choices")
        if isinstance(choices, list):
            for item in choices:
                if not isinstance(item, dict):
                    continue
                message = item.get("message")
                if isinstance(message, dict) and isinstance(message.get("content"), str):
                    return str(message["content"])
                if isinstance(item.get("text"), str):
                    return str(item["text"])
        if isinstance(payload.get("output"), str):
            return payload["output"]
        if isinstance(payload.get("content"), str):
            return payload["content"]
        return json.dumps(payload, ensure_ascii=False)

    @staticmethod
    def extract_generic_content(payload: dict[str, Any]) -> str:
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

    @staticmethod
    def build_session_id() -> str:
        return str(uuid.uuid4())
