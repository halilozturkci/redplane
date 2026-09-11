"""OpenAI-compatible HTTP connector."""

from __future__ import annotations

from typing import Any

from ..contracts import ChatRequest, ChatResult, ConnectorError
from .base import GatewayConnector


class OpenAICompatibleHTTPConnector(GatewayConnector):
    """Connector for providers exposing OpenAI-like chat completion API."""

    connector_name = "openai_compatible_http"

    def resolve_endpoint(self) -> str:
        endpoint = self.target.endpoint or self.target.config.get("endpoint")
        if not endpoint:
            raise ConnectorError(
                f"{self.connector_name} requires target.endpoint or target.config.endpoint",
                status_code=400,
                code="invalid_connector_config",
            )
        return str(endpoint)

    def build_payload(self, chat_request: ChatRequest) -> dict[str, Any]:
        payload = dict(chat_request.payload)
        payload["messages"] = chat_request.messages
        if not payload.get("model") and self.target.config.get("model"):
            payload["model"] = str(self.target.config.get("model"))
        return payload

    def chat_completion(self, chat_request: ChatRequest) -> ChatResult:
        endpoint = self.resolve_endpoint()
        payload = self.build_payload(chat_request)
        headers = self.build_auth_headers(self.target.auth)
        status, response_payload, _, _ = self.request_json(
            method="POST",
            url=endpoint,
            headers=headers,
            payload=payload,
        )
        content = self.extract_openai_content(response_payload)
        model = str(response_payload.get("model", payload.get("model", "")))
        usage = response_payload.get("usage")
        return ChatResult(
            content=content,
            model=model,
            finish_reason="stop",
            usage=usage if isinstance(usage, dict) else {},
            raw_response=response_payload,
            metadata={"http_status": status, "endpoint": endpoint},
        )
