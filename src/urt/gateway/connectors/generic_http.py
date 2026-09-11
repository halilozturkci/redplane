"""Generic JSON-over-HTTP connector."""

from __future__ import annotations

from ..contracts import ChatRequest, ChatResult, ConnectorError
from .base import GatewayConnector


class GenericHTTPJSONConnector(GatewayConnector):
    """Connector for generic callback APIs with JSON request/response."""

    connector_name = "generic_http_json"

    def chat_completion(self, chat_request: ChatRequest) -> ChatResult:
        endpoint = self.target.endpoint or self.target.config.get("endpoint")
        if not endpoint:
            raise ConnectorError(
                "generic_http_json requires target.endpoint",
                status_code=400,
                code="invalid_connector_config",
            )

        request_template = self.target.config.get("request_template")
        if isinstance(request_template, dict):
            payload = dict(request_template)
            payload["messages"] = chat_request.messages
            payload["session_id"] = self.build_session_id()
            payload["context"] = chat_request.context
        else:
            payload = {
                "messages": chat_request.messages,
                "session_id": self.build_session_id(),
                "context": chat_request.context,
            }

        headers = self.build_auth_headers(self.target.auth)
        method = str(self.target.config.get("method", "POST"))
        status, response_payload, _, _ = self.request_json(
            method=method,
            url=str(endpoint),
            headers=headers,
            payload=payload,
        )
        content = self.extract_generic_content(response_payload)
        return ChatResult(
            content=content,
            model=str(chat_request.model),
            raw_response=response_payload,
            metadata={"http_status": status, "endpoint": str(endpoint)},
        )
