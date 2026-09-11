"""Azure AI Foundry model inference connector."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..contracts import ConnectorError
from .openai_compatible import OpenAICompatibleHTTPConnector


class FoundryModelInferenceConnector(OpenAICompatibleHTTPConnector):
    """Connector for Foundry model inference `chat/completions` endpoint."""

    connector_name = "foundry_model_inference"

    def resolve_endpoint(self) -> str:
        endpoint = self.target.endpoint or self.target.config.get("endpoint")
        if endpoint:
            return self._append_api_version(str(endpoint))

        base_url = self.target.config.get("base_url")
        if not base_url:
            raise ConnectorError(
                "foundry_model_inference requires target.endpoint or config.base_url",
                status_code=400,
                code="invalid_connector_config",
            )
        path = str(self.target.config.get("path", "/models/chat/completions"))
        url = str(base_url).rstrip("/") + "/" + path.lstrip("/")
        return self._append_api_version(url)

    def _append_api_version(self, endpoint: str) -> str:
        api_version = self.target.config.get("api_version")
        if not api_version:
            return endpoint

        query_key = str(self.target.config.get("api_version_query_key", "api-version"))
        parts = urlparse(endpoint)
        query = dict(parse_qsl(parts.query, keep_blank_values=True))
        query[query_key] = str(api_version)
        return urlunparse(parts._replace(query=urlencode(query)))
