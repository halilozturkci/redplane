"""Azure OpenAI deployment connector."""

from __future__ import annotations

from urllib.parse import urlencode

from ..contracts import ChatRequest, ConnectorError
from .openai_compatible import OpenAICompatibleHTTPConnector


class AzureOpenAIDeploymentConnector(OpenAICompatibleHTTPConnector):
    """Connector for Azure OpenAI deployment-style chat completions endpoint."""

    connector_name = "azure_openai_deployment"

    def resolve_endpoint(self) -> str:
        endpoint = self.target.endpoint or self.target.config.get("endpoint")
        if endpoint:
            return str(endpoint)

        resource_url = self.target.config.get("resource_url")
        deployment = self.target.config.get("deployment")
        api_version = self.target.config.get("api_version")
        if not resource_url or not deployment or not api_version:
            raise ConnectorError(
                "azure_openai_deployment requires endpoint or config.resource_url + config.deployment + config.api_version",
                status_code=400,
                code="invalid_connector_config",
            )

        query = urlencode({"api-version": str(api_version)})
        return (
            f"{str(resource_url).rstrip('/')}/openai/deployments/{deployment}/chat/completions?{query}"
        )

    def build_payload(self, chat_request: ChatRequest) -> dict:
        payload = super().build_payload(chat_request)
        if bool(self.target.config.get("strip_model", True)):
            payload.pop("model", None)
        return payload
