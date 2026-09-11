"""Azure AI Foundry target adapter."""

from __future__ import annotations

from .http_agent import HttpTargetAdapter


class FoundryTargetAdapter(HttpTargetAdapter):
    """Foundry adapter built on HTTP target contract.

    Supports these auth keys in target.auth:
    - bearer_token
    - api_key
    - headers (merged)
    """

    @property
    def _headers(self) -> dict[str, str]:
        headers = super()._headers
        bearer = self.spec.auth.get("bearer_token")
        api_key = self.spec.auth.get("api_key")
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        if api_key:
            headers["api-key"] = str(api_key)
        return headers
