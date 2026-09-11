"""Connector registry for URT Universal Gateway."""

from __future__ import annotations

from .azure_openai import AzureOpenAIDeploymentConnector
from .base import GatewayConnector
from .copilot_studio import CopilotStudioSDKConnector
from .foundry_agent import FoundryAgentServiceConnector
from .foundry_model import FoundryModelInferenceConnector
from .generic_http import GenericHTTPJSONConnector
from .openai_compatible import OpenAICompatibleHTTPConnector


CONNECTOR_REGISTRY: dict[str, type[GatewayConnector]] = {
    "copilot_studio_sdk": CopilotStudioSDKConnector,
    "foundry_model_inference": FoundryModelInferenceConnector,
    "foundry_agent_service": FoundryAgentServiceConnector,
    "azure_openai_deployment": AzureOpenAIDeploymentConnector,
    "openai_compatible_http": OpenAICompatibleHTTPConnector,
    "generic_http_json": GenericHTTPJSONConnector,
}


__all__ = [
    "GatewayConnector",
    "CONNECTOR_REGISTRY",
    "CopilotStudioSDKConnector",
    "FoundryModelInferenceConnector",
    "FoundryAgentServiceConnector",
    "AzureOpenAIDeploymentConnector",
    "OpenAICompatibleHTTPConnector",
    "GenericHTTPJSONConnector",
]
