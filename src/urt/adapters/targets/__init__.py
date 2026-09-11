"""Target adapters."""

from .copilot import CopilotTargetAdapter
from .foundry import FoundryTargetAdapter
from .http_agent import HttpTargetAdapter

__all__ = ["CopilotTargetAdapter", "FoundryTargetAdapter", "HttpTargetAdapter"]
