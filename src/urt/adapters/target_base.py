"""Target adapter base interfaces."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ..types import TargetSpec, TargetResponse


class TargetAdapter(ABC):
    """Abstract target adapter."""

    def __init__(self, spec: TargetSpec):
        self.spec = spec
        self.connect_timeout_seconds = 10
        self.request_timeout_seconds = 60

    def apply_runtime(self, *, connect_seconds: int, request_seconds: int) -> None:
        self.connect_timeout_seconds = int(connect_seconds)
        self.request_timeout_seconds = int(request_seconds)

    @abstractmethod
    def healthcheck(self) -> tuple[bool, str]:
        """Validate target reachability and credentials."""

    @abstractmethod
    def start_session(self) -> str:
        """Start target session and return session id."""

    @abstractmethod
    def send(self, session_id: str, messages: list[dict[str, str]], context: dict[str, Any] | None = None) -> TargetResponse:
        """Send messages to target and return response."""

    @abstractmethod
    def end_session(self, session_id: str) -> None:
        """Close target session."""
