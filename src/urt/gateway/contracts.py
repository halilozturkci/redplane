"""Contracts and shared models for URT Universal Gateway."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class ConnectorError(RuntimeError):
    """Connector invocation failure with HTTP mapping metadata."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "connector_error",
        status_code: int = 502,
        detail: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.detail = detail or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "error": self.code,
            "message": str(self),
            "detail": self.detail,
            "status_code": self.status_code,
        }


class RoutingError(ValueError):
    """Raised when gateway routing cannot resolve target."""


@dataclass(slots=True)
class ChatRequest:
    """Normalized chat request passed into connector implementations."""

    trace_id: str
    model: str
    messages: list[dict[str, Any]]
    payload: dict[str, Any]
    headers: dict[str, str]
    context: dict[str, Any] = field(default_factory=dict)
    session_id: str | None = None


@dataclass(slots=True)
class ChatResult:
    """Normalized chat result returned from connectors."""

    content: str
    model: str = ""
    finish_reason: str = "stop"
    usage: dict[str, Any] = field(default_factory=dict)
    raw_response: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
