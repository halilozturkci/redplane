"""Routing model for URT Universal Gateway."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from .config import GatewayConfig, GatewayTargetConfig
from .contracts import RoutingError


@dataclass(slots=True)
class RouteDecision:
    target_id: str
    target: GatewayTargetConfig
    source: str


class GatewayRouter:
    """Resolve target selection from request metadata."""

    def __init__(self, config: GatewayConfig):
        self._config = config

    def resolve(self, *, path: str, headers: dict[str, str], payload: dict[str, Any]) -> RouteDecision:
        mode = self._config.routing.mode
        if mode == "model":
            ordered = (self._from_model, self._from_path, self._from_header, self._from_default)
        elif mode == "path":
            ordered = (self._from_path, self._from_header, self._from_model, self._from_default)
        else:
            ordered = (self._from_header, self._from_path, self._from_model, self._from_default)

        for resolver in ordered:
            match = resolver(path=path, headers=headers, payload=payload)
            if not match:
                continue
            target_id, source = match
            target = self._config.targets.get(target_id)
            if not target:
                raise RoutingError(f"Resolved target '{target_id}' not present in config")
            if not target.enabled:
                raise RoutingError(f"Target '{target_id}' is disabled")
            return RouteDecision(target_id=target_id, target=target, source=source)

        raise RoutingError("Could not resolve target for incoming request")

    def _from_header(self, *, path: str, headers: dict[str, str], payload: dict[str, Any]) -> tuple[str, str] | None:  # noqa: ARG002
        header_key = self._config.routing.header_name.lower()
        value = headers.get(header_key)
        if value:
            return value.strip(), "header"
        return None

    def _from_model(self, *, path: str, headers: dict[str, str], payload: dict[str, Any]) -> tuple[str, str] | None:  # noqa: ARG002
        model = str(payload.get("model", "")).strip()
        prefix = self._config.routing.model_prefix
        if model and model.startswith(prefix):
            return model[len(prefix) :], "model"
        return None

    def _from_path(self, *, path: str, headers: dict[str, str], payload: dict[str, Any]) -> tuple[str, str] | None:  # noqa: ARG002
        route_path = urlparse(path).path
        prefix = self._config.routing.path_prefix
        if route_path.startswith(prefix):
            target_id = route_path[len(prefix) :].strip("/")
            if target_id:
                return target_id, "path"
        return None

    def _from_default(self, *, path: str, headers: dict[str, str], payload: dict[str, Any]) -> tuple[str, str] | None:  # noqa: ARG002
        if self._config.routing.default_target:
            return self._config.routing.default_target, "default"
        if len(self._config.targets) == 1:
            target_id = next(iter(self._config.targets))
            return target_id, "single_target"
        return None
