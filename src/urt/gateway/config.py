"""Configuration loader and validators for URT Universal Gateway."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import expand_env_vars


SUPPORTED_CONNECTORS = {
    "copilot_studio_sdk",
    "foundry_model_inference",
    "foundry_agent_service",
    "azure_openai_deployment",
    "openai_compatible_http",
    "generic_http_json",
}


class GatewayConfigError(ValueError):
    """Raised when gateway config is invalid."""


@dataclass(slots=True)
class GatewayServerConfig:
    host: str = "127.0.0.1"
    port: int = 18080
    request_timeout_seconds: int = 90
    log_level: str = "INFO"
    session_ttl_seconds: float = 300.0
    api_key: str | None = None
    session_persist_path: str | None = None

    @classmethod
    def from_dict(cls, payload: dict[str, Any] | None) -> "GatewayServerConfig":
        if not payload:
            return cls()
        host = str(payload.get("host", "127.0.0.1")).strip() or "127.0.0.1"
        port = int(payload.get("port", 18080))
        timeout = int(payload.get("request_timeout_seconds", 90))
        if port < 0 or port > 65535:
            raise GatewayConfigError("gateway.port must be in range 0..65535")
        if timeout <= 0:
            raise GatewayConfigError("gateway.request_timeout_seconds must be > 0")
        session_ttl = float(payload.get("session_ttl_seconds", 300.0))
        if session_ttl <= 0:
            raise GatewayConfigError("gateway.session_ttl_seconds must be > 0")
        api_key_raw = payload.get("api_key")
        api_key = str(api_key_raw).strip() if api_key_raw else None
        persist_raw = payload.get("session_persist_path")
        persist_path = str(persist_raw).strip() if persist_raw else None
        return cls(
            host=host,
            port=port,
            request_timeout_seconds=timeout,
            log_level=str(payload.get("log_level", "INFO")).upper(),
            session_ttl_seconds=session_ttl,
            api_key=api_key or None,
            session_persist_path=persist_path or None,
        )


@dataclass(slots=True)
class GatewayRoutingConfig:
    mode: str = "header"
    header_name: str = "X-URT-Target"
    model_prefix: str = "urt/"
    default_target: str | None = None
    path_prefix: str = "/v1/chat/completions/"

    @classmethod
    def from_dict(cls, payload: dict[str, Any] | None) -> "GatewayRoutingConfig":
        if not payload:
            return cls()
        mode = str(payload.get("mode", "header")).strip().lower()
        if mode not in {"header", "model", "path"}:
            raise GatewayConfigError("routing.mode must be one of: header, model, path")
        path_prefix = str(payload.get("path_prefix", "/v1/chat/completions/")).strip() or "/v1/chat/completions/"
        if not path_prefix.startswith("/"):
            raise GatewayConfigError("routing.path_prefix must start with '/'")
        return cls(
            mode=mode,
            header_name=str(payload.get("header_name", "X-URT-Target")).strip() or "X-URT-Target",
            model_prefix=str(payload.get("model_prefix", "urt/")).strip() or "urt/",
            default_target=(str(payload.get("default_target")).strip() if payload.get("default_target") else None),
            path_prefix=path_prefix,
        )


@dataclass(slots=True)
class GatewayAuditConfig:
    artifact_root: str = ".urt_state/gateway"
    capture_bodies: bool = True
    max_body_bytes: int = 65536
    redact_headers: list[str] = field(default_factory=lambda: ["authorization", "api-key", "x-api-key"])

    @classmethod
    def from_dict(cls, payload: dict[str, Any] | None) -> "GatewayAuditConfig":
        if not payload:
            return cls()
        max_body_bytes = int(payload.get("max_body_bytes", 65536))
        if max_body_bytes <= 0:
            raise GatewayConfigError("audit.max_body_bytes must be > 0")
        redacted = payload.get("redact_headers", ["authorization", "api-key", "x-api-key"])
        if not isinstance(redacted, list):
            raise GatewayConfigError("audit.redact_headers must be a list")
        return cls(
            artifact_root=str(payload.get("artifact_root", ".urt_state/gateway")),
            capture_bodies=bool(payload.get("capture_bodies", True)),
            max_body_bytes=max_body_bytes,
            redact_headers=[str(item).lower() for item in redacted],
        )


@dataclass(slots=True)
class GatewayTargetConfig:
    target_id: str
    connector: str
    endpoint: str | None = None
    auth: dict[str, Any] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    retry_attempts: int = 1
    retry_backoff_seconds: float = 1.0

    @classmethod
    def from_pair(cls, target_id: str, payload: dict[str, Any]) -> "GatewayTargetConfig":
        if not isinstance(payload, dict):
            raise GatewayConfigError(f"targets.{target_id} must be an object")
        connector = str(payload.get("connector", "")).strip().lower()
        if connector not in SUPPORTED_CONNECTORS:
            raise GatewayConfigError(
                f"targets.{target_id}.connector must be one of {sorted(SUPPORTED_CONNECTORS)}"
            )
        endpoint = payload.get("endpoint")
        if endpoint is not None:
            endpoint = str(endpoint).strip()
        return cls(
            target_id=target_id,
            connector=connector,
            endpoint=endpoint,
            auth=dict(payload.get("auth", {})),
            config=dict(payload.get("config", {})),
            enabled=bool(payload.get("enabled", True)),
            retry_attempts=int(payload.get("retry_attempts", 1)),
            retry_backoff_seconds=float(payload.get("retry_backoff_seconds", 1.0)),
        )


@dataclass(slots=True)
class GatewayConfig:
    gateway: GatewayServerConfig = field(default_factory=GatewayServerConfig)
    routing: GatewayRoutingConfig = field(default_factory=GatewayRoutingConfig)
    audit: GatewayAuditConfig = field(default_factory=GatewayAuditConfig)
    targets: dict[str, GatewayTargetConfig] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "GatewayConfig":
        if not isinstance(payload, dict):
            raise GatewayConfigError("Gateway config must be an object")

        targets_raw = payload.get("targets", {})
        if not isinstance(targets_raw, dict) or not targets_raw:
            raise GatewayConfigError("targets must be a non-empty object")

        targets: dict[str, GatewayTargetConfig] = {}
        for target_id, target_payload in targets_raw.items():
            name = str(target_id).strip()
            if not name:
                raise GatewayConfigError("target ids cannot be empty")
            targets[name] = GatewayTargetConfig.from_pair(name, target_payload)

        gateway = GatewayServerConfig.from_dict(payload.get("gateway"))
        routing = GatewayRoutingConfig.from_dict(payload.get("routing"))
        audit = GatewayAuditConfig.from_dict(payload.get("audit"))

        if routing.default_target and routing.default_target not in targets:
            raise GatewayConfigError(
                f"routing.default_target '{routing.default_target}' not found in targets"
            )

        return cls(gateway=gateway, routing=routing, audit=audit, targets=targets)

    def to_dict(self) -> dict[str, Any]:
        return {
            "gateway": {
                "host": self.gateway.host,
                "port": self.gateway.port,
                "request_timeout_seconds": self.gateway.request_timeout_seconds,
                "log_level": self.gateway.log_level,
                "session_ttl_seconds": self.gateway.session_ttl_seconds,
                "api_key": self.gateway.api_key,
                "session_persist_path": self.gateway.session_persist_path,
            },
            "routing": {
                "mode": self.routing.mode,
                "header_name": self.routing.header_name,
                "model_prefix": self.routing.model_prefix,
                "default_target": self.routing.default_target,
                "path_prefix": self.routing.path_prefix,
            },
            "audit": {
                "artifact_root": self.audit.artifact_root,
                "capture_bodies": self.audit.capture_bodies,
                "max_body_bytes": self.audit.max_body_bytes,
                "redact_headers": self.audit.redact_headers,
            },
            "targets": {
                target_id: {
                    "connector": target.connector,
                    "endpoint": target.endpoint,
                    "auth": target.auth,
                    "config": target.config,
                    "enabled": target.enabled,
                    "retry_attempts": target.retry_attempts,
                    "retry_backoff_seconds": target.retry_backoff_seconds,
                }
                for target_id, target in self.targets.items()
            },
        }


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        import yaml  # type: ignore
    except ImportError as exc:
        raise RuntimeError("PyYAML is required for gateway YAML configs.") from exc
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise GatewayConfigError("Gateway config YAML must be an object")
    return payload


def load_gateway_config(path: str | Path | None = None) -> GatewayConfig:
    """Load gateway config from YAML/JSON file path or `URT_GATEWAY_CONFIG` env."""
    cfg_path_raw = path or os.getenv("URT_GATEWAY_CONFIG")
    if not cfg_path_raw:
        raise GatewayConfigError("Gateway config path is required (--config or URT_GATEWAY_CONFIG)")

    cfg_path = Path(str(cfg_path_raw)).expanduser()
    if not cfg_path.exists():
        raise FileNotFoundError(f"Gateway config not found: {cfg_path}")

    suffix = cfg_path.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        payload = _load_yaml(cfg_path)
    elif suffix == ".json":
        payload = json.loads(cfg_path.read_text(encoding="utf-8"))
    else:
        raise GatewayConfigError("Unsupported gateway config format. Use .yaml/.yml/.json")

    expanded = expand_env_vars(payload)
    return GatewayConfig.from_dict(expanded)
