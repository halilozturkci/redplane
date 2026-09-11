from __future__ import annotations

from pathlib import Path

import pytest

from urt.gateway.config import GatewayConfigError, load_gateway_config


def test_gateway_config_loads_and_expands_env(tmp_path: Path, monkeypatch) -> None:
    cfg_path = tmp_path / "gateway.yaml"
    monkeypatch.setenv("TEST_GATEWAY_TOKEN", "token-123")
    cfg_path.write_text(
        "gateway:\n"
        "  host: 127.0.0.1\n"
        "  port: 18080\n"
        "routing:\n"
        "  mode: header\n"
        "  default_target: demo\n"
        "targets:\n"
        "  demo:\n"
        "    connector: openai_compatible_http\n"
        "    endpoint: http://127.0.0.1:9999/v1/chat/completions\n"
        "    auth:\n"
        "      bearer_token: ${TEST_GATEWAY_TOKEN}\n",
        encoding="utf-8",
    )

    cfg = load_gateway_config(cfg_path)
    assert cfg.gateway.port == 18080
    assert cfg.routing.default_target == "demo"
    assert cfg.targets["demo"].auth["bearer_token"] == "token-123"


def test_gateway_config_rejects_unknown_connector(tmp_path: Path) -> None:
    cfg_path = tmp_path / "gateway.yaml"
    cfg_path.write_text(
        "targets:\n"
        "  bad:\n"
        "    connector: unknown_connector\n",
        encoding="utf-8",
    )

    with pytest.raises(GatewayConfigError):
        load_gateway_config(cfg_path)


def test_gateway_config_requires_existing_default_target(tmp_path: Path) -> None:
    cfg_path = tmp_path / "gateway.yaml"
    cfg_path.write_text(
        "routing:\n"
        "  default_target: missing\n"
        "targets:\n"
        "  ok:\n"
        "    connector: generic_http_json\n"
        "    endpoint: http://127.0.0.1:7777/invoke\n",
        encoding="utf-8",
    )

    with pytest.raises(GatewayConfigError):
        load_gateway_config(cfg_path)
