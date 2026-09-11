from __future__ import annotations

from urt.gateway.config import GatewayConfig
from urt.gateway.router import GatewayRouter


def _base_payload(mode: str) -> dict:
    return {
        "routing": {
            "mode": mode,
            "header_name": "X-URT-Target",
            "model_prefix": "urt/",
            "default_target": "a",
            "path_prefix": "/v1/chat/completions/",
        },
        "targets": {
            "a": {"connector": "generic_http_json", "endpoint": "http://localhost:7000/invoke"},
            "b": {"connector": "generic_http_json", "endpoint": "http://localhost:7001/invoke"},
        },
    }


def test_router_header_mode_prefers_header() -> None:
    cfg = GatewayConfig.from_dict(_base_payload("header"))
    router = GatewayRouter(cfg)
    decision = router.resolve(
        path="/v1/chat/completions",
        headers={"x-urt-target": "b"},
        payload={"model": "urt/a", "messages": []},
    )
    assert decision.target_id == "b"
    assert decision.source == "header"


def test_router_model_mode_prefers_model_prefix() -> None:
    cfg = GatewayConfig.from_dict(_base_payload("model"))
    router = GatewayRouter(cfg)
    decision = router.resolve(
        path="/v1/chat/completions",
        headers={"x-urt-target": "a"},
        payload={"model": "urt/b", "messages": []},
    )
    assert decision.target_id == "b"
    assert decision.source == "model"


def test_router_path_mode_prefers_path_segment() -> None:
    cfg = GatewayConfig.from_dict(_base_payload("path"))
    router = GatewayRouter(cfg)
    decision = router.resolve(
        path="/v1/chat/completions/b",
        headers={},
        payload={"model": "", "messages": []},
    )
    assert decision.target_id == "b"
    assert decision.source == "path"


def test_router_falls_back_to_default() -> None:
    cfg = GatewayConfig.from_dict(_base_payload("header"))
    router = GatewayRouter(cfg)
    decision = router.resolve(
        path="/v1/chat/completions",
        headers={},
        payload={"messages": []},
    )
    assert decision.target_id == "a"
    assert decision.source == "default"
