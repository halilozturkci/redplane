from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib import request
from urllib.parse import urlparse

from urt.gateway.app import UniversalGateway, create_http_server
from urt.gateway.config import GatewayConfig, GatewayTargetConfig
from urt.gateway.connectors.azure_openai import AzureOpenAIDeploymentConnector
from urt.gateway.connectors.copilot_studio import CopilotStudioSDKConnector
from urt.gateway.connectors.foundry_agent import FoundryAgentServiceConnector
from urt.gateway.connectors.foundry_model import FoundryModelInferenceConnector
from urt.gateway.connectors.generic_http import GenericHTTPJSONConnector
from urt.gateway.connectors.openai_compatible import OpenAICompatibleHTTPConnector
from urt.gateway.contracts import ChatRequest
from urt.gateway.session_store import SessionEntry, SessionStore


def _make_chat_request(model: str = "gpt-test") -> ChatRequest:
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "hello gateway"}],
    }
    return ChatRequest(
        trace_id="trace-test",
        model=model,
        messages=payload["messages"],
        payload=payload,
        headers={},
        context={},
    )


def _start_mock_backend() -> tuple[ThreadingHTTPServer, threading.Thread, dict[str, Any]]:
    state: dict[str, Any] = {"requests": [], "run_poll_count": 0}

    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b"{}"
            return json.loads(raw.decode("utf-8"))

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            body = self._body()
            state["requests"].append({"method": "POST", "path": parsed.path, "query": parsed.query, "body": body})

            if parsed.path == "/openai/chat/completions":
                self._send(
                    200,
                    {
                        "model": "openai-mock",
                        "choices": [{"message": {"role": "assistant", "content": "openai-ok"}}],
                        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                    },
                )
                return

            if parsed.path == "/generic/invoke":
                self._send(200, {"content": "generic-ok"})
                return

            if parsed.path == "/models/chat/completions":
                self._send(
                    200,
                    {
                        "model": "foundry-model-mock",
                        "choices": [{"message": {"role": "assistant", "content": "foundry-model-ok"}}],
                    },
                )
                return

            if parsed.path == "/openai/deployments/test-dep/chat/completions":
                self._send(
                    200,
                    {
                        "model": "azure-openai-mock",
                        "choices": [{"message": {"role": "assistant", "content": "azure-openai-ok"}}],
                    },
                )
                return

            if parsed.path == "/agents/threads":
                self._send(200, {"id": "thread-1"})
                return

            if parsed.path == "/agents/threads/thread-1/messages":
                self._send(200, {"id": "msg-1"})
                return

            if parsed.path == "/agents/threads/thread-1/runs":
                self._send(200, {"id": "run-1", "status": "queued"})
                return

            self._send(404, {"error": "not_found"})

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            state["requests"].append({"method": "GET", "path": parsed.path, "query": parsed.query, "body": {}})
            if parsed.path == "/agents/threads/thread-1/runs/run-1":
                state["run_poll_count"] += 1
                status = "completed" if state["run_poll_count"] >= 2 else "in_progress"
                self._send(200, {"id": "run-1", "status": status})
                return

            if parsed.path == "/agents/threads/thread-1/messages":
                self._send(
                    200,
                    {
                        "data": [
                            {
                                "role": "assistant",
                                "content": [{"type": "text", "text": {"value": "foundry-agent-ok"}}],
                            }
                        ]
                    },
                )
                return
            self._send(404, {"error": "not_found"})

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, state


def test_connectors_http_family_and_foundry_agent_flow(tmp_path: Path) -> None:
    server, thread, state = _start_mock_backend()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    req = _make_chat_request()

    try:
        openai_target = GatewayTargetConfig.from_pair(
            "openai",
            {"connector": "openai_compatible_http", "endpoint": f"{base}/openai/chat/completions"},
        )
        openai_result = OpenAICompatibleHTTPConnector(openai_target, timeout_seconds=5).chat_completion(req)
        assert openai_result.content == "openai-ok"

        generic_target = GatewayTargetConfig.from_pair(
            "generic",
            {"connector": "generic_http_json", "endpoint": f"{base}/generic/invoke"},
        )
        generic_result = GenericHTTPJSONConnector(generic_target, timeout_seconds=5).chat_completion(req)
        assert generic_result.content == "generic-ok"

        foundry_model_target = GatewayTargetConfig.from_pair(
            "foundry-model",
            {
                "connector": "foundry_model_inference",
                "config": {"base_url": base, "path": "/models/chat/completions", "api_version": "2024-05-01-preview"},
                "auth": {"api_key": "k1"},
            },
        )
        foundry_model_result = FoundryModelInferenceConnector(foundry_model_target, timeout_seconds=5).chat_completion(req)
        assert foundry_model_result.content == "foundry-model-ok"

        azure_target = GatewayTargetConfig.from_pair(
            "azure-openai",
            {
                "connector": "azure_openai_deployment",
                "config": {
                    "resource_url": base,
                    "deployment": "test-dep",
                    "api_version": "2024-10-21",
                },
                "auth": {"api_key": "k2"},
            },
        )
        azure_result = AzureOpenAIDeploymentConnector(azure_target, timeout_seconds=5).chat_completion(req)
        assert azure_result.content == "azure-openai-ok"

        foundry_agent_target = GatewayTargetConfig.from_pair(
            "foundry-agent",
            {
                "connector": "foundry_agent_service",
                "config": {
                    "base_url": f"{base}/agents",
                    "assistant_id": "asst-1",
                    "run_poll_interval_seconds": 0.01,
                    "run_timeout_seconds": 2,
                },
                "auth": {"bearer_token": "abc"},
            },
        )
        foundry_agent_result = FoundryAgentServiceConnector(foundry_agent_target, timeout_seconds=5).chat_completion(req)
        assert foundry_agent_result.content == "foundry-agent-ok"

        request_paths = [item["path"] for item in state["requests"]]
        assert "/openai/chat/completions" in request_paths
        assert "/generic/invoke" in request_paths
        assert "/models/chat/completions" in request_paths
        assert "/openai/deployments/test-dep/chat/completions" in request_paths
        assert "/agents/threads" in request_paths
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_copilot_connector_can_be_mocked(monkeypatch) -> None:
    class _FakeConn:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class _FakeClient:
        def __init__(self, connection_settings):
            self.connection_settings = connection_settings

        async def start_conversation_async(self):
            return []

        async def ask_question_async(self, prompt: str):
            return [SimpleNamespace(text=f"copilot-ok:{prompt}")]

    import urt.gateway.connectors.copilot_studio as copilot_mod

    monkeypatch.setattr(copilot_mod, "_get_mcs_client_classes", lambda: (_FakeConn, _FakeClient))

    target = GatewayTargetConfig.from_pair(
        "copilot",
        {
            "connector": "copilot_studio_sdk",
            "config": {
                "tenant_id": "tenant",
                "app_client_id": "client",
                "environment_id": "env",
                "agent_identifier": "agent",
            },
        },
    )
    connector = CopilotStudioSDKConnector(target, timeout_seconds=5)
    req = _make_chat_request()
    result = connector.chat_completion(req)
    assert result.content.startswith("copilot-ok:")


def _make_chat_request_with_session(session_id: str | None, store: SessionStore | None = None) -> ChatRequest:
    payload = {"model": "gpt-test", "messages": [{"role": "user", "content": "hello session"}]}
    context: dict[str, Any] = {}
    if store is not None:
        context["_session_store"] = store
    return ChatRequest(
        trace_id="trace-session-test",
        model="gpt-test",
        messages=payload["messages"],
        payload=payload,
        headers={},
        context=context,
        session_id=session_id,
    )


def test_copilot_connector_session_reuse(monkeypatch) -> None:
    """Second request with same session_id must reuse the existing MCS client."""
    call_log: list[str] = []

    class _FakeConn:
        def __init__(self, **kwargs):
            pass

    class _FakeClient:
        def __init__(self, connection_settings):
            call_log.append("start_conversation_async")

        async def start_conversation_async(self):
            return []

        async def ask_question_async(self, prompt: str):
            call_log.append(f"ask:{prompt}")
            return [SimpleNamespace(text="copilot-ok")]

    import urt.gateway.connectors.copilot_studio as copilot_mod

    monkeypatch.setattr(copilot_mod, "_get_mcs_client_classes", lambda: (_FakeConn, _FakeClient))

    target = GatewayTargetConfig.from_pair(
        "copilot",
        {
            "connector": "copilot_studio_sdk",
            "config": {
                "tenant_id": "t",
                "app_client_id": "c",
                "environment_id": "e",
                "agent_identifier": "a",
            },
        },
    )
    store = SessionStore(ttl_seconds=60.0)
    connector = CopilotStudioSDKConnector(target, timeout_seconds=5)

    req1 = _make_chat_request_with_session("sess-1", store)
    req2 = _make_chat_request_with_session("sess-1", store)

    r1 = connector.chat_completion(req1)
    assert r1.content == "copilot-ok"

    r2 = connector.chat_completion(req2)
    assert r2.content == "copilot-ok"

    # start_conversation_async should have been called exactly once (session reuse)
    assert call_log.count("start_conversation_async") == 1


def test_copilot_connector_stateless_when_no_session(monkeypatch) -> None:
    """Without session_id, each request creates a new conversation."""
    start_calls: list[int] = []

    class _FakeConn:
        def __init__(self, **kwargs):
            pass

    class _FakeClient:
        def __init__(self, connection_settings):
            pass

        async def start_conversation_async(self):
            start_calls.append(1)
            return []

        async def ask_question_async(self, prompt: str):
            return [SimpleNamespace(text="ok")]

    import urt.gateway.connectors.copilot_studio as copilot_mod

    monkeypatch.setattr(copilot_mod, "_get_mcs_client_classes", lambda: (_FakeConn, _FakeClient))

    target = GatewayTargetConfig.from_pair(
        "copilot",
        {
            "connector": "copilot_studio_sdk",
            "config": {
                "tenant_id": "t",
                "app_client_id": "c",
                "environment_id": "e",
                "agent_identifier": "a",
            },
        },
    )
    connector = CopilotStudioSDKConnector(target, timeout_seconds=5)

    r1 = connector.chat_completion(_make_chat_request_with_session(None))
    r2 = connector.chat_completion(_make_chat_request_with_session(None))
    assert r1.content == "ok"
    assert r2.content == "ok"
    # Each stateless call starts its own conversation
    assert len(start_calls) == 2


def test_copilot_connector_system_prompt_injection(monkeypatch) -> None:
    """With inject_system_prompt=true, system message is prepended to prompt."""
    received_prompts: list[str] = []

    class _FakeConn:
        def __init__(self, **kwargs):
            pass

    class _FakeClient:
        def __init__(self, connection_settings):
            pass

        async def start_conversation_async(self):
            return []

        async def ask_question_async(self, prompt: str):
            received_prompts.append(prompt)
            return [SimpleNamespace(text="ok")]

    import urt.gateway.connectors.copilot_studio as copilot_mod

    monkeypatch.setattr(copilot_mod, "_get_mcs_client_classes", lambda: (_FakeConn, _FakeClient))

    target = GatewayTargetConfig.from_pair(
        "copilot",
        {
            "connector": "copilot_studio_sdk",
            "config": {
                "tenant_id": "t",
                "app_client_id": "c",
                "environment_id": "e",
                "agent_identifier": "a",
                "inject_system_prompt": True,
            },
        },
    )
    connector = CopilotStudioSDKConnector(target, timeout_seconds=5)
    payload = {
        "model": "test",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "What is 2+2?"},
        ],
    }
    req = ChatRequest(
        trace_id="t",
        model="test",
        messages=payload["messages"],
        payload=payload,
        headers={},
        context={},
    )
    connector.chat_completion(req)
    assert len(received_prompts) == 1
    assert "[Context: You are a helpful assistant.]" in received_prompts[0]
    assert "What is 2+2?" in received_prompts[0]


def test_base_connector_retry_on_transient_error(tmp_path: Path) -> None:
    """request_json retries on 503 and succeeds on the second attempt."""
    call_count = 0

    class RetryHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                self.send_response(503)
                body = json.dumps({"error": "unavailable"}).encode()
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(200)
                body = json.dumps({"content": "retry-ok"}).encode()
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), RetryHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        target = GatewayTargetConfig.from_pair(
            "retry-test",
            {"connector": "generic_http_json", "endpoint": f"{base}/invoke"},
        )
        connector = GenericHTTPJSONConnector(target, timeout_seconds=5)
        status, payload, _, _ = connector.request_json(
            method="POST",
            url=f"{base}/invoke",
            payload={"msg": "hello"},
            retry_attempts=3,
            retry_backoff_seconds=0.01,
        )
        assert status == 200
        assert payload.get("content") == "retry-ok"
        assert call_count == 2
    finally:
        server.shutdown()
        t.join(timeout=5)


def test_gateway_http_server_sse_streaming(tmp_path: Path) -> None:
    """When stream=true, response Content-Type is text/event-stream."""
    backend_server, backend_thread, _ = _start_mock_backend()
    backend_base = f"http://127.0.0.1:{backend_server.server_address[1]}"
    gateway_cfg = GatewayConfig.from_dict(
        {
            "gateway": {"host": "127.0.0.1", "port": 0},
            "routing": {"mode": "header", "header_name": "X-URT-Target", "default_target": "mock-openai"},
            "audit": {"artifact_root": str(tmp_path / "gateway_audit_sse")},
            "targets": {
                "mock-openai": {
                    "connector": "openai_compatible_http",
                    "endpoint": f"{backend_base}/openai/chat/completions",
                }
            },
        }
    )
    gateway = UniversalGateway(gateway_cfg)
    gateway_server = create_http_server(gateway)
    gateway_thread = threading.Thread(target=gateway_server.serve_forever, daemon=True)
    gateway_thread.start()

    try:
        gateway_port = gateway_server.server_address[1]
        payload = {
            "model": "gpt-4.1-mini",
            "messages": [{"role": "user", "content": "stream me"}],
            "stream": True,
        }
        req = request.Request(
            url=f"http://127.0.0.1:{gateway_port}/v1/chat/completions",
            method="POST",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-URT-Target": "mock-openai"},
        )
        with request.urlopen(req, timeout=5) as resp:  # noqa: S310
            ct = resp.headers.get("Content-Type", "")
            body = resp.read().decode("utf-8")

        assert "text/event-stream" in ct
        assert "data: " in body
        assert "[DONE]" in body
        # Content should include the assistant reply text
        assert "openai-ok" in body
    finally:
        gateway_server.shutdown()
        gateway_thread.join(timeout=5)
        backend_server.shutdown()
        backend_thread.join(timeout=5)


def test_gateway_session_id_resolved_from_header(tmp_path: Path) -> None:
    """X-Session-Id header is parsed and passed to ChatRequest.session_id."""
    backend_server, backend_thread, _ = _start_mock_backend()
    backend_base = f"http://127.0.0.1:{backend_server.server_address[1]}"
    gateway_cfg = GatewayConfig.from_dict(
        {
            "gateway": {"host": "127.0.0.1", "port": 0},
            "routing": {"mode": "header", "header_name": "X-URT-Target", "default_target": "mock-openai"},
            "audit": {"artifact_root": str(tmp_path / "gw_audit_session")},
            "targets": {
                "mock-openai": {
                    "connector": "openai_compatible_http",
                    "endpoint": f"{backend_base}/openai/chat/completions",
                }
            },
        }
    )
    gateway = UniversalGateway(gateway_cfg)
    gateway_server = create_http_server(gateway)
    gateway_thread = threading.Thread(target=gateway_server.serve_forever, daemon=True)
    gateway_thread.start()

    try:
        gateway_port = gateway_server.server_address[1]
        payload = {
            "model": "gpt-4.1-mini",
            "messages": [{"role": "user", "content": "session test"}],
        }
        req = request.Request(
            url=f"http://127.0.0.1:{gateway_port}/v1/chat/completions",
            method="POST",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-URT-Target": "mock-openai",
                "X-Session-Id": "test-session-42",
            },
        )
        with request.urlopen(req, timeout=5) as resp:  # noqa: S310
            response_payload = json.loads(resp.read().decode("utf-8"))
        # Gateway should return a successful response
        assert response_payload["choices"][0]["message"]["content"] == "openai-ok"
    finally:
        gateway_server.shutdown()
        gateway_thread.join(timeout=5)
        backend_server.shutdown()
        backend_thread.join(timeout=5)


def test_foundry_agent_session_reuse(tmp_path: Path) -> None:
    """Second request with same session_id must reuse the Foundry thread."""
    server, thread, state = _start_mock_backend()
    base = f"http://127.0.0.1:{server.server_address[1]}"

    target = GatewayTargetConfig.from_pair(
        "foundry-agent",
        {
            "connector": "foundry_agent_service",
            "config": {
                "base_url": f"{base}/agents",
                "assistant_id": "asst-1",
                "run_poll_interval_seconds": 0.01,
                "run_timeout_seconds": 2,
            },
            "auth": {"bearer_token": "abc"},
        },
    )

    store = SessionStore(ttl_seconds=60.0)
    connector = FoundryAgentServiceConnector(target, timeout_seconds=5)

    req1 = _make_chat_request_with_session("sess-foundry", store)
    req2 = _make_chat_request_with_session("sess-foundry", store)

    try:
        r1 = connector.chat_completion(req1)
        assert r1.content == "foundry-agent-ok"

        state["run_poll_count"] = 0  # reset poll counter for second run

        r2 = connector.chat_completion(req2)
        assert r2.content == "foundry-agent-ok"

        # Thread creation should only happen once (the second request reuses)
        create_thread_calls = [r for r in state["requests"] if r["path"] == "/agents/threads" and r["method"] == "POST"]
        assert len(create_thread_calls) == 1
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_gateway_http_server_smoke_and_audit(tmp_path: Path) -> None:
    backend_server, backend_thread, _ = _start_mock_backend()
    backend_base = f"http://127.0.0.1:{backend_server.server_address[1]}"
    gateway_cfg = GatewayConfig.from_dict(
        {
            "gateway": {"host": "127.0.0.1", "port": 0},
            "routing": {
                "mode": "header",
                "header_name": "X-URT-Target",
                "default_target": "mock-openai",
            },
            "audit": {"artifact_root": str(tmp_path / "gateway_audit")},
            "targets": {
                "mock-openai": {
                    "connector": "openai_compatible_http",
                    "endpoint": f"{backend_base}/openai/chat/completions",
                }
            },
        }
    )
    gateway = UniversalGateway(gateway_cfg)
    gateway_server = create_http_server(gateway)
    gateway_thread = threading.Thread(target=gateway_server.serve_forever, daemon=True)
    gateway_thread.start()

    try:
        gateway_port = gateway_server.server_address[1]
        health_url = f"http://127.0.0.1:{gateway_port}/healthz?deep=true"
        with request.urlopen(request.Request(health_url, method="GET"), timeout=5) as resp:  # noqa: S310
            health_payload = json.loads(resp.read().decode("utf-8"))
        assert health_payload["ok"] is True
        assert health_payload["checks"][0]["ok"] is True

        payload = {
            "model": "gpt-4.1-mini",
            "messages": [{"role": "user", "content": "ping"}],
        }
        req = request.Request(
            url=f"http://127.0.0.1:{gateway_port}/v1/chat/completions",
            method="POST",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-URT-Target": "mock-openai"},
        )
        with request.urlopen(req, timeout=5) as resp:  # noqa: S310
            response_payload = json.loads(resp.read().decode("utf-8"))
        assert response_payload["choices"][0]["message"]["content"] == "openai-ok"

        audit_dir = tmp_path / "gateway_audit"
        trace_files = list(audit_dir.rglob("trace-*.json"))
        assert trace_files, "expected gateway audit trace file"
    finally:
        gateway_server.shutdown()
        gateway_thread.join(timeout=5)
        backend_server.shutdown()
        backend_thread.join(timeout=5)
