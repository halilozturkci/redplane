"""Universal Gateway HTTP app for OpenAI-compatible attack tooling."""

from __future__ import annotations

import json
import logging
import hmac
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from .audit import GatewayAuditStore
from .config import GatewayConfig
from .connectors import CONNECTOR_REGISTRY
from .contracts import ChatRequest, ConnectorError, RoutingError
from .router import GatewayRouter
from .session_store import SessionStore
from .token_utils import count_tokens

_log = logging.getLogger("urt.gateway")


def _request_authorized(headers: dict[str, str], api_key: str | None) -> bool:
    if not api_key:
        return True
    provided = headers.get("x-api-key") or headers.get("x-urt-api-key") or ""
    authorization = headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        provided = provided or authorization[7:].strip()
    if not provided:
        return False
    try:
        return hmac.compare_digest(provided, api_key)
    except (TypeError, ValueError):
        return False


class UniversalGateway:
    """OpenAI-compatible request gateway with pluggable backend connectors."""

    def __init__(self, config: GatewayConfig):
        self.config = config
        self.router = GatewayRouter(config)
        self.audit = GatewayAuditStore(config.audit)
        self.session_store = SessionStore(
            ttl_seconds=config.gateway.session_ttl_seconds,
            persist_path=config.gateway.session_persist_path,
        )

    def health_payload(self, *, deep: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "ok": True,
            "targets": sorted(self.config.targets.keys()),
            "routing_mode": self.config.routing.mode,
        }
        if not deep:
            return payload

        checks: list[dict[str, Any]] = []
        all_ok = True
        for target_id, target in self.config.targets.items():
            connector_cls = CONNECTOR_REGISTRY[target.connector]
            connector = connector_cls(target, timeout_seconds=self.config.gateway.request_timeout_seconds)
            ok, detail = connector.healthcheck()
            all_ok = all_ok and ok
            checks.append(
                {
                    "target_id": target_id,
                    "connector": target.connector,
                    "ok": bool(ok),
                    "detail": detail,
                }
            )
        payload["ok"] = all_ok
        payload["checks"] = checks
        return payload

    def handle_chat_completion(self, *, path: str, headers: dict[str, str], body: bytes) -> tuple[int, dict[str, Any]]:
        trace_id = uuid.uuid4().hex
        started = time.perf_counter()
        request_payload: dict[str, Any] = {}
        response_payload: dict[str, Any] = {}
        status_code = 500
        target_id = ""
        connector_name = ""
        route_source = ""
        run_id: str | None = None
        error: dict[str, Any] | None = None

        try:
            request_payload = json.loads(body.decode("utf-8") if body else "{}")
            if not isinstance(request_payload, dict):
                raise ConnectorError(
                    "request body must be a JSON object",
                    status_code=400,
                    code="invalid_request",
                )

            messages = request_payload.get("messages")
            if not isinstance(messages, list):
                raise ConnectorError(
                    "request body must include 'messages' list",
                    status_code=400,
                    code="invalid_request",
                )

            # Resolve session ID: header > body context > None
            session_id: str | None = (
                headers.get("x-session-id")
                or (
                    request_payload.get("context", {}).get("session_id")
                    if isinstance(request_payload.get("context"), dict)
                    else None
                )
            )
            run_id = self._run_id_from(headers, request_payload)

            decision = self.router.resolve(path=path, headers=headers, payload=request_payload)
            target_id = decision.target_id
            connector_name = decision.target.connector
            route_source = decision.source

            connector_cls = CONNECTOR_REGISTRY[decision.target.connector]
            connector = connector_cls(decision.target, timeout_seconds=self.config.gateway.request_timeout_seconds)

            context = request_payload.get("context", {}) if isinstance(request_payload.get("context", {}), dict) else {}
            context["_session_store"] = self.session_store

            chat_request = ChatRequest(
                trace_id=trace_id,
                model=str(request_payload.get("model", "")),
                messages=messages,
                payload=request_payload,
                headers=headers,
                context=context,
                session_id=session_id,
            )
            result = connector.chat_completion(chat_request)
            status_code = 200
            response_payload = self._to_openai_response(
                result=result,
                model_hint=chat_request.model,
                messages=messages,
            )

        except RoutingError as exc:
            status_code = 404
            error = {"error": "routing_error", "message": str(exc)}
            response_payload = {"error": "routing_error", "message": str(exc)}
        except ConnectorError as exc:
            status_code = exc.status_code
            error = exc.to_dict()
            response_payload = {
                "error": exc.code,
                "message": str(exc),
                "detail": exc.detail,
            }
        except json.JSONDecodeError:
            status_code = 400
            error = {"error": "invalid_json", "message": "request body is not valid JSON"}
            response_payload = error
        except Exception as exc:  # noqa: BLE001
            status_code = 500
            error = {"error": "gateway_internal_error", "message": str(exc)}
            response_payload = error
        finally:
            finished = time.perf_counter()
            latency_ms = round((finished - started) * 1000, 2)
            _log.info(
                "request trace_id=%s target=%s latency_ms=%.0f status=%d",
                trace_id,
                target_id,
                latency_ms,
                status_code,
            )
            audit_entry = {
                "trace_id": trace_id,
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "target_id": target_id,
                "connector": connector_name,
                "route_source": route_source,
                "latency_ms": latency_ms,
                "status_code": status_code,
                # Set when the attack tool forwarded `X-URT-Run-Id` (from `URT_RUN_ID` in
                # its environment); lets the control plane join traces to the run exactly.
                "run_id": run_id,
                "request": {
                    "path": path,
                    "headers": headers,
                    "body": request_payload,
                },
                "response": {
                    "body": response_payload,
                },
                "error": error,
            }
            trace_path = self.audit.write_trace(trace_id, audit_entry)
            response_payload.setdefault("metadata", {})
            if isinstance(response_payload["metadata"], dict):
                response_payload["metadata"].setdefault("trace_id", trace_id)
                # Relative to the audit root, never the server's filesystem layout.
                response_payload["metadata"].setdefault("audit_path", trace_path)

        return status_code, response_payload

    @staticmethod
    def _run_id_from(headers: dict[str, str], payload: dict[str, Any]) -> str | None:
        candidate = headers.get("x-urt-run-id")
        if not candidate and isinstance(payload.get("context"), dict):
            candidate = payload["context"].get("run_id")
        if not candidate:
            return None
        text = str(candidate).strip()
        return text[:128] if text else None

    def sessions_payload(self) -> dict[str, Any]:
        """Live/persisted session identifiers with presence flags only (no content)."""
        rows = self.session_store.describe()
        return {"count": len(rows), "ttl_seconds": self.config.gateway.session_ttl_seconds, "sessions": rows}

    @staticmethod
    def _to_openai_response(*, result: Any, model_hint: str, messages: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        model = result.model or model_hint or "urt-gateway-model"
        if isinstance(result.usage, dict) and result.usage:
            usage = result.usage
        else:
            prompt_tokens = count_tokens(messages or [], model=model)
            completion_tokens = max(1, len(result.content) // 4)
            usage = {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            }
        return {
            "id": f"chatcmpl-{int(time.time() * 1000)}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": result.content},
                    "finish_reason": result.finish_reason or "stop",
                }
            ],
            "usage": usage,
            "gateway": {
                "metadata": result.metadata,
            },
        }


def create_http_server(gateway: UniversalGateway) -> ThreadingHTTPServer:
    """Create configured HTTP server instance for gateway."""

    class Handler(BaseHTTPRequestHandler):
        server_version = "URTUniversalGateway/1.0"

        def _send_json(self, code: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_sse(self, code: int, payload: dict[str, Any]) -> None:
            """Emit pseudo-streaming SSE: one content chunk + [DONE]."""
            content = ""
            choices = payload.get("choices")
            if isinstance(choices, list) and choices:
                msg = choices[0].get("message") if isinstance(choices[0], dict) else {}
                if isinstance(msg, dict):
                    content = msg.get("content", "")

            base = {
                "id": payload.get("id", f"chatcmpl-{int(time.time() * 1000)}"),
                "object": "chat.completion.chunk",
                "created": payload.get("created", int(time.time())),
                "model": payload.get("model", "urt-gateway-model"),
            }
            chunk = {**base, "choices": [{"index": 0, "delta": {"role": "assistant", "content": content}, "finish_reason": None}]}
            final = {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}
            done_line = b"data: [DONE]\n\n"

            body = (
                f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n"
                f"data: {json.dumps(final, ensure_ascii=False)}\n\n"
            ).encode("utf-8") + done_line

            self.send_response(code)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path == "/healthz":
                query = parse_qs(parsed.query)
                deep = str(query.get("deep", ["false"])[0]).lower() in {"1", "true", "yes", "on"}
                payload = gateway.health_payload(deep=deep)
                self._send_json(200, payload)
                return
            if parsed.path == "/v1/sessions":
                headers = {str(key).lower(): str(value) for key, value in self.headers.items()}
                if not _request_authorized(headers, gateway.config.gateway.api_key):
                    self._send_json(401, {"error": "unauthorized", "message": "invalid or missing gateway API key"})
                    return
                self._send_json(200, gateway.sessions_payload())
                return
            self._send_json(404, {"error": "not_found"})

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            path = parsed.path
            if not (path == "/v1/chat/completions" or path.startswith(gateway.config.routing.path_prefix)):
                self._send_json(404, {"error": "not_found"})
                return

            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length > 0 else b""
            headers = {str(key).lower(): str(value) for key, value in self.headers.items()}
            if not _request_authorized(headers, gateway.config.gateway.api_key):
                self._send_json(
                    401,
                    {
                        "error": "unauthorized",
                        "message": "invalid or missing gateway API key",
                    },
                )
                return
            code, payload = gateway.handle_chat_completion(path=path, headers=headers, body=body)

            # Determine whether client requested SSE streaming
            try:
                request_body = json.loads(body.decode("utf-8")) if body else {}
                is_stream = request_body.get("stream") is True
            except (json.JSONDecodeError, UnicodeDecodeError):
                is_stream = False

            if is_stream and code == 200:
                self._send_sse(code, payload)
            else:
                self._send_json(code, payload)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
            _log.debug("%s - %s", self.address_string(), format % args)

    return ThreadingHTTPServer((gateway.config.gateway.host, gateway.config.gateway.port), Handler)


def serve_gateway(config: GatewayConfig) -> None:
    """Start gateway server and block forever."""
    logging.basicConfig(
        level=getattr(logging, config.gateway.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    gateway = UniversalGateway(config)
    httpd = create_http_server(gateway)
    host = config.gateway.host
    port = config.gateway.port
    _log.info("Redplane network gateway listening on http://%s:%d", host, port)
    print(f"Redplane network gateway listening on http://{host}:{port}", flush=True)
    httpd.serve_forever()
