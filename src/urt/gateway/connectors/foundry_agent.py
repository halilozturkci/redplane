"""Azure AI Foundry Agent Service connector."""

from __future__ import annotations

import json
import time
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..contracts import ChatRequest, ChatResult, ConnectorError
from .base import GatewayConnector


class FoundryAgentServiceConnector(GatewayConnector):
    """Connector implementing thread/run/message flow for Foundry Agent Service."""

    connector_name = "foundry_agent_service"

    def chat_completion(self, chat_request: ChatRequest) -> ChatResult:
        base_url = self.target.endpoint or self.target.config.get("base_url")
        if not base_url:
            raise ConnectorError(
                "foundry_agent_service requires target.endpoint or config.base_url",
                status_code=400,
                code="invalid_connector_config",
            )

        prompt = self.latest_user_message(chat_request.messages)
        if not prompt:
            raise ConnectorError(
                "foundry_agent_service requires at least one user message",
                status_code=400,
                code="invalid_request",
            )

        headers = self.build_auth_headers(self.target.auth)
        headers.setdefault("Content-Type", "application/json")
        assistant_id = self._resolve_assistant_id()

        retry = self.target.retry_attempts
        backoff = self.target.retry_backoff_seconds

        # Check for an existing session thread to reuse
        session_store = chat_request.context.get("_session_store")
        session_id = chat_request.session_id
        thread_id: str | None = None
        thread_status = 200
        thread_payload: dict[str, Any] = {}

        if session_store is not None and session_id:
            from ..session_store import SessionEntry

            entry = session_store.get(session_id)
            if entry and entry.thread_id:
                thread_id = entry.thread_id
            else:
                thread_status, thread_payload, _, _ = self.request_json(
                    method="POST",
                    url=self._build_url(base_url, self._path("create_thread", "/threads")),
                    headers=headers,
                    payload=self._payload("thread_payload", default={}),
                    retry_attempts=retry,
                    retry_backoff_seconds=backoff,
                )
                thread_id = self._first_string(thread_payload, ("id", "thread_id", "threadId"))
                if not thread_id:
                    raise ConnectorError(
                        "foundry_agent_service did not return thread id",
                        code="invalid_backend_response",
                        detail={"response": thread_payload},
                    )
                new_entry = SessionEntry(client=None, thread_id=thread_id)
                session_store.put(session_id, new_entry)
        else:
            thread_status, thread_payload, _, _ = self.request_json(
                method="POST",
                url=self._build_url(base_url, self._path("create_thread", "/threads")),
                headers=headers,
                payload=self._payload("thread_payload", default={}),
                retry_attempts=retry,
                retry_backoff_seconds=backoff,
            )
            thread_id = self._first_string(thread_payload, ("id", "thread_id", "threadId"))
        if not thread_id:
            raise ConnectorError(
                "foundry_agent_service did not return thread id",
                code="invalid_backend_response",
                detail={"response": thread_payload},
            )

        message_payload = self._payload(
            "message_payload",
            default={"role": "user", "content": prompt},
        )
        message_payload.setdefault("role", "user")
        message_payload["content"] = prompt
        self.request_json(
            method="POST",
            url=self._build_url(base_url, self._path("create_message", "/threads/{thread_id}/messages").format(thread_id=thread_id)),
            headers=headers,
            payload=message_payload,
            retry_attempts=retry,
            retry_backoff_seconds=backoff,
        )

        assistant_field = str(self.target.config.get("assistant_id_field", "assistant_id"))
        run_payload = self._payload("run_payload", default={})
        run_payload.setdefault(assistant_field, assistant_id)
        run_status, run_response, _, _ = self.request_json(
            method="POST",
            url=self._build_url(base_url, self._path("create_run", "/threads/{thread_id}/runs").format(thread_id=thread_id)),
            headers=headers,
            payload=run_payload,
            retry_attempts=retry,
            retry_backoff_seconds=backoff,
        )
        run_id = self._first_string(run_response, ("id", "run_id", "runId"))
        if not run_id:
            raise ConnectorError(
                "foundry_agent_service did not return run id",
                code="invalid_backend_response",
                detail={"response": run_response},
            )

        run_info = self._poll_run(base_url=str(base_url), headers=headers, thread_id=thread_id, run_id=run_id)
        status = str(run_info.get("status", "unknown")).lower()
        if status not in {"completed", "succeeded", "done"}:
            raise ConnectorError(
                f"foundry_agent_service run ended with status '{status}'",
                code="run_not_completed",
                status_code=502,
                detail={"run": run_info, "thread_id": thread_id, "run_id": run_id},
            )

        _, messages_payload, _, _ = self.request_json(
            method="GET",
            url=self._build_url(base_url, self._path("list_messages", "/threads/{thread_id}/messages").format(thread_id=thread_id)),
            headers=headers,
            payload=None,
        )
        content = self._extract_assistant_text(messages_payload)
        if not content:
            content = "No assistant message returned by foundry_agent_service."

        return ChatResult(
            content=content,
            model=str(chat_request.model),
            raw_response={
                "thread": thread_payload,
                "run": run_info,
                "messages": messages_payload,
            },
            metadata={
                "thread_id": thread_id,
                "run_id": run_id,
                "create_thread_status": thread_status,
                "create_run_status": run_status,
            },
        )

    def healthcheck(self) -> tuple[bool, str]:
        base_url = self.target.endpoint or self.target.config.get("base_url")
        if not base_url:
            return False, "missing endpoint/base_url"
        try:
            self._resolve_assistant_id()
        except ConnectorError as exc:
            return False, str(exc)
        return True, "foundry agent configuration looks valid"

    def _resolve_assistant_id(self) -> str:
        assistant_id = self.target.config.get("assistant_id") or self.target.config.get("agent_id")
        if not assistant_id:
            raise ConnectorError(
                "foundry_agent_service requires config.assistant_id (or config.agent_id)",
                status_code=400,
                code="invalid_connector_config",
            )
        return str(assistant_id)

    def _poll_run(self, *, base_url: str, headers: dict[str, str], thread_id: str, run_id: str) -> dict[str, Any]:
        timeout = float(self.target.config.get("run_timeout_seconds", 120))
        interval = float(self.target.config.get("run_poll_interval_seconds", 1.0))
        started = time.monotonic()
        run_path = self._path("get_run", "/threads/{thread_id}/runs/{run_id}")
        terminal_ok = {"completed", "succeeded", "done"}
        terminal_bad = {"failed", "cancelled", "canceled", "expired", "error"}

        last_payload: dict[str, Any] = {}
        while True:
            _, run_payload, _, _ = self.request_json(
                method="GET",
                url=self._build_url(base_url, run_path.format(thread_id=thread_id, run_id=run_id)),
                headers=headers,
                payload=None,
            )
            last_payload = run_payload
            status = str(run_payload.get("status", "unknown")).lower()
            if status in terminal_ok:
                return run_payload
            if status in terminal_bad:
                return run_payload
            if (time.monotonic() - started) > timeout:
                raise ConnectorError(
                    "foundry_agent_service run polling timeout",
                    code="run_timeout",
                    status_code=504,
                    detail={"last_run_payload": last_payload, "thread_id": thread_id, "run_id": run_id},
                )
            time.sleep(interval)

    def _build_url(self, base_url: str, path: str) -> str:
        url = str(base_url).rstrip("/") + "/" + path.lstrip("/")
        api_version = self.target.config.get("api_version")
        if not api_version:
            return url
        query_key = str(self.target.config.get("api_version_query_key", "api-version"))
        parsed = urlparse(url)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query[query_key] = str(api_version)
        return urlunparse(parsed._replace(query=urlencode(query)))

    def _path(self, key: str, default: str) -> str:
        paths = self.target.config.get("paths", {})
        if isinstance(paths, dict) and paths.get(key):
            return str(paths[key])
        return default

    def _payload(self, key: str, *, default: dict[str, Any]) -> dict[str, Any]:
        value = self.target.config.get(key)
        if isinstance(value, dict):
            return dict(value)
        return dict(default)

    @staticmethod
    def _first_string(payload: dict[str, Any], candidates: tuple[str, ...]) -> str | None:
        for key in candidates:
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    @staticmethod
    def _extract_assistant_text(payload: dict[str, Any]) -> str:
        items: list[Any] = []
        if isinstance(payload.get("data"), list):
            items = payload["data"]
        elif isinstance(payload.get("messages"), list):
            items = payload["messages"]
        elif isinstance(payload.get("items"), list):
            items = payload["items"]

        for item in items:
            if not isinstance(item, dict):
                continue
            if str(item.get("role", "")).lower() != "assistant":
                continue
            content = item.get("content")
            if isinstance(content, str):
                return content
            if isinstance(content, list):
                parts: list[str] = []
                for chunk in content:
                    if isinstance(chunk, str):
                        parts.append(chunk)
                        continue
                    if not isinstance(chunk, dict):
                        continue
                    text = chunk.get("text")
                    if isinstance(text, str):
                        parts.append(text)
                    elif isinstance(text, dict) and isinstance(text.get("value"), str):
                        parts.append(text["value"])
                    elif isinstance(chunk.get("value"), str):
                        parts.append(str(chunk["value"]))
                if parts:
                    return "\n".join(parts).strip()

        if payload:
            return json.dumps(payload, ensure_ascii=False)
        return ""
