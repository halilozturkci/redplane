"""Copilot Studio SDK connector for URT Universal Gateway."""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any

from ..contracts import ChatRequest, ChatResult, ConnectorError
from .base import GatewayConnector


def _import_mcs_client():
    from urt.integrations.mcs_pyrit.copilot_client import (
        McsConnectionSettings,
        McsCopilotClient,
    )

    return McsConnectionSettings, McsCopilotClient


def _get_mcs_client_classes():
    return _import_mcs_client()


class CopilotStudioSDKConnector(GatewayConnector):
    """Connector for Copilot Studio via python SDK helper."""

    connector_name = "copilot_studio_sdk"

    def chat_completion(self, chat_request: ChatRequest) -> ChatResult:
        messages = chat_request.messages
        prompt = self.latest_user_message(messages)
        if not prompt:
            raise ConnectorError(
                "copilot_studio_sdk requires at least one user message",
                status_code=400,
                code="invalid_request",
            )

        # Opt-in system prompt injection for stateful backends
        if self.target.config.get("inject_system_prompt"):
            system = next(
                (m.get("content") for m in messages if isinstance(m, dict) and m.get("role") == "system"),
                None,
            )
            if system and isinstance(system, str):
                prompt = f"[Context: {system}]\n\n{prompt}"

        connection_kwargs = self._connection_kwargs()
        retry_attempts = self.target.retry_attempts
        retry_backoff_seconds = self.target.retry_backoff_seconds
        retry_on_exc_codes: set[int] = {502, 503, 504}

        last_exc: ConnectorError | None = None
        for attempt in range(1, retry_attempts + 1):
            try:
                answer = self._ask_with_session(chat_request=chat_request, prompt=prompt, connection_kwargs=connection_kwargs)
                break
            except ConnectorError as exc:
                if attempt < retry_attempts and exc.status_code in retry_on_exc_codes:
                    time.sleep(retry_backoff_seconds * attempt)
                    last_exc = exc
                    continue
                raise
            except Exception as exc:  # noqa: BLE001
                raise ConnectorError(
                    f"copilot_studio_sdk invocation failed: {exc}",
                    code="connector_runtime_error",
                    status_code=502,
                ) from exc
        else:
            raise last_exc or ConnectorError(  # type: ignore[misc]
                "copilot_studio_sdk all retry attempts exhausted",
                code="connector_runtime_error",
                status_code=502,
            )

        return ChatResult(
            content=answer or "I cannot provide a response to this request.",
            model=str(chat_request.model),
            raw_response={"output": answer},
            metadata={"connector": self.connector_name},
        )

    def _ask_with_session(self, *, chat_request: ChatRequest, prompt: str, connection_kwargs: dict[str, str]) -> str:
        """Ask the MCS agent, reusing an existing session when available."""
        session_store = chat_request.context.get("_session_store")
        session_id = chat_request.session_id

        if session_store is not None and session_id:
            from ..session_store import SessionEntry

            entry = session_store.get(session_id)
            if entry and entry.client is not None:
                # Reuse existing conversation
                try:
                    return asyncio.run(self._ask_existing_client(client=entry.client, prompt=prompt))
                except Exception:  # noqa: BLE001
                    # Client may have gone stale; fall through to create a new one
                    pass

            # Create new session and store it
            McsConnectionSettings, McsCopilotClient = _get_mcs_client_classes()
            connection = McsConnectionSettings(**connection_kwargs)
            client = McsCopilotClient(connection_settings=connection)
            asyncio.run(self._start_with_timeout(client))
            new_entry = SessionEntry(client=client, thread_id=None)
            session_store.put(session_id, new_entry)
            return asyncio.run(self._ask_existing_client(client=client, prompt=prompt))

        # Stateless mode: new conversation per request (original behavior)
        return asyncio.run(self._ask_copilot(prompt=prompt, connection_kwargs=connection_kwargs))

    async def _start_with_timeout(self, client: Any) -> None:
        async with asyncio.timeout(self.timeout_seconds):
            await client.start_conversation_async()

    async def _ask_existing_client(self, *, client: Any, prompt: str) -> str:
        async with asyncio.timeout(self.timeout_seconds):
            activities = await client.ask_question_async(prompt)
        parts: list[str] = []
        for activity in activities:
            text = getattr(activity, "text", None)
            if isinstance(text, str):
                parts.append(text)
        return "".join(parts).strip()

    def healthcheck(self) -> tuple[bool, str]:
        missing = [key for key in self._required_keys() if not self._resolve_value(key)]
        if missing:
            return False, f"missing required settings: {missing}"
        return True, "copilot configuration looks valid"

    def _required_keys(self) -> tuple[str, ...]:
        return ("tenant_id", "app_client_id", "environment_id", "agent_identifier")

    def _resolve_value(self, key: str) -> str | None:
        if isinstance(self.target.config.get(key), str) and str(self.target.config.get(key)).strip():
            return str(self.target.config.get(key)).strip()

        env_map = {
            "tenant_id": "TENANT_ID",
            "app_client_id": "APP_CLIENT_ID",
            "environment_id": "ENVIRONMENT_ID",
            "agent_identifier": "AGENT_IDENTIFIER",
        }
        env_key = env_map.get(key)
        if env_key:
            env_val = os.getenv(env_key)
            if isinstance(env_val, str) and env_val.strip():
                return env_val.strip()
        return None

    def _connection_kwargs(self) -> dict[str, str]:
        kwargs: dict[str, str] = {}
        for key in self._required_keys():
            value = self._resolve_value(key)
            if not value:
                raise ConnectorError(
                    f"missing required copilot setting '{key}'",
                    status_code=400,
                    code="invalid_connector_config",
                )
            kwargs[key] = value
        return kwargs

    async def _ask_copilot(self, *, prompt: str, connection_kwargs: dict[str, str]) -> str:
        McsConnectionSettings, McsCopilotClient = _get_mcs_client_classes()
        connection = McsConnectionSettings(**connection_kwargs)
        client = McsCopilotClient(connection_settings=connection)
        async with asyncio.timeout(self.timeout_seconds):
            await client.start_conversation_async()
            activities = await client.ask_question_async(prompt)

        parts: list[str] = []
        for activity in activities:
            text = getattr(activity, "text", None)
            if isinstance(text, str):
                parts.append(text)
        return "".join(parts).strip()
