"""Copilot Studio target adapter."""

from __future__ import annotations

import asyncio
import importlib
import importlib.util
import uuid
from pathlib import Path
from typing import Any

from .http_agent import HttpTargetAdapter
from ...types import TargetResponse

PROJECT_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_SDK_PATH = PROJECT_ROOT / "src/urt/integrations/mcs_pyrit/copilot_client.py"


class CopilotTargetAdapter(HttpTargetAdapter):
    """Copilot Studio target adapter.

    Modes:
    - http (default): endpoint-based invocation (same contract as HttpTargetAdapter)
    - sdk: uses local CopilotStudioClient helper module if available.
    """

    def __init__(self, spec):
        super().__init__(spec)
        self._sdk_client = None

    @property
    def mode(self) -> str:
        return str(self.spec.config.get("mode", "http")).lower()

    def healthcheck(self) -> tuple[bool, str]:
        if self.mode == "sdk":
            sdk_path = self.spec.config.get("sdk_path", str(DEFAULT_SDK_PATH))
            if not sdk_path:
                return False, "copilot sdk mode requires config.sdk_path"
            if not Path(str(sdk_path)).exists():
                return False, f"copilot sdk path not found: {sdk_path}"
            required = ["tenant_id", "app_client_id", "environment_id", "agent_identifier"]
            missing = [key for key in required if not (self.spec.auth.get(key) or self.spec.config.get(key))]
            if missing:
                return False, f"missing copilot sdk auth keys: {missing}"
            return True, "copilot sdk configuration looks valid"

        return super().healthcheck()

    def start_session(self) -> str:
        if self.mode != "sdk":
            return super().start_session()

        self._sdk_client = self._build_sdk_client()
        asyncio.run(self._sdk_client.start_conversation_async())
        return str(uuid.uuid4())

    def send(self, session_id: str, messages: list[dict[str, str]], context: dict[str, Any] | None = None) -> TargetResponse:  # noqa: ARG002
        if self.mode != "sdk":
            return super().send(session_id, messages, context)

        if not self._sdk_client:
            self._sdk_client = self._build_sdk_client()
            asyncio.run(self._sdk_client.start_conversation_async())

        prompt = messages[-1]["content"] if messages else ""
        activities = asyncio.run(self._sdk_client.ask_question_async(prompt))
        parts: list[str] = []
        raw_activities: list[dict[str, Any]] = []
        for activity in activities:
            text = getattr(activity, "text", None)
            kind = getattr(activity, "type", None)
            raw_activities.append({"type": str(kind), "text": text})
            if isinstance(text, str):
                parts.append(text)

        content = "".join(parts).strip() or "I encountered an error and couldn't process your request."
        return TargetResponse(content=content, raw={"activities": raw_activities})

    def end_session(self, session_id: str) -> None:  # noqa: ARG002
        self._sdk_client = None

    def _build_sdk_client(self):
        sdk_path = Path(str(self.spec.config.get("sdk_path", str(DEFAULT_SDK_PATH))))
        module = self._load_module_from_path(sdk_path)

        tenant_id = self.spec.auth.get("tenant_id") or self.spec.config.get("tenant_id")
        app_client_id = self.spec.auth.get("app_client_id") or self.spec.config.get("app_client_id")
        environment_id = self.spec.auth.get("environment_id") or self.spec.config.get("environment_id")
        agent_identifier = self.spec.auth.get("agent_identifier") or self.spec.config.get("agent_identifier")

        connection = module.McsConnectionSettings(
            tenant_id=tenant_id,
            app_client_id=app_client_id,
            environment_id=environment_id,
            agent_identifier=agent_identifier,
        )
        return module.McsCopilotClient(connection_settings=connection)

    def _load_module_from_path(self, module_path: Path):
        if module_path.is_dir():
            file_path = module_path / "copilot_client.py"
            if not file_path.exists():
                file_path = module_path / "CopilotStudioClient.py"
        else:
            file_path = module_path

        if file_path.suffix != ".py":
            raise ValueError(f"Invalid SDK module path: {file_path}")

        module_name = f"copilot_sdk_{uuid.uuid4().hex}"
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Unable to load SDK module from {file_path}")

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
