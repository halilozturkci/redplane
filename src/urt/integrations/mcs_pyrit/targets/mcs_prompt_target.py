"""PyRIT 1.x PromptTarget wrapping the MCS Copilot Studio callback."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from pyrit.models import Message, MessagePiece, construct_response_from_request
from pyrit.prompt_target.common.prompt_target import PromptTarget
from pyrit.prompt_target.common.target_configuration import TargetConfiguration

Callback = Callable[..., Awaitable[Any] | Any]


class McsPyritPromptTarget(PromptTarget):
    """Send the current turn through the existing MCS async callback."""

    def __init__(
        self,
        *,
        callback: Callback | None = None,
        mcs_agent_config: Any | None = None,
        custom_configuration: TargetConfiguration | None = None,
    ) -> None:
        super().__init__(custom_configuration=custom_configuration)
        if callback is None:
            if mcs_agent_config is None:
                raise ValueError("callback or mcs_agent_config is required")
            from urt.integrations.mcs_pyrit.targets.mcs_agent_callback import (  # noqa: PLC0415
                McsAgentCallbackTarget,
            )

            callback = McsAgentCallbackTarget(mcs_agent_config).get_target()
        self._callback = callback

    async def _send_prompt_to_target_async(self, *, normalized_conversation: list[Message]) -> list[Message]:
        message = normalized_conversation[-1]
        piece: MessagePiece = message.message_pieces[0]
        history = [_piece_as_chat(item) for prior in normalized_conversation for item in prior.message_pieces]
        payload = await self._callback(history)
        content = assistant_text(payload)
        return [construct_response_from_request(request=piece, response_text_pieces=[content])]

    def _validate_request(self, *, normalized_conversation: list[Message]) -> None:
        if not normalized_conversation:
            raise ValueError("normalized_conversation is empty")
        if not normalized_conversation[-1].message_pieces:
            raise ValueError("current message has no pieces")

    async def cleanup_target_async(self) -> None:
        return None


def _piece_as_chat(piece: MessagePiece) -> dict[str, str]:
    role = str(piece.role or "user")
    content = str(piece.converted_value or piece.original_value or "")
    return {"role": role, "content": content}


def assistant_text(payload: object) -> str:
    """Extract assistant text from the MCS callback chat-protocol payload."""
    if isinstance(payload, str):
        return payload
    if not isinstance(payload, dict):
        return str(payload)
    messages = payload.get("messages")
    if isinstance(messages, list) and messages:
        last = messages[-1]
        if isinstance(last, dict):
            content = last.get("content")
            if content is not None:
                return str(content)
    content = payload.get("content")
    if content is not None:
        return str(content)
    return "No response available."
