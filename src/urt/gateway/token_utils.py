"""Token counting utilities for URT Universal Gateway."""

from __future__ import annotations

from typing import Any


def count_tokens(messages: list[dict[str, Any]], model: str = "gpt-4o") -> int:
    """Count tokens for *messages* using tiktoken when available.

    Falls back to a character-length heuristic (len // 4) when tiktoken is
    not installed or the model encoding cannot be resolved.
    """
    try:
        import tiktoken  # type: ignore

        try:
            enc = tiktoken.encoding_for_model(model)
        except KeyError:
            enc = tiktoken.get_encoding("cl100k_base")

        total = 0
        for msg in messages:
            content = msg.get("content") or ""
            if isinstance(content, str):
                total += len(enc.encode(content))
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict):
                        text = part.get("text") or ""
                        if isinstance(text, str):
                            total += len(enc.encode(text))
        return total
    except Exception:  # noqa: BLE001
        # Fallback: rough estimate of ~4 chars per token
        total = 0
        for msg in messages:
            content = msg.get("content") or ""
            if isinstance(content, str):
                total += len(content) // 4
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict):
                        text = part.get("text") or ""
                        if isinstance(text, str):
                            total += len(text) // 4
        return total
