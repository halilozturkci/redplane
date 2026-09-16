"""Per-engine transcript extraction from finding metadata.

Engines store the prompt/response exchange in different shapes; this module maps
each to a flat list of `Turn`s so one template renders them all as text. Anything
unrecognised yields no turns and the renderer falls back to the raw metadata JSON.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class Turn:
    role: str
    content: str


def _text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value if value.strip() else None
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, list):
        parts = [_text(item) for item in value]
        joined = "\n".join(part for part in parts if part)
        return joined or None
    if isinstance(value, dict):
        for key in ("output", "content", "text", "raw", "value"):
            found = _text(value.get(key))
            if found:
                return found
    return None


def _conversation_turns(items: Any) -> list[Turn]:
    turns: list[Turn] = []
    if not isinstance(items, list):
        return turns
    for item in items:
        if not isinstance(item, dict):
            continue
        content = _text(item.get("content") or item.get("converted_value") or item.get("original_value"))
        if content:
            turns.append(Turn(role=str(item.get("role") or "unknown"), content=content))
    return turns


def _promptfoo(raw: dict[str, Any]) -> list[Turn]:
    turns: list[Turn] = []
    vars_payload = raw.get("vars") if isinstance(raw.get("vars"), dict) else {}
    prompt = _text(vars_payload.get("attack_prompt")) or _text(vars_payload.get("prompt")) or _text(raw.get("prompt"))
    if prompt:
        turns.append(Turn(role="user", content=prompt))
    response = _text(raw.get("response"))
    if response:
        turns.append(Turn(role="assistant", content=response))
    grading = raw.get("gradingResult") if isinstance(raw.get("gradingResult"), dict) else {}
    reason = _text(grading.get("reason"))
    if reason:
        turns.append(Turn(role="grader", content=reason))
    return turns


def _garak(raw: dict[str, Any]) -> list[Turn]:
    turns: list[Turn] = []
    prompt = _text(raw.get("prompt"))
    if prompt:
        turns.append(Turn(role="user", content=prompt))
    outputs = _text(raw.get("outputs")) or _text(raw.get("output"))
    if outputs:
        turns.append(Turn(role="assistant", content=outputs))
    return turns


def _deepteam(raw: dict[str, Any]) -> list[Turn]:
    turns: list[Turn] = []
    prompt = _text(raw.get("input")) or _text(raw.get("prompt"))
    if prompt:
        turns.append(Turn(role="user", content=prompt))
    output = _text(raw.get("actual_output")) or _text(raw.get("output"))
    if output:
        turns.append(Turn(role="assistant", content=output))
    reason = _text(raw.get("reason"))
    if reason:
        turns.append(Turn(role="grader", content=reason))
    return turns


_RAW_EXTRACTORS = {
    "promptfoo": _promptfoo,
    "garak": _garak,
    "deepteam": _deepteam,
}


def extract_transcript(record: dict[str, Any]) -> tuple[list[Turn], str]:
    """Return `(turns, source)`; `source` names the metadata field used, "" when none."""
    metadata = record.get("metadata") or {}
    if not isinstance(metadata, dict):
        return [], ""
    engine = str(record.get("engine", "")).lower()

    for key in ("conversation", "conversation_preview"):
        turns = _conversation_turns(metadata.get(key))
        if turns:
            return turns, f"metadata.{key}"

    raw = metadata.get("raw")
    if isinstance(raw, dict):
        extractor = _RAW_EXTRACTORS.get(engine)
        turns = extractor(raw) if extractor else []
        if not turns:
            turns = _conversation_turns(raw.get("conversation") or raw.get("messages"))
        if turns:
            return turns, "metadata.raw"
    return [], ""
