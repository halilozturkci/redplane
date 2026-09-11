"""Waiver matching used by CI gates."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..types import UnifiedFinding, WaiverRecord


def parse_expiry(raw: str) -> datetime | None:
    text = str(raw or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def waiver_is_active(waiver: dict[str, Any] | WaiverRecord, *, now: datetime | None = None) -> bool:
    payload = waiver if isinstance(waiver, dict) else {
        "expires_at": waiver.expires_at,
    }
    expires = parse_expiry(str(payload.get("expires_at", "")))
    if expires is None:
        return False
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return expires >= current


def _finding_control_candidates(finding: UnifiedFinding) -> list[str]:
    candidates = [
        finding.category,
        finding.sub_category or "",
        finding.finding_id,
        finding.engine,
        finding.attack_vector,
    ]
    for values in finding.mappings.values():
        candidates.extend(values)
    return [str(item).strip() for item in candidates if str(item).strip()]


def control_matches(finding: UnifiedFinding, control_id: str) -> bool:
    needle = str(control_id or "").strip().lower()
    if not needle:
        return False
    for candidate in _finding_control_candidates(finding):
        text = candidate.lower()
        if text == needle:
            return True
        if text.startswith(f"{needle} ") or text.startswith(f"{needle}:"):
            return True
    return False


def target_matches(finding: UnifiedFinding, target_id: str) -> bool:
    wanted = str(target_id or "").strip()
    if not wanted or wanted == "*":
        return True
    return finding.target_id == wanted


def matching_waiver(
    finding: UnifiedFinding,
    waivers: list[dict[str, Any]],
    *,
    now: datetime | None = None,
) -> dict[str, Any] | None:
    for waiver in waivers:
        if not waiver_is_active(waiver, now=now):
            continue
        if not target_matches(finding, str(waiver.get("target_id", ""))):
            continue
        if control_matches(finding, str(waiver.get("control_id", ""))):
            return waiver
    return None
