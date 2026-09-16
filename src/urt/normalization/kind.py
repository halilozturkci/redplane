"""`finding_kind` (idea 4): attack / coverage_gap / execution / eval.

Only `attack` findings count towards ASR and the framework coverage matrix; the
other kinds describe the run (an engine that did not start, a launcher crash, a
failed target healthcheck, an evaluator metric), not the target's behaviour.
`normalize_findings` stores the kind in `metadata.finding_kind`; readers fall back
to derivation for records written before the tag existed.
"""

from __future__ import annotations

from typing import Any

from ..constants import SUPPORTED_EVALUATORS
from ..types import UnifiedFinding

FINDING_KINDS = ("attack", "coverage_gap", "execution", "eval", "signal")
ASR_KINDS = frozenset({"attack"})
PLATFORM_ENGINE = "platform"
# Idea 4: tenant/governance observations (Power CAT `governance_scan`, PowerPwn
# `recon_signal`) describe configuration, not a prompt that succeeded against the
# model; they are findings, but not attacks, so they never move ASR.
SIGNAL_ATTACK_VECTORS = frozenset({"governance_scan", "recon_signal"})


def _fields(finding: UnifiedFinding | dict[str, Any]) -> dict[str, Any]:
    if isinstance(finding, UnifiedFinding):
        return {
            "category": finding.category,
            "sub_category": finding.sub_category,
            "engine": finding.engine,
            "attack_vector": finding.attack_vector,
            "metadata": finding.metadata,
        }
    return finding


def derive_finding_kind(finding: UnifiedFinding | dict[str, Any]) -> str:
    """Kind from the record's shape (ignores any stored tag)."""
    record = _fields(finding)
    category = str(record.get("category", "")).lower()
    sub_category = str(record.get("sub_category") or "").lower()
    engine = str(record.get("engine", "")).lower()
    attack_vector = str(record.get("attack_vector", "")).lower()
    metadata = record.get("metadata") or {}
    if category == "coverage_gap" or sub_category == "engine_skipped" or metadata.get("status") == "skipped":
        return "coverage_gap"
    if category == "execution" or attack_vector == "tool_runtime" or engine == PLATFORM_ENGINE:
        return "execution"
    if attack_vector in SIGNAL_ATTACK_VECTORS:
        return "signal"
    if engine in SUPPORTED_EVALUATORS or attack_vector == "n/a":
        return "eval"
    return "attack"


def finding_kind(finding: UnifiedFinding | dict[str, Any]) -> str:
    """Stored `metadata.finding_kind` when valid, else derived."""
    record = _fields(finding)
    tagged = (record.get("metadata") or {}).get("finding_kind")
    if tagged in FINDING_KINDS:
        return str(tagged)
    return derive_finding_kind(finding)
