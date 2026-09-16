"""Multi-run matrix for the red-team lead: targets (rows) × runs (columns).

Each cell is that target's own scorecard inside that run (`build_scorecard` over the
target's findings), the same computation `trend()` uses per target — so a run that
covered three targets contributes three cells, and a target the run never included
is an explicit `None`, not a zero. No totals are invented across cells.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .normalization import build_scorecard
from .types import UnifiedFinding

DEFAULT_RUN_LIMIT = 12
MAX_RUN_LIMIT = 100
MATRIX_NOTE = (
    "Each cell is the per-target scorecard of that run (severity counts and ASR computed from that "
    "target's findings only), not the run total. An empty cell means the run did not include the target."
)


@dataclass(slots=True)
class RunMatrix:
    targets: list[str]
    runs: list[dict[str, Any]]
    cells: dict[str, dict[str, dict[str, Any] | None]]
    truncated: bool = False
    note: str = MATRIX_NOTE
    filters: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "note": self.note,
            "filters": dict(self.filters),
            "truncated": self.truncated,
            "targets": list(self.targets),
            "runs": [dict(run) for run in self.runs],
            "cells": {target: dict(columns) for target, columns in self.cells.items()},
        }


def _cell(run_id: str, findings: list[UnifiedFinding], status: str) -> dict[str, Any]:
    card = build_scorecard(run_id, findings)
    return {
        "status": status,
        "total_findings": card.total_findings,
        "critical": card.critical,
        "high": card.high,
        "medium": card.medium,
        "low": card.low,
        "info": card.info,
        "critical_high": card.critical + card.high,
        "success_count": card.success_count,
        "total_attacks": card.total_attacks,
        "asr_overall": card.asr_overall,
    }


def build_run_matrix(
    rows: list[dict[str, Any]],
    findings_for: Callable[[str], list[UnifiedFinding] | None],
    *,
    target: str | None = None,
    name_prefix: str | None = None,
    limit: int = DEFAULT_RUN_LIMIT,
) -> RunMatrix:
    """`rows` are enriched run rows (newest first, as `Orchestrator.list_runs` returns);
    `findings_for(run_id)` yields the run's findings or None when it has none yet.
    Runs without findings are skipped; at most `limit` runs become columns."""
    if limit < 1:
        raise ValueError("limit must be >= 1")
    selected: list[dict[str, Any]] = []
    for row in rows:
        declared = [str(t) for t in (row.get("targets") or [])]
        if target and target not in declared:
            continue
        if name_prefix and not str(row.get("name", "")).startswith(name_prefix):
            continue
        selected.append(row)
    truncated = len(selected) > limit
    selected = selected[:limit]

    columns: list[dict[str, Any]] = []
    per_run: dict[str, tuple[list[str], list[UnifiedFinding]]] = {}
    for row in selected:
        findings = findings_for(row["run_id"])
        if findings is None:
            continue
        declared = [str(t) for t in (row.get("targets") or [])]
        seen = list(dict.fromkeys(declared + [f.target_id for f in findings]))
        per_run[row["run_id"]] = (seen, findings)
        columns.append(
            {
                "run_id": row["run_id"],
                "name": row.get("name"),
                "profile": row.get("profile"),
                "status": row.get("status"),
                "created_at": row.get("created_at"),
                "targets": seen,
            }
        )

    all_targets = sorted({t for seen, _ in per_run.values() for t in seen})
    if target:
        all_targets = [t for t in all_targets if t == target]
    cells: dict[str, dict[str, dict[str, Any] | None]] = {}
    for target_id in all_targets:
        cells[target_id] = {}
        for column in columns:
            seen, findings = per_run[column["run_id"]]
            if target_id not in seen:
                cells[target_id][column["run_id"]] = None
                continue
            mine = [f for f in findings if f.target_id == target_id]
            cells[target_id][column["run_id"]] = _cell(column["run_id"], mine, str(column.get("status") or ""))
    return RunMatrix(
        targets=all_targets,
        runs=columns,
        cells=cells,
        truncated=truncated,
        filters={"target": target or "", "name_prefix": name_prefix or "", "limit": limit},
    )
