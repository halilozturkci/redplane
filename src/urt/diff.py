"""Cross-run comparison (G8 / next-development idea 1): `urt diff`, run diff and target trend.

Findings cannot be compared by `finding_id` across runs (it embeds the run id), so
the identity key is `category + sub_category + target_id`. Two findings with the
same key in two runs are the "same" issue whether or not the same engine raised it;
counts and max severity per key are kept so a change in either is visible.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .constants import SEVERITY_ORDER
from .types import UnifiedFinding

IDENTITY_FIELDS = ("category", "sub_category", "target_id")
SCORECARD_DELTA_KEYS = (
    "total_findings",
    "critical",
    "high",
    "medium",
    "low",
    "info",
    "success_count",
    "total_attacks",
    "asr_overall",
    "eval_pass_rate",
)


def finding_identity(finding: UnifiedFinding | dict[str, Any]) -> str:
    if isinstance(finding, UnifiedFinding):
        values = (finding.category, finding.sub_category or "", finding.target_id)
    else:
        values = (str(finding.get("category", "")), str(finding.get("sub_category") or ""), str(finding.get("target_id", "")))
    return "|".join(str(v) for v in values)


def _max_severity(findings: list[UnifiedFinding]) -> str | None:
    if not findings:
        return None
    return max((f.severity.lower() for f in findings), key=lambda level: SEVERITY_ORDER.get(level, -1))


@dataclass(slots=True)
class DiffGroup:
    """One identity key as seen in run A and run B."""

    key: str
    category: str
    sub_category: str
    target_id: str
    count_a: int = 0
    count_b: int = 0
    max_severity_a: str | None = None
    max_severity_b: str | None = None
    finding_ids_a: list[str] = field(default_factory=list)
    finding_ids_b: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "DiffGroup":
        return cls(
            key=str(payload["key"]),
            category=str(payload.get("category", "")),
            sub_category=str(payload.get("sub_category", "")),
            target_id=str(payload.get("target_id", "")),
            count_a=int(payload.get("count_a", 0)),
            count_b=int(payload.get("count_b", 0)),
            max_severity_a=payload.get("max_severity_a"),
            max_severity_b=payload.get("max_severity_b"),
            finding_ids_a=list(payload.get("finding_ids_a", [])),
            finding_ids_b=list(payload.get("finding_ids_b", [])),
        )


@dataclass(slots=True)
class RunDiff:
    run_a: str
    run_b: str
    new: list[DiffGroup]
    resolved: list[DiffGroup]
    persisting: list[DiffGroup]
    scorecard_delta: dict[str, dict[str, Any]]
    asr_by_category_delta: dict[str, dict[str, Any]]
    eval_delta: dict[str, dict[str, Any]]
    identity_fields: tuple[str, ...] = IDENTITY_FIELDS

    @property
    def summary(self) -> dict[str, int]:
        return {"new": len(self.new), "resolved": len(self.resolved), "persisting": len(self.persisting)}

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_a": self.run_a,
            "run_b": self.run_b,
            "identity_fields": list(self.identity_fields),
            "summary": self.summary,
            "new": [g.to_dict() for g in self.new],
            "resolved": [g.to_dict() for g in self.resolved],
            "persisting": [g.to_dict() for g in self.persisting],
            "scorecard_delta": self.scorecard_delta,
            "asr_by_category_delta": self.asr_by_category_delta,
            "eval_delta": self.eval_delta,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "RunDiff":
        return cls(
            run_a=str(payload["run_a"]),
            run_b=str(payload["run_b"]),
            new=[DiffGroup.from_dict(g) for g in payload.get("new", [])],
            resolved=[DiffGroup.from_dict(g) for g in payload.get("resolved", [])],
            persisting=[DiffGroup.from_dict(g) for g in payload.get("persisting", [])],
            scorecard_delta=dict(payload.get("scorecard_delta", {})),
            asr_by_category_delta=dict(payload.get("asr_by_category_delta", {})),
            eval_delta=dict(payload.get("eval_delta", {})),
            identity_fields=tuple(payload.get("identity_fields", IDENTITY_FIELDS)),
        )


def _group(findings: list[UnifiedFinding]) -> dict[str, list[UnifiedFinding]]:
    groups: dict[str, list[UnifiedFinding]] = {}
    for finding in findings:
        groups.setdefault(finding_identity(finding), []).append(finding)
    return groups


def _num(value: Any) -> float | int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _delta(a: Any, b: Any) -> dict[str, Any]:
    left, right = _num(a), _num(b)
    if left is None or right is None:
        return {"a": left, "b": right, "delta": None}
    delta: float | int = right - left
    if not isinstance(delta, int):
        delta = round(delta, 6)
    return {"a": left, "b": right, "delta": delta}


def _keyed_delta(a: dict[str, Any] | None, b: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    left, right = dict(a or {}), dict(b or {})
    return {key: _delta(left.get(key), right.get(key)) for key in sorted(set(left) | set(right))}


def _severity_rank(group: DiffGroup) -> tuple[int, str]:
    level = group.max_severity_b or group.max_severity_a or "info"
    return (-SEVERITY_ORDER.get(level, -1), group.key)


def diff_runs(
    run_a: str,
    findings_a: list[UnifiedFinding],
    scorecard_a: dict[str, Any] | None,
    run_b: str,
    findings_b: list[UnifiedFinding],
    scorecard_b: dict[str, Any] | None,
) -> RunDiff:
    """Compare run A (older/baseline) with run B (newer). `new` = in B only, `resolved` = in A only."""
    groups_a, groups_b = _group(findings_a), _group(findings_b)
    new: list[DiffGroup] = []
    resolved: list[DiffGroup] = []
    persisting: list[DiffGroup] = []
    for key in sorted(set(groups_a) | set(groups_b)):
        in_a, in_b = groups_a.get(key, []), groups_b.get(key, [])
        sample = (in_b or in_a)[0]
        group = DiffGroup(
            key=key,
            category=sample.category,
            sub_category=sample.sub_category or "",
            target_id=sample.target_id,
            count_a=len(in_a),
            count_b=len(in_b),
            max_severity_a=_max_severity(in_a),
            max_severity_b=_max_severity(in_b),
            finding_ids_a=sorted(f.finding_id for f in in_a),
            finding_ids_b=sorted(f.finding_id for f in in_b),
        )
        if in_a and in_b:
            persisting.append(group)
        elif in_b:
            new.append(group)
        else:
            resolved.append(group)
    for bucket in (new, resolved, persisting):
        bucket.sort(key=_severity_rank)

    left, right = dict(scorecard_a or {}), dict(scorecard_b or {})
    return RunDiff(
        run_a=run_a,
        run_b=run_b,
        new=new,
        resolved=resolved,
        persisting=persisting,
        scorecard_delta={key: _delta(left.get(key), right.get(key)) for key in SCORECARD_DELTA_KEYS},
        asr_by_category_delta=_keyed_delta(left.get("asr_by_category"), right.get("asr_by_category")),
        eval_delta=_keyed_delta(left.get("eval_scores"), right.get("eval_scores")),
    )


@dataclass(slots=True)
class TrendPoint:
    """One run's numbers for one target. Severity counts and ASR are computed from the
    findings of that target only; `eval_pass_rate_run` is the run-level value (evaluator
    scores are not attributable to a target) and None when the run had no evaluators."""

    run_id: str
    name: str
    created_at: str
    status: str
    total_findings: int
    critical: int
    high: int
    critical_high: int
    asr_overall: float
    success_count: int
    total_attacks: int
    eval_pass_rate_run: float | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "TrendPoint":
        return cls(**{key: payload.get(key) for key in cls.__dataclass_fields__})  # type: ignore[arg-type]


def render_diff_text(diff: RunDiff) -> str:
    """Compact human summary for `urt diff --format text`."""
    lines = [f"Diff {diff.run_a} -> {diff.run_b} (identity: {' + '.join(diff.identity_fields)})", ""]
    for title, groups in (("new", diff.new), ("resolved", diff.resolved), ("persisting", diff.persisting)):
        lines.append(f"{title} ({len(groups)}):")
        for group in groups:
            lines.append(
                f"  - {group.key}  a={group.count_a}/{group.max_severity_a or '-'}  b={group.count_b}/{group.max_severity_b or '-'}"
            )
        lines.append("")
    lines.append("scorecard:")
    for key, values in diff.scorecard_delta.items():
        lines.append(f"  {key}: {values['a']} -> {values['b']} (delta {values['delta']})")
    if diff.asr_by_category_delta:
        lines.append("asr_by_category:")
        for key, values in diff.asr_by_category_delta.items():
            lines.append(f"  {key}: {values['a']} -> {values['b']} (delta {values['delta']})")
    if diff.eval_delta:
        lines.append("eval_scores:")
        for key, values in diff.eval_delta.items():
            lines.append(f"  {key}: {values['a']} -> {values['b']} (delta {values['delta']})")
    return "\n".join(lines)
