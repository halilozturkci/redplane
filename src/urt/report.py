"""Reporting helpers."""

from __future__ import annotations

import csv
import html
import json
from dataclasses import asdict, dataclass, field
from io import StringIO
from pathlib import Path
from typing import Any

from .constants import SEVERITY_ORDER
from .policy.waivers import matching_waiver
from .types import UnifiedFinding


def load_findings(path: str | Path) -> list[UnifiedFinding]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    findings: list[UnifiedFinding] = []
    for item in payload:
        findings.append(
            UnifiedFinding(
                finding_id=item["finding_id"],
                run_id=item["run_id"],
                target_id=item["target_id"],
                engine=item["engine"],
                category=item["category"],
                sub_category=item.get("sub_category"),
                severity=item["severity"],
                confidence=float(item.get("confidence", 0.0)),
                attack_vector=item.get("attack_vector", "unknown"),
                attack_complexity=item.get("attack_complexity", "unknown"),
                success=bool(item.get("success", False)),
                description=item.get("description", ""),
                evidence_refs=item.get("evidence_refs", []),
                repro_steps=item.get("repro_steps", []),
                mappings=item.get("mappings", {}),
                metadata=item.get("metadata", {}),
            )
        )
    return findings


def render_markdown(scorecard: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    sorted_findings = sort_findings(findings)

    lines = [
        f"# URT Report - {scorecard.get('run_id', 'unknown')}",
        "",
        "## Scorecard",
        f"- Total Findings: {scorecard.get('total_findings', 0)}",
        f"- ASR Overall: {scorecard.get('asr_overall', 0.0):.2%}",
        f"- Critical/High/Medium/Low/Info: {scorecard.get('critical', 0)}/{scorecard.get('high', 0)}/{scorecard.get('medium', 0)}/{scorecard.get('low', 0)}/{scorecard.get('info', 0)}",
        "",
        "## Executive Summary",
    ]

    critical_high = [x for x in sorted_findings if str(x.get("severity", "info")).lower() in {"critical", "high"}]
    if critical_high:
        lines.append(f"- Critical/High finding count: {len(critical_high)}")
        lines.append("- Immediate action recommended for items below.")
    else:
        lines.append("- No critical/high findings detected in this run.")

    lines.extend(["", "## Top Findings"])

    if not sorted_findings:
        lines.append("No findings.")
    else:
        for item in sorted_findings[:30]:
            lines.append(
                f"- [{item.get('severity','info').upper()}] {item.get('target_id')} / {item.get('engine')} / {item.get('category')}: {item.get('description')}"
            )

    by_engine: dict[str, int] = {}
    for item in findings:
        by_engine[item.get("engine", "unknown")] = by_engine.get(item.get("engine", "unknown"), 0) + 1

    lines.extend(["", "## Findings By Engine"])
    for engine, count in sorted(by_engine.items(), key=lambda x: x[0]):
        lines.append(f"- {engine}: {count}")

    # Evaluation Results section
    eval_scores = scorecard.get("eval_scores", {})
    eval_pass_rate = scorecard.get("eval_pass_rate", 0.0)
    if eval_scores:
        lines.extend(["", "## Evaluation Results"])
        lines.append(f"- Overall Pass Rate: {eval_pass_rate:.2%}")
        lines.append("")
        lines.append("| Metric | Avg Score |")
        lines.append("|--------|-----------|")
        for metric, avg in sorted(eval_scores.items()):
            lines.append(f"| {metric} | {avg:.4f} |")

    return "\n".join(lines)


def _esc(value: Any) -> str:
    """Escape attacker-influenced text (finding fields, model output) for HTML."""
    return html.escape(str(value), quote=True)


def render_html(
    scorecard: dict[str, Any],
    findings: list[dict[str, Any]],
    *,
    waivers: list[dict[str, Any]] | None = None,
) -> str:
    """Self-contained HTML viewer for one run from in-memory payloads.

    Callers with a run directory should prefer `Orchestrator.write_reports` /
    `urt.ui.load_bundle`, which also embed the manifest, invocations, evidence
    links and the bundle file list. Every interpolated value is autoescaped.
    """
    from .ui import build_bundle
    from .ui.render import render_run_page

    bundle = build_bundle(
        str(scorecard.get("run_id", "unknown")),
        scorecard=scorecard,
        findings=findings,
        manifest={"run_id": scorecard.get("run_id", "unknown"), "status": "completed"},
        waivers=waivers,
    )
    return render_run_page(bundle, mode="static")


def render_csv(findings: list[dict[str, Any]]) -> str:
    output = StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "finding_id",
            "run_id",
            "target_id",
            "engine",
            "severity",
            "category",
            "sub_category",
            "attack_vector",
            "attack_complexity",
            "success",
            "description",
        ],
    )
    writer.writeheader()
    for item in sort_findings(findings):
        writer.writerow(
            {
                "finding_id": item.get("finding_id"),
                "run_id": item.get("run_id"),
                "target_id": item.get("target_id"),
                "engine": item.get("engine"),
                "severity": item.get("severity"),
                "category": item.get("category"),
                "sub_category": item.get("sub_category"),
                "attack_vector": item.get("attack_vector"),
                "attack_complexity": item.get("attack_complexity"),
                "success": item.get("success"),
                "description": item.get("description"),
            }
        )
    return output.getvalue()


def sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        findings,
        key=lambda x: SEVERITY_ORDER.get(str(x.get("severity", "info")).lower(), -1),
        reverse=True,
    )


@dataclass(slots=True)
class GateResult:
    """Structured gate verdict: what blocks, what was waived and by which waiver."""

    ok: bool
    threshold: str
    message: str
    blocking: list[dict[str, Any]] = field(default_factory=list)
    waived: list[dict[str, Any]] = field(default_factory=list)
    # True when waivers were supplied to the evaluation (not: a waiver matched).
    waivers_considered: bool = False
    # Optional evaluator floor (idea 2). `eval_ok` is None when no minimum was requested,
    # False when the scorecard has no evaluator scores at all (never silently passed).
    eval_min_pass_rate: float | None = None
    eval_pass_rate: float | None = None
    eval_ok: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "GateResult":
        def _opt_float(key: str) -> float | None:
            value = payload.get(key)
            return None if value is None else float(value)

        eval_ok = payload.get("eval_ok")
        return cls(
            ok=bool(payload["ok"]),
            threshold=str(payload["threshold"]),
            message=str(payload.get("message", "")),
            blocking=list(payload.get("blocking", [])),
            waived=list(payload.get("waived", [])),
            waivers_considered=bool(payload.get("waivers_considered", False)),
            eval_min_pass_rate=_opt_float("eval_min_pass_rate"),
            eval_pass_rate=_opt_float("eval_pass_rate"),
            eval_ok=None if eval_ok is None else bool(eval_ok),
        )


def scorecard_eval_pass_rate(scorecard: dict[str, Any] | None) -> float | None:
    """The scorecard's `eval_pass_rate`, or None when the run had no evaluator scores
    (`build_scorecard` writes 0.0 in that case, which must not read as "0% passed")."""
    if not scorecard or not scorecard.get("eval_scores"):
        return None
    try:
        return float(scorecard.get("eval_pass_rate", 0.0))
    except (TypeError, ValueError):
        return None


def parse_eval_min_pass_rate(raw: Any) -> float | None:
    """Parse a user-supplied evaluator floor; None for absent/blank, ValueError otherwise."""
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"eval_min_pass_rate must be a number between 0 and 1, got {raw!r}") from exc
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"eval_min_pass_rate must be between 0 and 1, got {value}")
    return value


def gate_finding_row(finding: UnifiedFinding) -> dict[str, Any]:
    return {
        "finding_id": finding.finding_id,
        "severity": finding.severity,
        "target_id": finding.target_id,
        "engine": finding.engine,
        "category": finding.category,
        "sub_category": finding.sub_category,
        "description": finding.description,
    }


def _severity_sort_key(row: dict[str, Any]) -> tuple[int, str]:
    return (-SEVERITY_ORDER.get(str(row.get("severity", "info")).lower(), -1), str(row.get("finding_id", "")))


def gate_result(
    findings: list[UnifiedFinding],
    threshold: str = "high",
    *,
    waivers: list[dict[str, Any]] | None = None,
    eval_min_pass_rate: float | None = None,
    eval_pass_rate: float | None = None,
) -> GateResult:
    threshold_key = threshold.lower()
    threshold_value = SEVERITY_ORDER.get(threshold_key)
    if threshold_value is None:
        raise ValueError(f"Unsupported threshold: {threshold}")
    eval_min = parse_eval_min_pass_rate(eval_min_pass_rate)
    threshold_name = threshold_key.upper()
    active_waivers = list(waivers or [])

    blocking: list[dict[str, Any]] = []
    waived: list[dict[str, Any]] = []
    for finding in findings:
        level = SEVERITY_ORDER.get(finding.severity.lower(), -1)
        if level < threshold_value:
            continue
        matched = matching_waiver(finding, active_waivers)
        if matched:
            waived.append(
                {
                    **gate_finding_row(finding),
                    "waiver_id": matched.get("waiver_id"),
                    "control_id": matched.get("control_id"),
                    "owner": matched.get("owner"),
                    "expires_at": matched.get("expires_at"),
                }
            )
            continue
        blocking.append(gate_finding_row(finding))

    blocking.sort(key=_severity_sort_key)
    waived.sort(key=_severity_sort_key)

    waived_note = f" ({len(waived)} waived)" if waived else ""
    if blocking:
        findings_clause = f"at least one finding severity >= {threshold_name}{waived_note}"
    elif waived:
        findings_clause = f"{len(waived)} finding(s) waived, none remaining severity >= {threshold_name}"
    else:
        findings_clause = f"no findings severity >= {threshold_name}"

    eval_ok: bool | None = None
    eval_clause = ""
    if eval_min is not None:
        if eval_pass_rate is None:
            eval_ok = False
            eval_clause = f"eval pass rate unavailable (no evaluator scores), minimum {eval_min:.1%} required"
        elif eval_pass_rate >= eval_min:
            eval_ok = True
            eval_clause = f"eval pass rate {eval_pass_rate:.1%} >= minimum {eval_min:.1%}"
        else:
            eval_ok = False
            eval_clause = f"eval pass rate {eval_pass_rate:.1%} below minimum {eval_min:.1%}"

    ok = not blocking and eval_ok is not False
    if ok:
        message = f"Gate passed: {findings_clause}" + (f"; {eval_clause}" if eval_clause else "")
    elif blocking and eval_ok is False:
        message = f"Gate failed: {findings_clause}; {eval_clause}"
    elif blocking:
        message = f"Gate failed: {findings_clause}"
    else:
        message = f"Gate failed: {eval_clause} ({findings_clause})"

    return GateResult(
        ok=ok,
        threshold=threshold_key,
        message=message,
        blocking=blocking,
        waived=waived,
        waivers_considered=bool(active_waivers),
        eval_min_pass_rate=eval_min,
        eval_pass_rate=eval_pass_rate,
        eval_ok=eval_ok,
    )


def evaluate_gate(
    findings: list[UnifiedFinding],
    threshold: str = "high",
    *,
    waivers: list[dict[str, Any]] | None = None,
) -> tuple[bool, str]:
    """Boolean/message view of `gate_result`, kept for `urt gate` and existing callers."""
    result = gate_result(findings, threshold, waivers=waivers)
    return result.ok, result.message
