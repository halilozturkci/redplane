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


def render_html(scorecard: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    sorted_findings = sort_findings(findings)
    rows: list[str] = []
    for item in sorted_findings:
        rows.append(
            "<tr>"
            f"<td>{_esc(item.get('severity', ''))}</td>"
            f"<td>{_esc(item.get('target_id', ''))}</td>"
            f"<td>{_esc(item.get('engine', ''))}</td>"
            f"<td>{_esc(item.get('category', ''))}</td>"
            f"<td>{_esc(item.get('description', ''))}</td>"
            "</tr>"
        )

    run_id = _esc(scorecard.get("run_id", "unknown"))
    total_findings = _esc(scorecard.get("total_findings", 0))
    asr_overall = f"{float(scorecard.get('asr_overall', 0.0)):.2%}"
    severity_counts = "/".join(
        _esc(scorecard.get(level, 0)) for level in ("critical", "high", "medium", "low", "info")
    )

    # Build eval results HTML section
    eval_scores = scorecard.get("eval_scores", {})
    eval_pass_rate = scorecard.get("eval_pass_rate", 0.0)
    eval_html = ""
    if eval_scores:
        eval_rows = "".join(
            f"<tr><td>{_esc(metric)}</td><td>{float(avg):.4f}</td></tr>"
            for metric, avg in sorted(eval_scores.items())
        )
        eval_html = f"""
  <h2>Evaluation Results</h2>
  <div class="meta"><strong>Overall Pass Rate:</strong> {float(eval_pass_rate):.2%}</div>
  <table>
    <thead><tr><th>Metric</th><th>Avg Score</th></tr></thead>
    <tbody>{eval_rows}</tbody>
  </table>"""

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>URT Report {run_id}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 24px; }}
    h1, h2 {{ margin: 0 0 12px 0; }}
    .meta {{ margin-bottom: 20px; }}
    table {{ border-collapse: collapse; width: 100%; font-size: 14px; margin-bottom: 20px; }}
    th, td {{ border: 1px solid #d5d5d5; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #f2f2f2; }}
  </style>
</head>
<body>
  <h1>URT Report</h1>
  <div class="meta">
    <div><strong>Run ID:</strong> {run_id}</div>
    <div><strong>Total Findings:</strong> {total_findings}</div>
    <div><strong>ASR Overall:</strong> {asr_overall}</div>
    <div><strong>Critical/High/Medium/Low/Info:</strong> {severity_counts}</div>
  </div>
  <h2>Findings</h2>
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Target</th>
        <th>Engine</th>
        <th>Category</th>
        <th>Description</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>
  {eval_html}
</body>
</html>
"""


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
    waivers_applied: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _gate_finding_row(finding: UnifiedFinding) -> dict[str, Any]:
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
) -> GateResult:
    threshold_key = threshold.lower()
    threshold_value = SEVERITY_ORDER.get(threshold_key)
    if threshold_value is None:
        raise ValueError(f"Unsupported threshold: {threshold}")
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
                    **_gate_finding_row(finding),
                    "waiver_id": matched.get("waiver_id"),
                    "control_id": matched.get("control_id"),
                    "owner": matched.get("owner"),
                    "expires_at": matched.get("expires_at"),
                }
            )
            continue
        blocking.append(_gate_finding_row(finding))

    blocking.sort(key=_severity_sort_key)
    waived.sort(key=_severity_sort_key)

    if blocking:
        waived_note = f" ({len(waived)} waived)" if waived else ""
        message = f"Gate failed: at least one finding severity >= {threshold_name}{waived_note}"
    elif waived:
        message = (
            f"Gate passed: {len(waived)} finding(s) waived, none remaining severity >= {threshold_name}"
        )
    else:
        message = f"Gate passed: no findings severity >= {threshold_name}"

    return GateResult(
        ok=not blocking,
        threshold=threshold_key,
        message=message,
        blocking=blocking,
        waived=waived,
        waivers_applied=bool(active_waivers),
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
