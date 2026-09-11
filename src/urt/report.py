"""Reporting helpers."""

from __future__ import annotations

import csv
import json
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


def render_html(scorecard: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    sorted_findings = sort_findings(findings)
    rows: list[str] = []
    for item in sorted_findings:
        rows.append(
            "<tr>"
            f"<td>{item.get('severity', '')}</td>"
            f"<td>{item.get('target_id', '')}</td>"
            f"<td>{item.get('engine', '')}</td>"
            f"<td>{item.get('category', '')}</td>"
            f"<td>{item.get('description', '')}</td>"
            "</tr>"
        )

    # Build eval results HTML section
    eval_scores = scorecard.get("eval_scores", {})
    eval_pass_rate = scorecard.get("eval_pass_rate", 0.0)
    eval_html = ""
    if eval_scores:
        eval_rows = "".join(
            f"<tr><td>{metric}</td><td>{avg:.4f}</td></tr>"
            for metric, avg in sorted(eval_scores.items())
        )
        eval_html = f"""
  <h2>Evaluation Results</h2>
  <div class="meta"><strong>Overall Pass Rate:</strong> {eval_pass_rate:.2%}</div>
  <table>
    <thead><tr><th>Metric</th><th>Avg Score</th></tr></thead>
    <tbody>{eval_rows}</tbody>
  </table>"""

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>URT Report {scorecard.get('run_id', 'unknown')}</title>
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
    <div><strong>Run ID:</strong> {scorecard.get('run_id', 'unknown')}</div>
    <div><strong>Total Findings:</strong> {scorecard.get('total_findings', 0)}</div>
    <div><strong>ASR Overall:</strong> {scorecard.get('asr_overall', 0.0):.2%}</div>
    <div><strong>Critical/High/Medium/Low/Info:</strong> {scorecard.get('critical', 0)}/{scorecard.get('high', 0)}/{scorecard.get('medium', 0)}/{scorecard.get('low', 0)}/{scorecard.get('info', 0)}</div>
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


def evaluate_gate(
    findings: list[UnifiedFinding],
    threshold: str = "high",
    *,
    waivers: list[dict[str, Any]] | None = None,
) -> tuple[bool, str]:
    threshold_name = threshold.upper()
    active_waivers = list(waivers or [])
    blocking: list[UnifiedFinding] = []
    waived_count = 0
    threshold_value = SEVERITY_ORDER.get(threshold.lower())
    if threshold_value is None:
        raise ValueError(f"Unsupported threshold: {threshold}")

    for finding in findings:
        level = SEVERITY_ORDER.get(finding.severity.lower(), -1)
        if level < threshold_value:
            continue
        matched = matching_waiver(finding, active_waivers)
        if matched:
            waived_count += 1
            continue
        blocking.append(finding)

    if blocking:
        waived_note = f" ({waived_count} waived)" if waived_count else ""
        return False, f"Gate failed: at least one finding severity >= {threshold_name}{waived_note}"
    if waived_count:
        return True, (
            f"Gate passed: {waived_count} finding(s) waived, none remaining severity >= {threshold_name}"
        )
    return True, f"Gate passed: no findings severity >= {threshold_name}"
