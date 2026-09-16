"""CSV export of the framework coverage matrix (`GET /v1/runs/{id}/coverage`).

One row per (framework, control label, target) cell, flat enough for a spreadsheet.
Every row repeats the `basis` so the honesty label survives the export: mappings are
category-level heuristics, not per-test verdicts, and an empty count means "no finding
mapped there", not "covered". Cells that a spreadsheet would evaluate as a formula
(`=`, `+`, `-`, `@` prefixes) are neutralised with a leading apostrophe — category
names and labels are attacker-influenced text.
"""

from __future__ import annotations

import csv
from io import StringIO
from typing import Any

COVERAGE_CSV_COLUMNS = (
    "run_id",
    "framework",
    "framework_title",
    "label",
    "unmapped",
    "target",
    "count",
    "max_severity",
    "categories",
    "basis",
)
BASIS = "category-level heuristic"
# `|` is the DDE prefix some spreadsheets honour; leading whitespace (including the
# non-breaking space) is stripped by several importers before the formula check.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "|")


def csv_safe(value: Any) -> str:
    text = "" if value is None else str(value)
    if text.startswith(_FORMULA_PREFIXES) or text.lstrip().startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


def coverage_csv(coverage: dict[str, Any]) -> str:
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=list(COVERAGE_CSV_COLUMNS))
    writer.writeheader()
    run_id = coverage.get("run_id", "")
    for framework in coverage.get("frameworks") or []:
        for row in framework.get("rows") or []:
            for target, cell in (row.get("cells") or {}).items():
                categories = "; ".join(csv_safe(c) for c in sorted(cell.get("categories") or []))
                writer.writerow(
                    {
                        "run_id": csv_safe(run_id),
                        "framework": csv_safe(framework.get("framework")),
                        "framework_title": csv_safe(framework.get("title")),
                        "label": csv_safe(row.get("label")),
                        "unmapped": "yes" if row.get("unmapped") else "no",
                        "target": csv_safe(target),
                        "count": int(cell.get("count") or 0),
                        "max_severity": csv_safe(cell.get("max_severity") or ""),
                        "categories": csv_safe(categories),
                        "basis": BASIS,
                    }
                )
    return output.getvalue()
