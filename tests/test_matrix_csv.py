"""Later phase: multi-run matrix (targets × runs) for the lead, and CSV export of the
framework coverage matrix (CSV is allowed; PDF is not).
"""

from __future__ import annotations

import csv
import io

import pytest
from conftest import TARGET_ID, Bundle, bundle_spec, engine_findings, with_engine_findings
from fastapi.testclient import TestClient

from urt.api import create_app
from urt.coverage_csv import COVERAGE_CSV_COLUMNS, coverage_csv
from urt.matrix import build_run_matrix
from urt.types import RunSpec, UnifiedFinding

EVIL_TARGET = 'other"><img src=x onerror=alert(1)>'


@pytest.fixture
def two_runs(rich_bundle: Bundle) -> tuple[Bundle, str]:
    spec = bundle_spec("other-agent-garak-real-20260917")
    spec["targets"][0]["id"] = EVIL_TARGET
    other = rich_bundle.orchestrator.execute(RunSpec.from_dict(spec))
    assert other["status"] == "completed"
    return rich_bundle, other["run_id"]


@pytest.fixture
def client(two_runs) -> TestClient:
    return TestClient(create_app(two_runs[0].orchestrator))


def test_build_run_matrix_has_targets_as_rows_and_runs_as_columns(two_runs):
    bundle, other_id = two_runs
    orch = bundle.orchestrator
    matrix = build_run_matrix(orch.list_runs(), orch.run_findings)

    assert [run["run_id"] for run in matrix.runs] == [other_id, bundle.run_id]  # newest first
    assert matrix.targets == sorted([TARGET_ID, EVIL_TARGET])
    mine = matrix.cells[TARGET_ID]
    assert mine[other_id] is None  # that run never included this target
    cell = mine[bundle.run_id]
    scorecard = bundle.read_json("scorecard.json")
    assert cell["critical"] == scorecard["critical"] and cell["high"] == scorecard["high"]
    assert cell["total_findings"] == scorecard["total_findings"]
    assert cell["asr_overall"] == pytest.approx(scorecard["asr_overall"])
    assert set(cell) >= {"critical", "high", "critical_high", "total_findings", "asr_overall", "success_count", "total_attacks", "status"}

    payload = matrix.to_dict()
    assert payload["targets"] == matrix.targets
    assert payload["cells"][EVIL_TARGET][bundle.run_id] is None
    assert "note" in payload and "per-target" in payload["note"]


def test_build_run_matrix_filters_and_caps_the_run_columns(two_runs):
    bundle, other_id = two_runs
    orch = bundle.orchestrator
    only_mine = build_run_matrix(orch.list_runs(), orch.run_findings, target=TARGET_ID)
    assert only_mine.targets == [TARGET_ID]
    assert [run["run_id"] for run in only_mine.runs] == [bundle.run_id]

    by_prefix = build_run_matrix(orch.list_runs(), orch.run_findings, name_prefix="other-agent-")
    assert [run["run_id"] for run in by_prefix.runs] == [other_id]

    capped = build_run_matrix(orch.list_runs(), orch.run_findings, limit=1)
    assert [run["run_id"] for run in capped.runs] == [other_id]
    assert capped.truncated is True


def test_matrix_api_and_page(client: TestClient, two_runs):
    bundle, other_id = two_runs
    payload = client.get("/v1/matrix").json()
    assert [run["run_id"] for run in payload["runs"]] == [other_id, bundle.run_id]
    assert payload["cells"][TARGET_ID][bundle.run_id]["critical"] == bundle.read_json("scorecard.json")["critical"]
    assert client.get("/v1/matrix", params={"limit": 0}).status_code == 400
    assert [run["run_id"] for run in client.get("/v1/matrix", params={"target": TARGET_ID}).json()["runs"]] == [bundle.run_id]

    page = client.get("/ui/matrix")
    assert page.status_code == 200
    assert f'href="/ui/runs/{bundle.run_id}"' in page.text and f'href="/ui/runs/{other_id}"' in page.text
    assert "&lt;img src=x onerror=alert(1)&gt;" in page.text
    assert "<img src=x" not in page.text
    assert "per-target" in page.text  # honesty note: cells are per-target scorecards, not run totals
    assert "<progress" not in page.text
    filtered = client.get("/ui/matrix", params={"name_prefix": "other-agent-"}).text
    assert other_id in filtered and bundle.run_id not in filtered
    assert client.get("/ui/matrix", params={"limit": "x"}).status_code == 400
    assert 'href="/ui/matrix"' in client.get("/ui").text


def test_coverage_csv_matches_the_json_matrix_and_neutralises_formula_cells(rich_bundle: Bundle):
    evil = UnifiedFinding(
        finding_id=f"{rich_bundle.run_id}:{TARGET_ID}:evil:0",
        run_id=rich_bundle.run_id,
        target_id=TARGET_ID,
        engine="promptfoo",
        category="=HYPERLINK(\"http://evil.example\",\"click\")",
        sub_category="x",
        severity="low",
        confidence=0.5,
        attack_vector="jailbreak",
        attack_complexity="unknown",
        success=True,
        description="formula-shaped category",
    )
    with_engine_findings(rich_bundle, engine_findings(rich_bundle.run_id) + [evil])
    coverage = rich_bundle.orchestrator.coverage(rich_bundle.run_id)
    text = coverage_csv(coverage)
    rows = list(csv.DictReader(io.StringIO(text)))
    assert list(rows[0]) == list(COVERAGE_CSV_COLUMNS)

    expected = 0
    for framework in coverage["frameworks"]:
        for row in framework["rows"]:
            for target, cell in row["cells"].items():
                expected += 1
                match = next(
                    r for r in rows if r["framework"] == framework["framework"] and r["label"] == row["label"] and r["target"] == target
                )
                assert int(match["count"]) == cell["count"]
                assert match["max_severity"] == (cell["max_severity"] or "")
                assert match["unmapped"] == ("yes" if row["unmapped"] else "no")
                assert match["basis"] == "category-level heuristic"
    assert len(rows) == expected
    unmapped_cells = [r for r in rows if r["unmapped"] == "yes"]
    assert unmapped_cells
    # Formula-shaped text is prefixed so a spreadsheet treats it as text (categories are
    # lower-cased by `canonical_category` on the way into the bundle).
    assert any(cat.startswith("'=hyperlink") for r in unmapped_cells for cat in r["categories"].split("; "))
    assert not any(field.startswith(("=", "+", "-", "@")) for r in rows for field in r.values())


@pytest.mark.parametrize(
    "value",
    ["=HYPERLINK(1)", "+1", "-2+3", "@SUM(A1)", "\t=x", "\r=x", "|cmd", "  =x", " \t+1", "\u00a0=x"],
)
def test_csv_safe_neutralises_formula_and_pipe_prefixes_after_leading_whitespace(value: str):
    from urt.coverage_csv import csv_safe

    safe = csv_safe(value)
    assert safe.startswith("'")
    assert safe.endswith(value)


@pytest.mark.parametrize("value", ["plain", "prompt injection", "a=b", "x|y", "", None])
def test_csv_safe_leaves_ordinary_text_alone(value):
    from urt.coverage_csv import csv_safe

    assert csv_safe(value) == ("" if value is None else value)


def test_coverage_csv_endpoint_and_link(client: TestClient, two_runs):
    bundle, _ = two_runs
    response = client.get(f"/v1/runs/{bundle.run_id}/coverage.csv")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert response.headers["content-disposition"] == f'attachment; filename="{bundle.run_id}-coverage.csv"'
    assert response.headers["x-content-type-options"] == "nosniff"
    rows = list(csv.DictReader(io.StringIO(response.text)))
    assert rows and rows[0]["framework"] in {"owasp_llm", "owasp_agentic", "mitre_atlas"}
    assert client.get("/v1/runs/missing/coverage.csv").status_code == 404

    detail = client.get(f"/ui/runs/{bundle.run_id}").text
    assert f'href="/v1/runs/{bundle.run_id}/coverage.csv"' in detail
