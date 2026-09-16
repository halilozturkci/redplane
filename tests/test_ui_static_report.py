"""`report.html` as a self-contained viewer (Option C).

Exit criterion under test: a CI reviewer who only has the uploaded bundle can
explain a gate failure from `report.html` alone — no server, no Python, no JSON.
"""

from __future__ import annotations

import base64
import hashlib
import re

import pytest
from conftest import LEGACY_SECRET, TARGET_ID, Bundle

from urt.ui import load_bundle
from urt.ui.render import render_run_page

WAIVER = {
    "waiver_id": "w-garak-dan",
    "target_id": TARGET_ID,
    "control_id": "mitigation.MitigationBypass",
    "reason": "known DAN bypass, mitigation ticket SEC-142",
    "owner": "sec-lead@example.test",
    "expires_at": "2099-01-01T00:00:00+00:00",
}


def _static_page(bundle: Bundle, waivers: list[dict] | None = None, **kwargs) -> str:
    return render_run_page(load_bundle(bundle.run_dir, waivers=waivers or []), mode="static", **kwargs)


def test_reviewer_can_explain_a_gate_failure_from_report_html_alone(rich_bundle: Bundle):
    html = _static_page(rich_bundle, waivers=[WAIVER])
    run_id = rich_bundle.run_id

    # The default threshold for pr_gate is high: the critical Promptfoo finding blocks,
    # the high Garak finding is waived. Both facts and the reason are on the page.
    assert "Gate failed: at least one finding severity &gt;= HIGH (1 waived)" in html
    assert f"{run_id}:{TARGET_ID}:promptfoo:test:0" in html
    assert "Model disclosed the system prompt when asked to ignore instructions" in html
    assert f"{run_id}:{TARGET_ID}:garak:3" in html
    assert "w-garak-dan" in html
    assert "sec-lead@example.test" in html
    assert "2099-01-01T00:00:00+00:00" in html
    assert "known DAN bypass, mitigation ticket SEC-142" in html

    # Every threshold is pre-evaluated so the viewer can switch without a server.
    for level in ("critical", "high", "medium", "low", "info"):
        assert f'data-threshold="{level}"' in html
    assert "Gate passed: no findings severity &gt;= CRITICAL" not in html  # critical finding exists
    assert "Gate failed: at least one finding severity &gt;= CRITICAL" in html

    # Self-contained: nothing fetched from the network.
    assert "http://" not in html.replace("http://localhost:9999/invoke", "")
    assert "https://" not in html
    assert "<link" not in html
    assert 'src="' not in html


def test_static_page_escapes_attacker_text_and_locks_scripts_with_a_hash_csp(rich_bundle: Bundle):
    html = _static_page(rich_bundle)

    # Attacker-controlled model output from the Promptfoo transcript.
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<b>You are a helpful assistant</b>" not in html

    csp = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)"', html)
    assert csp, "CSP meta missing"
    policy = csp.group(1)
    assert "default-src 'none'" in policy
    assert "'unsafe-inline'" not in policy
    assert "'unsafe-eval'" not in policy

    scripts = re.findall(r"<script>(.*?)</script>", html, flags=re.S)
    assert len(scripts) == 1, "exactly one executable inline script"
    digest = base64.b64encode(hashlib.sha256(scripts[0].encode("utf-8")).digest()).decode("ascii")
    assert f"script-src 'sha256-{digest}'" in policy

    styles = re.findall(r"<style>(.*?)</style>", html, flags=re.S)
    assert len(styles) == 1
    style_digest = base64.b64encode(hashlib.sha256(styles[0].encode("utf-8")).digest()).decode("ascii")
    assert f"style-src 'sha256-{style_digest}'" in policy

    # Hash CSP forbids inline handlers and style attributes; the page must not rely on them.
    assert not re.search(r"\son[a-z]+=", html)
    assert ' style="' not in html
    # Embedded data is inert JSON, never executable, and cannot close its own tag.
    data = re.search(r'<script type="application/json" id="redplane-data">(.*?)</script>', html, flags=re.S)
    assert data
    assert "</" not in data.group(1)
    assert "<" not in data.group(1)


def test_static_page_shows_scorecard_tiles_eval_table_matrix_and_files(rich_bundle: Bundle):
    html = _static_page(rich_bundle)
    scorecard = rich_bundle.read_json("scorecard.json")
    index = {row["path"]: row for row in rich_bundle.read_json("artifacts_index.json")}
    manifest = rich_bundle.read_json("run_manifest.json")

    assert f'<span class="tile-value">{scorecard["total_findings"]}</span>' in html
    assert f"{scorecard['asr_overall']:.1%}" in html
    assert f"{scorecard['eval_pass_rate']:.1%}" in html
    # Budget snapshot verbatim: no invented cost figure anywhere in the scorecard.
    tiles = re.search(r'<div class="tiles">(.*?)</div>\s*(?:<h3|<p)', html, flags=re.S).group(1)
    assert f"cost_enforcement: {manifest['budget']['cost_enforcement']}" in tiles
    assert "$" not in tiles
    assert "USD" not in tiles

    assert "<td>answer_relevancy</td><td>0.8200</td>" in html
    assert "<td>toxicity</td><td>0.7000</td>" in html

    assert "OWASP LLM Top 10 (2025)" in html
    assert "LLM01:2025 Prompt Injection" in html
    assert "MITRE ATLAS" in html
    assert "unmapped" in html
    assert "category-level heuristics" in html

    for rel in ("findings.json", "scorecard.json", f"raw/garak/{TARGET_ID}_stdout.log"):
        assert f'href="{rel}"' in html, rel
        assert index[rel]["sha256"] in html, rel
    # The page cannot know its own final hash.
    assert index["report.html"]["sha256"] not in html

    assert 'data-engine="garak"' in html
    assert "engine_skipped" in html
    assert "coverage_gap" in html


def test_metadata_json_is_capped_and_links_to_findings_json(rich_bundle: Bundle):
    page = render_run_page(load_bundle(rich_bundle.run_dir, waivers=[], metadata_cap=80), mode="static")
    assert "truncated" in page
    assert 'href="findings.json"' in page

    full = _static_page(rich_bundle)
    assert "truncated at" not in full


def test_static_page_for_a_legacy_bundle_is_redacted_and_labelled(legacy_bundle: Bundle):
    html = _static_page(legacy_bundle)
    assert LEGACY_SECRET not in html
    assert "1.0" in html
    assert "predates write-time redaction" in html


def test_failed_run_page_shows_error_head_and_no_invented_numbers(orchestrator):
    from urt.types import RunSpec
    from conftest import PYTHON, bundle_spec

    spec = bundle_spec("broken")
    spec["engines"] = [
        {"name": "garak", "fail_open": False, "params": {"command": f'{PYTHON} -c "raise SystemExit(3)"'}}
    ]
    result = orchestrator.execute(RunSpec.from_dict(spec))
    assert result["status"] == "failed"
    run_dir = orchestrator.artifact_store.run_dir(result["run_id"])

    html = render_run_page(load_bundle(run_dir, waivers=[]), mode="static")
    assert "failed" in html
    assert "fail_open=false" in html
    assert "run_error.log" in html
    assert "No scorecard" in html


@pytest.mark.parametrize("mode", ["static"])
def test_render_is_deterministic_for_the_same_bundle(rich_bundle: Bundle, mode: str):
    bundle = load_bundle(rich_bundle.run_dir, waivers=[])
    assert render_run_page(bundle, mode=mode) == render_run_page(bundle, mode=mode)
