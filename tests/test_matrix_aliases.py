"""v1 §4.4 / G11 (ideas 4 and 5): category aliases for framework mapping, the
`finding_kind` tag with an ASR allowlist, and the coverage matrix endpoint."""

from __future__ import annotations

from conftest import TARGET_ID, Bundle, engine_findings, with_engine_findings
from fastapi.testclient import TestClient

from urt.api import create_app
from urt.normalization import build_scorecard, normalize_findings
from urt.normalization.kind import finding_kind
from urt.policy.mapping import canonical_category, map_category
from urt.types import UnifiedFinding


def _finding(fid: str, category: str, *, engine: str = "pyrit", attack_vector: str = "prompt", sub: str | None = None, success: bool = True, metadata: dict | None = None):
    return UnifiedFinding(
        finding_id=fid,
        run_id="r",
        target_id="t1",
        engine=engine,
        category=category,
        sub_category=sub,
        severity="high",
        confidence=0.9,
        attack_vector=attack_vector,
        attack_complexity="unknown",
        success=success,
        description=category,
        metadata=metadata or {},
    )


def test_aliases_map_engine_specific_category_spellings_to_canonical_keys():
    assert canonical_category("hateunfairness") == "hate_unfairness"
    assert canonical_category("Hate-Unfairness") == "hate_unfairness"
    assert canonical_category("selfharm") == "self_harm"
    assert canonical_category("jailbreak") == "prompt_injection"
    assert canonical_category("indirect_prompt_injection") == "prompt_injection"
    assert canonical_category("sensitive_information_disclosure") == "data_exfiltration"
    assert canonical_category("pii") == "data_exfiltration"
    assert canonical_category("excessive_agency") == "tool_abuse"
    assert canonical_category("unknown_thing") == "unknown_thing"
    assert map_category("hateunfairness") == map_category("hate_unfairness")
    assert map_category("hateunfairness")["owasp_llm"] == ["LLM08:2025 Excessive Prompt Surface"]


def test_normalize_canonicalizes_category_and_tags_finding_kind():
    raw = [
        _finding("f-hate", "hateunfairness"),
        _finding("f-skip", "coverage_gap", engine="garak", sub="engine_skipped", attack_vector="n/a"),
        _finding("f-exec", "execution", engine="garak", attack_vector="tool_runtime"),
        _finding("f-eval", "eval_quality", engine="deepeval", attack_vector="n/a"),
        _finding("f-health", "misconfiguration", engine="platform", attack_vector="connectivity", sub="target_healthcheck"),
    ]
    out = {f.finding_id: f for f in normalize_findings(raw, policy_profiles=["owasp_llm", "owasp_agentic", "mitre_atlas"])}

    hate = out["f-hate"]
    assert hate.category == "hate_unfairness"
    assert hate.metadata["category_reported"] == "hateunfairness"
    assert hate.mappings["owasp_llm"] == ["LLM08:2025 Excessive Prompt Surface"]
    assert hate.metadata["finding_kind"] == "attack"
    assert out["f-skip"].metadata["finding_kind"] == "coverage_gap"
    assert out["f-exec"].metadata["finding_kind"] == "execution"
    assert out["f-eval"].metadata["finding_kind"] == "eval"
    assert out["f-health"].metadata["finding_kind"] == "execution"
    assert "category_reported" not in out["f-skip"].metadata

    # The tag wins over derivation once present; derivation covers untagged (older) records.
    assert finding_kind({"metadata": {"finding_kind": "eval"}, "category": "prompt_injection"}) == "eval"
    assert finding_kind({"category": "prompt_injection", "engine": "pyrit", "attack_vector": "x"}) == "attack"


def test_scorecard_asr_counts_only_attack_kind_findings():
    findings = normalize_findings(
        [
            _finding("a1", "prompt_injection", success=True),
            _finding("a2", "prompt_injection", success=False),
            _finding("skip", "coverage_gap", engine="garak", sub="engine_skipped", attack_vector="n/a"),
            _finding("exec", "execution", engine="garak", attack_vector="tool_runtime"),
            _finding("eval", "eval_quality", engine="deepeval", attack_vector="n/a"),
            _finding("health", "misconfiguration", engine="platform", attack_vector="connectivity", sub="target_healthcheck"),
        ],
        policy_profiles=["owasp_llm"],
    )
    score = build_scorecard("r", findings)
    assert score.total_attacks == 2
    assert score.success_count == 1
    assert score.asr_overall == 0.5
    assert set(score.asr_by_category) == {"prompt_injection"}
    assert score.total_findings == 6  # counts are not filtered, only the ASR is


def test_coverage_endpoint_and_matrix_page_are_honest_about_heuristics(rich_bundle: Bundle):
    run_id = rich_bundle.run_id
    unmapped = _finding(f"{run_id}:{TARGET_ID}:pyrit:odd", "some_new_probe_family", engine="pyrit")
    unmapped.run_id, unmapped.target_id = run_id, TARGET_ID
    aliased = _finding(f"{run_id}:{TARGET_ID}:pyrit:hate", "hateunfairness", engine="pyrit")
    aliased.run_id, aliased.target_id = run_id, TARGET_ID
    with_engine_findings(rich_bundle, [unmapped, aliased])
    client = TestClient(create_app(rich_bundle.orchestrator))

    response = client.get(f"/v1/runs/{run_id}/coverage")
    assert response.status_code == 200
    body = response.json()
    assert "category-level heuristic" in body["note"]
    assert body["targets"] == [TARGET_ID]
    frameworks = {m["framework"]: m for m in body["frameworks"]}
    assert set(frameworks) == {"owasp_llm", "owasp_agentic", "mitre_atlas"}
    llm = frameworks["owasp_llm"]
    rows = {row["label"]: row for row in llm["rows"]}
    assert rows["LLM01:2025 Prompt Injection"]["cells"][TARGET_ID]["count"] == 2
    assert rows["LLM01:2025 Prompt Injection"]["cells"][TARGET_ID]["max_severity"] == "critical"
    assert rows["LLM08:2025 Excessive Prompt Surface"]["cells"][TARGET_ID]["categories"] == ["hate_unfairness"]
    assert rows["unmapped"]["unmapped"] is True
    assert "some_new_probe_family" in rows["unmapped"]["cells"][TARGET_ID]["categories"]
    assert "some_new_probe_family" in body["unmapped_categories"]
    assert "hate_unfairness" not in body["unmapped_categories"]
    assert body["excluded_kinds"] == ["coverage_gap", "eval", "execution"]
    assert client.get("/v1/runs/nope/coverage").status_code == 404

    page = client.get(f"/ui/runs/{run_id}").text
    assert "category-level heuristics" in page
    assert '<tr class="unmapped">' in page
    assert "some_new_probe_family" in page
