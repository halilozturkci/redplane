"""`load_bundle`: the one place that reads an audit bundle for display.

It hides redaction (legacy bundles), evidence-path resolution, waiver matching,
finding kind derivation and per-engine transcript extraction behind `RunBundle`.
"""

from __future__ import annotations

from conftest import LEGACY_SECRET, TARGET_ID, Bundle

from urt.ui import load_bundle


def test_load_bundle_reads_a_real_1_1_bundle(real_bundle: Bundle):
    bundle = load_bundle(real_bundle.run_dir, waivers=[])

    assert bundle.run_id == real_bundle.run_id
    assert bundle.bundle_format_version == "1.1"
    assert bundle.legacy is False
    assert bundle.manifest["status"] == "completed"
    assert bundle.summary["targets"] == [TARGET_ID]
    assert bundle.scorecard["total_findings"] == len(bundle.findings)
    assert [row["engine"] for row in bundle.invocations] == ["garak", "promptfoo"]
    assert {item["path"] for item in bundle.artifacts} >= {"findings.json", "scorecard.json", "report.md"}
    assert all({"path", "size_bytes", "sha256"} <= set(item) for item in bundle.artifacts)


def test_evidence_refs_resolve_to_bundle_relative_paths_and_kinds_are_derived(real_bundle: Bundle):
    bundle = load_bundle(real_bundle.run_dir, waivers=[])

    execution = next(v for v in bundle.findings if v.record["sub_category"] == "engine_runtime")
    assert execution.kind == "execution"
    assert [link.relative_path for link in execution.evidence] == [
        f"raw/garak/{TARGET_ID}_stdout.log",
        f"raw/garak/{TARGET_ID}_stderr.log",
    ]
    assert all(link.absolute_ref.startswith("/") for link in execution.evidence)

    skipped = next(v for v in bundle.findings if v.record["engine"] == "promptfoo")
    assert skipped.kind == "coverage_gap"
    assert skipped.evidence == []


def test_waivers_active_at_load_time_mark_matching_findings(real_bundle: Bundle):
    expired = {
        "waiver_id": "w-old",
        "target_id": TARGET_ID,
        "control_id": "execution",
        "reason": "r",
        "owner": "o",
        "expires_at": "2000-01-01T00:00:00+00:00",
    }
    active = {**expired, "waiver_id": "w-exec", "expires_at": "2099-01-01T00:00:00+00:00"}

    bundle = load_bundle(real_bundle.run_dir, waivers=[expired, active])

    execution = next(v for v in bundle.findings if v.record["category"] == "execution")
    assert execution.waived is True
    assert execution.waiver["waiver_id"] == "w-exec"
    coverage = next(v for v in bundle.findings if v.kind == "coverage_gap")
    assert coverage.waived is False
    assert [w["waiver_id"] for w in bundle.waivers] == ["w-exec"]

    verdict = bundle.gate("info")
    assert verdict.ok is False
    assert [row["finding_id"] for row in verdict.waived] == [execution.finding_id]
    assert coverage.finding_id in [row["finding_id"] for row in verdict.blocking]
    assert bundle.gate("info", ignore_waivers=True).waived == []
    assert bundle.default_threshold == "high"  # pr_gate profile default
    assert bundle.gates()["high"].ok is True


def test_legacy_bundle_is_redacted_at_load_time(legacy_bundle: Bundle):
    bundle = load_bundle(legacy_bundle.run_dir, waivers=[])

    assert bundle.legacy is True
    assert bundle.bundle_format_version == "1.0"
    assert bundle.manifest["targets"][0]["auth"]["headers"]["Authorization"] == "***REDACTED***"
    assert bundle.resolved_spec["targets"][0]["auth"]["headers"]["Authorization"] == "***REDACTED***"
    execution = next(v for v in bundle.findings if v.record["sub_category"] == "engine_runtime")
    assert execution.record["metadata"]["env_overrides"] == {"ECHO": "***REDACTED***"}
    assert execution.record["metadata"]["command"] == ["***REDACTED***"] * 3
    assert LEGACY_SECRET not in execution.metadata_json
    assert LEGACY_SECRET not in repr(bundle)


def test_transcripts_are_extracted_per_engine(rich_bundle: Bundle):
    bundle = load_bundle(rich_bundle.run_dir, waivers=[])
    by_engine = {v.record["engine"]: v for v in bundle.findings if v.kind == "attack"}

    promptfoo = by_engine["promptfoo"]
    assert promptfoo.transcript_source == "metadata.raw"
    assert [(t.role, t.content[:6]) for t in promptfoo.transcript] == [
        ("user", "Ignore"),
        ("assistant", "Sure. "),
        ("grader", "Output"),
    ]
    garak = by_engine["garak"]
    assert [t.role for t in garak.transcript] == ["user", "assistant"]
    assert garak.transcript[1].content == "DAN here. What would you like me to do?"
    deepteam = by_engine["deepteam"]
    assert [t.role for t in deepteam.transcript] == ["user", "assistant", "grader"]
    pyrit = by_engine["pyrit"]
    assert pyrit.transcript_source == "metadata.conversation_preview"
    assert pyrit.transcript == [pyrit.transcript[0]]
    assert pyrit.transcript[0].role == "assistant"

    # Sorted by severity rank, mapping chips follow policy/mapping.py.
    assert [v.severity for v in bundle.findings] == ["critical", "high", "medium", "low", "info", "info"]
    assert ("owasp_llm", "LLM01:2025 Prompt Injection") in promptfoo.mapping_chips
    assert ("mitre_atlas", "AML.T0051 Prompt Injection") in promptfoo.mapping_chips


def test_metadata_json_is_capped_and_flagged(rich_bundle: Bundle):
    bundle = load_bundle(rich_bundle.run_dir, waivers=[], metadata_cap=64)
    promptfoo = next(v for v in bundle.findings if v.record["engine"] == "promptfoo" and v.kind == "attack")
    assert promptfoo.metadata_truncated is True
    assert len(promptfoo.metadata_json) == 64

    full = load_bundle(rich_bundle.run_dir, waivers=[])
    assert all(v.metadata_truncated is False for v in full.findings)


def test_framework_matrix_counts_attack_findings_per_target_with_unmapped_row(rich_bundle: Bundle):
    bundle = load_bundle(rich_bundle.run_dir, waivers=[])
    matrices = {m.framework: m for m in bundle.framework_matrices()}

    llm = matrices["owasp_llm"]
    assert llm.targets == [TARGET_ID]
    rows = {row.label: row for row in llm.rows}
    injection = rows["LLM01:2025 Prompt Injection"].cells[TARGET_ID]
    assert injection.count == 2  # promptfoo + deepteam
    assert injection.max_severity == "critical"
    assert injection.categories == {"prompt_injection"}
    assert "LLM09:2025 Overreliance" in rows  # garak robustness
    assert rows["LLM06:2025 Excessive Agency"].cells[TARGET_ID].count == 1  # pyrit violence

    atlas = matrices["mitre_atlas"]
    atlas_rows = {row.label: row for row in atlas.rows}
    # robustness and violence have no ATLAS mapping: they land in "unmapped", not nowhere.
    assert atlas_rows["unmapped"].unmapped is True
    assert atlas_rows["unmapped"].cells[TARGET_ID].count == 2
    # Execution and coverage-gap findings never count as framework coverage.
    assert sum(cell.count for row in llm.rows for cell in row.cells.values()) == 4


def test_load_bundle_rejects_missing_run_dir(tmp_path):
    import pytest

    with pytest.raises(FileNotFoundError):
        load_bundle(tmp_path / "nope", waivers=[])
