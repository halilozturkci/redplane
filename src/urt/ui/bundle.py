"""Read an audit bundle for display.

`load_bundle` is the single read seam for the static viewer, `urt view` and the
served `/ui` pages. It hides what would otherwise be spread across callers:
read-time redaction for pre-1.1 bundles, absolute evidence refs → bundle-relative
paths, waiver matching, finding kind derivation and per-engine transcripts.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..constants import (
    DEFAULT_RUN_PROFILE,
    REDACTED_BUNDLE_MIN_VERSION,
    REPORT_METADATA_JSON_CAP,
    RUN_PROFILE_DEFAULTS,
    SEVERITY_ORDER,
)
from ..normalization.kind import FINDING_KINDS, finding_kind
from ..policy.waivers import matching_waiver, waiver_is_active
from ..redaction import redact_bundle_payload
from ..report import GateResult, gate_result, scorecard_eval_pass_rate, sort_findings
from ..types import UnifiedFinding
from .transcript import Turn, extract_transcript

FRAMEWORKS = ("owasp_llm", "owasp_agentic", "mitre_atlas")
FRAMEWORK_LABELS = {
    "owasp_llm": "OWASP LLM Top 10 (2025)",
    "owasp_agentic": "OWASP Agentic (2026)",
    "mitre_atlas": "MITRE ATLAS",
}
MATRIX_NOTE = (
    "Mappings are category-level heuristics (policy/mapping.py), not per-test verdicts. "
    "An empty cell means no finding mapped there, not that the control is covered or safe. "
    "Only attack findings count; coverage_gap, execution and eval findings are excluded."
)
_ = FINDING_KINDS  # re-exported for templates/tests that enumerate kinds
ERROR_LOG_HEAD_LINES = 40
LEGACY_ERROR_WITHHELD = (
    f"error text not shown for pre-{REDACTED_BUNDLE_MIN_VERSION} bundles "
    "(it may contain unscrubbed command lines); read run_error.log on disk"
)


def _parse_version(value: str | None) -> tuple[int, ...]:
    if not value:
        return (0,)
    try:
        return tuple(int(part) for part in str(value).split("."))
    except ValueError:
        return (0,)


@dataclass(slots=True)
class EvidenceLink:
    absolute_ref: str
    relative_path: str | None

    @property
    def label(self) -> str:
        return self.relative_path or Path(self.absolute_ref).name


@dataclass(slots=True)
class FindingView:
    """One finding plus everything a renderer needs that the record does not carry."""

    record: dict[str, Any]
    kind: str
    waiver: dict[str, Any] | None
    evidence: list[EvidenceLink]
    transcript: list[Turn]
    transcript_source: str
    metadata_json: str
    metadata_truncated: bool
    mapping_chips: list[tuple[str, str]]

    @property
    def finding_id(self) -> str:
        return str(self.record.get("finding_id", ""))

    @property
    def severity(self) -> str:
        return str(self.record.get("severity", "info")).lower()

    @property
    def waived(self) -> bool:
        return self.waiver is not None

    def facet_values(self) -> dict[str, str]:
        record = self.record
        return {
            "severity": self.severity,
            "engine": str(record.get("engine", "")),
            "category": str(record.get("category", "")),
            "sub_category": str(record.get("sub_category") or ""),
            "target": str(record.get("target_id", "")),
            "success": "yes" if record.get("success") else "no",
            "waived": "yes" if self.waived else "no",
            "kind": self.kind,
        }


@dataclass(slots=True)
class FrameworkCell:
    count: int = 0
    max_severity: str | None = None
    categories: set[str] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        return {"count": self.count, "max_severity": self.max_severity, "categories": sorted(self.categories)}


@dataclass(slots=True)
class FrameworkRow:
    label: str
    cells: dict[str, FrameworkCell]
    unmapped: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "unmapped": self.unmapped,
            "cells": {target: cell.to_dict() for target, cell in self.cells.items()},
        }


@dataclass(slots=True)
class FrameworkMatrix:
    framework: str
    title: str
    targets: list[str]
    rows: list[FrameworkRow]

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework,
            "title": self.title,
            "targets": list(self.targets),
            "rows": [row.to_dict() for row in self.rows],
        }


@dataclass(slots=True)
class RunBundle:
    run_id: str
    run_dir: Path | None
    manifest: dict[str, Any]
    summary: dict[str, Any]
    scorecard: dict[str, Any]
    resolved_spec: dict[str, Any]
    invocations: list[dict[str, Any]]
    artifacts: list[dict[str, Any]]
    findings: list[FindingView]
    waivers: list[dict[str, Any]]
    bundle_format_version: str | None
    legacy: bool
    error_log_head: str | None = None
    _unified: list[UnifiedFinding] = field(default_factory=list, repr=False)

    @property
    def name(self) -> str:
        return str(self.manifest.get("name") or self.summary.get("name") or self.run_id)

    @property
    def status(self) -> str:
        return str(self.manifest.get("status") or "unknown")

    @property
    def profile(self) -> str:
        return str(self.manifest.get("run_profile") or self.summary.get("profile") or DEFAULT_RUN_PROFILE)

    @property
    def default_threshold(self) -> str:
        defaults = RUN_PROFILE_DEFAULTS.get(self.profile, RUN_PROFILE_DEFAULTS[DEFAULT_RUN_PROFILE])
        return str(defaults.get("gate_threshold", "high"))

    @property
    def targets(self) -> list[str]:
        listed = self.summary.get("targets") or [t.get("id") for t in self.manifest.get("targets", []) if isinstance(t, dict)]
        seen = list(dict.fromkeys(str(t) for t in listed if t))
        for view in self.findings:
            target = str(view.record.get("target_id", ""))
            if target and target not in seen:
                seen.append(target)
        return seen

    def gate(
        self,
        threshold: str | None = None,
        *,
        ignore_waivers: bool = False,
        eval_min_pass_rate: float | None = None,
    ) -> GateResult:
        return gate_result(
            self._unified,
            threshold=threshold or self.default_threshold,
            waivers=[] if ignore_waivers else self.waivers,
            eval_min_pass_rate=eval_min_pass_rate,
            eval_pass_rate=scorecard_eval_pass_rate(self.scorecard),
        )

    def gates(self) -> dict[str, GateResult]:
        """Verdict at every threshold, for a viewer that cannot re-evaluate."""
        return {level: self.gate(level) for level in SEVERITY_ORDER}

    def facets(self) -> dict[str, list[tuple[str, int]]]:
        counts: dict[str, dict[str, int]] = {}
        for view in self.findings:
            for facet, value in view.facet_values().items():
                bucket = counts.setdefault(facet, {})
                bucket[value] = bucket.get(value, 0) + 1
        out: dict[str, list[tuple[str, int]]] = {}
        for facet, bucket in counts.items():
            if facet == "severity":
                ordered = sorted(bucket.items(), key=lambda kv: -SEVERITY_ORDER.get(kv[0], -1))
            else:
                ordered = sorted(bucket.items())
            out[facet] = ordered
        return out

    def framework_matrices(self) -> list[FrameworkMatrix]:
        targets = self.targets
        matrices: list[FrameworkMatrix] = []
        for framework in FRAMEWORKS:
            rows: dict[str, FrameworkRow] = {}
            unmapped = FrameworkRow(label="unmapped", cells={t: FrameworkCell() for t in targets}, unmapped=True)
            for view in self.findings:
                if view.kind != "attack":
                    continue
                labels = [str(x) for x in (view.record.get("mappings") or {}).get(framework, [])]
                target = str(view.record.get("target_id", ""))
                if not labels:
                    _bump(unmapped.cells.setdefault(target, FrameworkCell()), view)
                    continue
                for label in labels:
                    row = rows.setdefault(label, FrameworkRow(label=label, cells={t: FrameworkCell() for t in targets}))
                    _bump(row.cells.setdefault(target, FrameworkCell()), view)
            ordered = [rows[key] for key in sorted(rows)]
            if any(cell.count for cell in unmapped.cells.values()):
                ordered.append(unmapped)
            matrices.append(
                FrameworkMatrix(framework=framework, title=FRAMEWORK_LABELS[framework], targets=targets, rows=ordered)
            )
        return matrices

    def coverage(self) -> dict[str, Any]:
        """JSON form of the framework matrices with the honesty label attached."""
        matrices = self.framework_matrices()
        # A category is "unmapped" for the run only when no framework maps it; a
        # category that maps in OWASP LLM but not in ATLAS still shows in ATLAS's own
        # unmapped row.
        per_framework: list[set[str]] = []
        for matrix in matrices:
            missing: set[str] = set()
            for row in matrix.rows:
                if row.unmapped:
                    for cell in row.cells.values():
                        missing.update(cell.categories)
            per_framework.append(missing)
        unmapped = set.intersection(*per_framework) if per_framework else set()
        return {
            "run_id": self.run_id,
            "note": MATRIX_NOTE,
            "targets": self.targets,
            "excluded_kinds": sorted(kind for kind in FINDING_KINDS if kind != "attack"),
            "frameworks": [matrix.to_dict() for matrix in matrices],
            "unmapped_categories": sorted(unmapped),
        }

    def find(self, finding_id: str) -> FindingView | None:
        for view in self.findings:
            if view.finding_id == finding_id:
                return view
        return None


def _bump(cell: FrameworkCell, view: FindingView) -> None:
    cell.count += 1
    cell.categories.add(str(view.record.get("category", "")))
    if cell.max_severity is None or SEVERITY_ORDER.get(view.severity, -1) > SEVERITY_ORDER.get(cell.max_severity, -1):
        cell.max_severity = view.severity


def _relative_evidence(run_dir: Path | None, ref: str) -> str | None:
    if run_dir is None:
        return None
    path = Path(ref)
    if not path.is_absolute():
        return None
    try:
        return path.resolve().relative_to(run_dir.resolve()).as_posix()
    except (ValueError, OSError):
        return None


def _capped_json(payload: Any, cap: int) -> tuple[str, bool]:
    text = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True, default=str)
    if len(text) <= cap:
        return text, False
    return text[:cap], True


def _to_unified(record: dict[str, Any]) -> UnifiedFinding:
    return UnifiedFinding(
        finding_id=str(record.get("finding_id", "")),
        run_id=str(record.get("run_id", "")),
        target_id=str(record.get("target_id", "")),
        engine=str(record.get("engine", "")),
        category=str(record.get("category", "")),
        sub_category=record.get("sub_category"),
        severity=str(record.get("severity", "info")),
        confidence=float(record.get("confidence", 0.0) or 0.0),
        attack_vector=str(record.get("attack_vector", "unknown")),
        attack_complexity=str(record.get("attack_complexity", "unknown")),
        success=bool(record.get("success", False)),
        description=str(record.get("description", "")),
        evidence_refs=list(record.get("evidence_refs", []) or []),
        repro_steps=list(record.get("repro_steps", []) or []),
        mappings=dict(record.get("mappings", {}) or {}),
        metadata=dict(record.get("metadata", {}) or {}),
    )


def build_bundle(
    run_id: str,
    *,
    scorecard: dict[str, Any] | None,
    findings: list[dict[str, Any]],
    manifest: dict[str, Any] | None = None,
    summary: dict[str, Any] | None = None,
    resolved_spec: dict[str, Any] | None = None,
    invocations: list[dict[str, Any]] | None = None,
    artifacts: list[dict[str, Any]] | None = None,
    waivers: list[dict[str, Any]] | None = None,
    run_dir: Path | None = None,
    error_log_head: str | None = None,
    metadata_cap: int = REPORT_METADATA_JSON_CAP,
) -> RunBundle:
    """Assemble a `RunBundle` from already-loaded payloads (redaction is the caller's job)."""
    manifest = dict(manifest or {})
    version = manifest.get("bundle_format_version")
    version_text = None if version is None else str(version)
    legacy = _parse_version(version_text) < _parse_version(REDACTED_BUNDLE_MIN_VERSION)
    active_waivers = [w for w in (waivers or []) if waiver_is_active(w)]

    views: list[FindingView] = []
    unified: list[UnifiedFinding] = []
    for record in sort_findings(findings):
        finding = _to_unified(record)
        unified.append(finding)
        transcript, source = extract_transcript(record)
        metadata_json, truncated = _capped_json(record.get("metadata") or {}, metadata_cap)
        chips = [
            (framework, str(label))
            for framework in FRAMEWORKS
            for label in (record.get("mappings") or {}).get(framework, [])
        ]
        views.append(
            FindingView(
                record=record,
                kind=finding_kind(record),
                waiver=matching_waiver(finding, active_waivers),
                evidence=[
                    EvidenceLink(absolute_ref=str(ref), relative_path=_relative_evidence(run_dir, str(ref)))
                    for ref in record.get("evidence_refs", []) or []
                ],
                transcript=transcript,
                transcript_source=source,
                metadata_json=metadata_json,
                metadata_truncated=truncated,
                mapping_chips=chips,
            )
        )

    return RunBundle(
        run_id=run_id,
        run_dir=run_dir,
        manifest=manifest,
        summary=dict(summary or {}),
        scorecard=dict(scorecard or {}),
        resolved_spec=dict(resolved_spec or {}),
        invocations=list(invocations or []),
        artifacts=list(artifacts or []),
        findings=views,
        waivers=active_waivers,
        bundle_format_version=version_text,
        legacy=legacy,
        error_log_head=error_log_head,
        _unified=unified,
    )


def _read_json(run_dir: Path, name: str) -> Any | None:
    path = run_dir / name
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _error_log_head(run_dir: Path) -> str | None:
    path = run_dir / "run_error.log"
    if not path.is_file():
        return None
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    head = "\n".join(lines[:ERROR_LOG_HEAD_LINES])
    if len(lines) > ERROR_LOG_HEAD_LINES:
        head += f"\n… ({len(lines) - ERROR_LOG_HEAD_LINES} more lines in run_error.log)"
    return head


def load_bundle(
    run_dir: str | Path,
    *,
    waivers: list[dict[str, Any]],
    metadata_cap: int = REPORT_METADATA_JSON_CAP,
) -> RunBundle:
    """Read every bundle file under `run_dir`, redacting at read time for pre-1.1 bundles.

    Raises `FileNotFoundError` when the directory does not exist. Missing files
    are tolerated (failed runs have no scorecard) and reported as empty, never
    zero-filled.
    """
    root = Path(run_dir)
    if not root.is_dir():
        raise FileNotFoundError(f"Run directory not found: {root}")

    manifest = _read_json(root, "run_manifest.json") or {}
    version = manifest.get("bundle_format_version")
    legacy = _parse_version(None if version is None else str(version)) < _parse_version(REDACTED_BUNDLE_MIN_VERSION)

    def redacted(name: str, default: Any) -> Any:
        content = _read_json(root, name)
        if content is None:
            return default
        return redact_bundle_payload(content, legacy=legacy)

    findings = redacted("findings.json", [])
    redacted_manifest = redact_bundle_payload(manifest, legacy=legacy)
    if legacy:
        # Free-text error channels: pre-1.1 never scrubbed them and `TimeoutExpired`
        # puts the full argv (secrets included) there. Key heuristics cannot see
        # inside a string, so the whole channel is withheld for legacy bundles.
        if "error" in redacted_manifest:
            redacted_manifest["error"] = LEGACY_ERROR_WITHHELD
    return build_bundle(
        run_id=str(manifest.get("run_id") or root.name),
        scorecard=redacted("scorecard.json", None),
        findings=findings if isinstance(findings, list) else [],
        manifest=redacted_manifest,
        summary=redacted("run_summary.json", {}),
        resolved_spec=redacted("resolved_spec.json", {}),
        invocations=redacted("engine_invocations.json", []),
        artifacts=_read_json(root, "artifacts_index.json") or [],
        waivers=waivers,
        run_dir=root,
        error_log_head=None if legacy else _error_log_head(root),
        metadata_cap=metadata_cap,
    )
