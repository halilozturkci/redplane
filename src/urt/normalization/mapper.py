"""Normalize findings and attach policy mappings."""

from __future__ import annotations

from collections import OrderedDict

from ..policy.mapping import canonical_category, enabled_mapping_keys, map_category, merge_mappings
from ..types import UnifiedFinding
from .kind import derive_finding_kind


def normalize_findings(
    findings: list[UnifiedFinding],
    *,
    policy_profiles: list[str],
) -> list[UnifiedFinding]:
    """Canonicalize categories (aliases), attach framework mappings and tag `finding_kind`.

    When an alias rewrites the category the engine's spelling is kept in
    `metadata.category_reported` so nothing is lost from the audit trail.
    """
    profile_keys = enabled_mapping_keys(policy_profiles)

    deduped: "OrderedDict[str, UnifiedFinding]" = OrderedDict()
    for finding in findings:
        canonical = canonical_category(finding.category)
        if canonical != finding.category:
            finding.metadata.setdefault("category_reported", finding.category)
            finding.category = canonical
        mapped = map_category(finding.category)
        filtered = {k: v for k, v in mapped.items() if k in profile_keys}
        if filtered:
            finding.mappings = merge_mappings(finding.mappings, filtered)
        finding.metadata["finding_kind"] = derive_finding_kind(finding)
        deduped[finding.finding_id] = finding
    return list(deduped.values())
