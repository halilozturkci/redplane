"""Normalize findings and attach policy mappings."""

from __future__ import annotations

from collections import OrderedDict

from ..policy.mapping import enabled_mapping_keys, map_category, merge_mappings
from ..types import UnifiedFinding


def normalize_findings(
    findings: list[UnifiedFinding],
    *,
    policy_profiles: list[str],
) -> list[UnifiedFinding]:
    profile_keys = enabled_mapping_keys(policy_profiles)

    deduped: "OrderedDict[str, UnifiedFinding]" = OrderedDict()
    for finding in findings:
        mapped = map_category(finding.category)
        filtered = {k: v for k, v in mapped.items() if k in profile_keys}
        if filtered:
            finding.mappings = merge_mappings(finding.mappings, filtered)
        deduped[finding.finding_id] = finding
    return list(deduped.values())
