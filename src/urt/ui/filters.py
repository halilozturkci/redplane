"""Finding facet filters shared by the served explorer and any future CLI face."""

from __future__ import annotations

from dataclasses import dataclass, fields
from typing import Any
from urllib.parse import urlencode

from .bundle import FindingView, RunBundle

FACET_KEYS = ("severity", "engine", "category", "sub_category", "target", "success", "waived", "kind")


@dataclass(slots=True)
class FindingFilters:
    severity: str = ""
    engine: str = ""
    category: str = ""
    sub_category: str = ""
    target: str = ""
    success: str = ""
    waived: str = ""
    kind: str = ""
    q: str = ""

    @classmethod
    def from_params(cls, params: Any) -> "FindingFilters":
        return cls(**{f.name: str(params.get(f.name, "") or "").strip() for f in fields(cls)})

    def to_dict(self) -> dict[str, str]:
        return {f.name: getattr(self, f.name) for f in fields(self)}

    def query_string(self) -> str:
        return urlencode({key: value for key, value in self.to_dict().items() if value})


def filter_findings(bundle: RunBundle, filters: FindingFilters) -> list[FindingView]:
    """Exact match on every set facet; `q` is a case-insensitive substring over the
    finding id, description, attack vector, facets and transcript text."""
    query = filters.q.lower()
    out: list[FindingView] = []
    for view in bundle.findings:
        facet = view.facet_values()
        if any(getattr(filters, key) and facet[key] != getattr(filters, key) for key in FACET_KEYS):
            continue
        if query:
            record = view.record
            haystack = " ".join(
                [
                    view.finding_id,
                    str(record.get("description", "")),
                    str(record.get("attack_vector", "")),
                    facet["category"],
                    facet["sub_category"],
                    facet["engine"],
                    facet["target"],
                    " ".join(turn.content for turn in view.transcript),
                ]
            ).lower()
            if query not in haystack:
                continue
        out.append(view)
    return out
