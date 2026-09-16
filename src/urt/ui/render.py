"""Jinja2 rendering for the viewer: one template set, two modes.

- ``static``: a self-contained ``report.html`` — CSS and JS inlined, data embedded as
  inert JSON, hash-based CSP (no ``'unsafe-inline'``), evidence links relative to the
  run directory so the page works unzipped or under ``urt view``.
- ``served``: pages/fragments for ``/ui`` on ``urt serve-api`` — assets linked from
  ``/ui/static``, evidence links through the artifact API, HTMX swaps fragments.

Autoescape is on for every template; the only ``Markup`` values are our own CSS/JS
assets and the JSON data block, which is escaped for ``<script>`` embedding.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable
from importlib import resources
from typing import Any, Literal

from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape
from markupsafe import Markup

from ..constants import LEGACY_RAW_DOWNLOAD_ALLOWLIST, REDACTED_BUNDLE_MIN_VERSION, SEVERITY_ORDER
from .bundle import RunBundle
from .filters import FindingFilters

Mode = Literal["static", "served"]
HrefFor = Callable[[str], str | None]

SEVERITY_LEVELS = tuple(sorted(SEVERITY_ORDER, key=lambda level: -SEVERITY_ORDER[level]))
# Files the page cannot describe accurately: it cannot know its own final hash, and
# the index is written after the page.
SELF_REFERENTIAL_FILES = ("report.html", "artifacts_index.json")


def _pct(value: Any) -> str:
    if value is None:
        return "—"
    try:
        return f"{float(value):.1%}"
    except (TypeError, ValueError):
        return "—"


def _num(value: Any, digits: int = 4) -> str:
    if value is None:
        return "—"
    try:
        return f"{float(value):.{digits}f}"
    except (TypeError, ValueError):
        return str(value)


def _seconds(value: Any) -> str:
    if value is None:
        return "—"
    try:
        return f"{float(value):.1f} s"
    except (TypeError, ValueError):
        return str(value)


def json_script(payload: Any) -> Markup:
    """JSON safe to place inside ``<script type="application/json">``.

    ``<``, ``>`` and ``&`` are emitted as ``\\uXXXX`` escapes so the payload can never
    terminate the element or start a tag, whatever the findings contain.
    """
    text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True, default=str)
    text = text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return Markup(text)


def _environment() -> Environment:
    env = Environment(
        loader=PackageLoader("urt.ui", "templates"),
        autoescape=select_autoescape(default=True, default_for_string=True),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["pct"] = _pct
    env.filters["num"] = _num
    env.filters["seconds"] = _seconds
    env.filters["json_script"] = json_script
    env.filters["pretty_json"] = lambda value: json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True, default=str)
    env.globals["severity_levels"] = SEVERITY_LEVELS
    return env


_ENV = _environment()


def _asset(name: str) -> str:
    return (resources.files("urt.ui") / "static" / name).read_text(encoding="utf-8")


def csp_hash(text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return f"'sha256-{base64.b64encode(digest).decode('ascii')}'"


def static_csp(*, script: str, style: str) -> str:
    return (
        "default-src 'none'; "
        f"script-src {csp_hash(script)}; "
        f"style-src {csp_hash(style)}; "
        "base-uri 'none'; form-action 'none'"
    )


SERVED_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)


def relative_href(bundle: RunBundle) -> HrefFor:
    """Static mode: links are relative to the run directory the page sits in."""

    def href(relative_path: str) -> str | None:
        return relative_path

    return href


def api_href(bundle: RunBundle, *, prefix: str = "/v1/runs") -> HrefFor:
    """Served mode: files come through the artifact API, which refuses non-allowlisted
    files of pre-1.1 bundles — so those are not linked at all."""

    def href(relative_path: str) -> str | None:
        if bundle.legacy and relative_path not in LEGACY_RAW_DOWNLOAD_ALLOWLIST:
            return None
        return f"{prefix}/{bundle.run_id}/artifacts/{relative_path}"

    return href


def _embedded_data(bundle: RunBundle) -> dict[str, Any]:
    return {
        "run_id": bundle.run_id,
        "bundle_format_version": bundle.bundle_format_version,
        "default_threshold": bundle.default_threshold,
        "findings": [
            {"id": view.finding_id, **view.facet_values()} for view in bundle.findings
        ],
    }


def _tiles(bundle: RunBundle) -> list[dict[str, str]]:
    scorecard = bundle.scorecard
    if not scorecard:
        return []
    tiles = [{"label": "Findings", "value": str(scorecard.get("total_findings", 0)), "css": "total"}]
    for level in SEVERITY_LEVELS:
        tiles.append({"label": level.capitalize(), "value": str(scorecard.get(level, 0)), "css": f"sev-{level}"})
    tiles.append({"label": "ASR overall", "value": _pct(scorecard.get("asr_overall")), "css": "asr"})
    tiles.append(
        {
            "label": "Attacks (success / total)",
            "value": f"{scorecard.get('success_count', 0)} / {scorecard.get('total_attacks', 0)}",
            "css": "attacks",
        }
    )
    if scorecard.get("eval_scores"):
        tiles.append({"label": "Eval pass rate", "value": _pct(scorecard.get("eval_pass_rate")), "css": "eval"})
    return tiles


def page_context(bundle: RunBundle, *, mode: Mode, href_for: HrefFor) -> dict[str, Any]:
    """Everything the run templates need, precomputed so templates stay declarative."""
    scorecard = bundle.scorecard
    files = [row for row in bundle.artifacts if row.get("path") not in SELF_REFERENTIAL_FILES]
    return {
        "mode": mode,
        "bundle": bundle,
        "run_id": bundle.run_id,
        "name": bundle.name,
        "status": bundle.status,
        "profile": bundle.profile,
        "legacy": bundle.legacy,
        "version": bundle.bundle_format_version or "unknown",
        "redacted_min_version": REDACTED_BUNDLE_MIN_VERSION,
        "manifest": bundle.manifest,
        "summary": bundle.summary,
        "scorecard": scorecard,
        "tiles": _tiles(bundle),
        "asr_by_category": sorted((scorecard.get("asr_by_category") or {}).items(), key=lambda kv: (-kv[1], kv[0])),
        "by_engine": sorted((scorecard.get("by_engine") or {}).items()),
        "eval_rows": sorted((scorecard.get("eval_scores") or {}).items()),
        "eval_pass_rate": scorecard.get("eval_pass_rate"),
        "gates": bundle.gates(),
        "default_threshold": bundle.default_threshold,
        "findings": bundle.findings,
        "facets": bundle.facets(),
        "matrices": bundle.framework_matrices(),
        "invocations": bundle.invocations,
        "probes": bundle.manifest.get("target_probe_results", []),
        "evaluator_summaries": bundle.summary.get("evaluator_summaries", []),
        "budget": bundle.manifest.get("budget") or {},
        "files": files,
        "self_referential_files": SELF_REFERENTIAL_FILES,
        "resolved_spec": bundle.resolved_spec,
        "error_log_head": bundle.error_log_head,
        "href_for": href_for,
        "waivers": bundle.waivers,
    }


def served_context(
    bundle: RunBundle,
    *,
    threshold: str | None = None,
    ignore_waivers: bool = False,
    filters: FindingFilters | None = None,
    href_for: HrefFor | None = None,
) -> dict[str, Any]:
    """Page context for ``/ui`` pages and fragments: one gate verdict at the requested
    threshold, current facet filters, and download links that respect the legacy rule."""
    context = page_context(bundle, mode="served", href_for=href_for or api_href(bundle))
    effective = threshold or bundle.default_threshold
    context.update(
        {
            "gate": bundle.gate(effective, ignore_waivers=ignore_waivers),
            "gate_threshold": effective,
            "ignore_waivers": ignore_waivers,
            "filters": (filters or FindingFilters()).to_dict(),
            "zip_href": None if bundle.legacy else f"/v1/runs/{bundle.run_id}/artifacts.zip",
            "report_href": context["href_for"]("report.html"),
            "api_href": f"/v1/runs/{bundle.run_id}",
        }
    )
    return context


def render_run_page(bundle: RunBundle, *, mode: Mode = "static", href_for: HrefFor | None = None) -> str:
    """Render the single-run viewer. ``static`` is what lands in ``report.html``;
    ``served`` is the ``/ui/runs/{id}`` page at the profile's default threshold."""
    if mode == "static":
        css_text = _asset("app.css")
        js_text = _asset("report.js")
        context = page_context(bundle, mode="static", href_for=href_for or relative_href(bundle))
        context.update(
            {
                "css_text": Markup(css_text),
                "js_text": Markup(js_text),
                "csp": Markup(static_csp(script=js_text, style=css_text)),
                "embedded_data": _embedded_data(bundle),
            }
        )
        return _ENV.get_template("run_page.html").render(**context)
    return _ENV.get_template("run_detail.html").render(**served_context(bundle, href_for=href_for))


def render_template(template_name: str, /, **context: Any) -> str:
    """Render any template in the set (served pages and HTMX fragments)."""
    return _ENV.get_template(template_name).render(**context)
