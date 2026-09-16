"""`/ui`: read-only server-rendered pages on the control-plane API (Option A).

Same partials as the static viewer, rendered in ``served`` mode: assets from
``/ui/static`` (vendored, no CDN), evidence through ``/v1/runs/{id}/artifacts/…``,
HTMX swapping fragments for facets, the finding drawer and the gate panel. Every
page also works without JavaScript (plain GET forms, ``?finding_id=`` drawer).
"""

from __future__ import annotations

from importlib import resources

from fastapi import APIRouter, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, Response

from ..constants import SEVERITY_ORDER
from ..orchestrator import Orchestrator
from ..report import parse_eval_min_pass_rate
from .bundle import RunBundle, load_bundle
from .filters import FindingFilters, filter_findings
from .render import SERVED_CSP, render_template, served_context

STATIC_ASSETS = {
    "app.css": "text/css; charset=utf-8",
    "htmx.min.js": "text/javascript; charset=utf-8",
}
PAGE_HEADERS = {
    "Content-Security-Policy": SERVED_CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def _check_threshold(threshold: str | None) -> str | None:
    if threshold is None or threshold == "":
        return None
    if threshold.lower() not in SEVERITY_ORDER:
        raise HTTPException(
            status_code=400, detail=f"Unsupported threshold '{threshold}'. Supported: {list(SEVERITY_ORDER)}"
        )
    return threshold.lower()


def _check_eval_min(raw: str | None) -> float | None:
    try:
        return parse_eval_min_pass_rate(raw)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def mount_ui(app: FastAPI, orch: Orchestrator) -> None:
    router = APIRouter(prefix="/ui")

    def html(text: str, status_code: int = 200) -> HTMLResponse:
        return HTMLResponse(text, status_code=status_code, headers=PAGE_HEADERS)

    def bundle_for(run_id: str) -> RunBundle:
        if not orch.get_run(run_id):
            raise HTTPException(status_code=404, detail="Run not found")
        try:
            run_dir = orch.artifact_store.existing_run_dir(run_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail="Run not found") from exc
        if run_dir is None:
            raise HTTPException(status_code=404, detail="Run directory not found")
        return load_bundle(run_dir, waivers=orch.list_waivers())

    @router.get("", response_class=HTMLResponse)
    @router.get("/", response_class=HTMLResponse)
    def runs_list(
        target: str = Query(default=""),
        name_prefix: str = Query(default=""),
        gate_threshold: str = Query(default=""),
    ) -> HTMLResponse:
        threshold = _check_threshold(gate_threshold)
        rows = orch.list_runs(gate_threshold=threshold)
        targets = sorted({str(t) for row in rows for t in (row.get("targets") or [])})
        if target:
            rows = [row for row in rows if target in (row.get("targets") or [])]
        if name_prefix:
            rows = [row for row in rows if str(row.get("name", "")).startswith(name_prefix)]
        return html(
            render_template(
                "runs_list.html",
                mode="served",
                rows=rows,
                targets=targets,
                filters={"target": target, "name_prefix": name_prefix, "gate_threshold": threshold or ""},
            )
        )

    @router.get("/runs/{run_id}", response_class=HTMLResponse)
    def run_detail(
        run_id: str,
        threshold: str = Query(default=""),
        ignore_waivers: bool = Query(default=False),
        eval_min_pass_rate: str = Query(default=""),
    ) -> HTMLResponse:
        bundle = bundle_for(run_id)
        context = served_context(
            bundle,
            threshold=_check_threshold(threshold),
            ignore_waivers=ignore_waivers,
            eval_min_pass_rate=_check_eval_min(eval_min_pass_rate),
        )
        return html(render_template("run_detail.html", **context))

    @router.get("/runs/{run_id}/gate", response_class=HTMLResponse)
    def gate_fragment(
        run_id: str,
        threshold: str = Query(default=""),
        ignore_waivers: bool = Query(default=False),
        eval_min_pass_rate: str = Query(default=""),
    ) -> HTMLResponse:
        bundle = bundle_for(run_id)
        context = served_context(
            bundle,
            threshold=_check_threshold(threshold),
            ignore_waivers=ignore_waivers,
            eval_min_pass_rate=_check_eval_min(eval_min_pass_rate),
        )
        return html(render_template("partials/_gate_verdict.html", result=context["gate"], **context))

    @router.get("/runs/{run_id}/findings", response_class=HTMLResponse)
    def findings_page(run_id: str, request: Request, finding_id: str = Query(default="")) -> HTMLResponse:
        bundle = bundle_for(run_id)
        filters = FindingFilters.from_params(request.query_params)
        context = served_context(bundle, filters=filters)
        selected = bundle.find(finding_id) if finding_id else None
        if finding_id and selected is None:
            raise HTTPException(status_code=404, detail="Finding not found")
        context.update({"filtered": filter_findings(bundle, filters), "selected": selected, "filters_qs": filters.query_string()})
        return html(render_template("findings_page.html", **context))

    @router.get("/runs/{run_id}/findings/table", response_class=HTMLResponse)
    def findings_table(run_id: str, request: Request) -> HTMLResponse:
        bundle = bundle_for(run_id)
        filters = FindingFilters.from_params(request.query_params)
        context = served_context(bundle, filters=filters)
        context.update({"filtered": filter_findings(bundle, filters), "filters_qs": filters.query_string()})
        return html(render_template("partials/_findings_table.html", **context))

    @router.get("/runs/{run_id}/findings/detail", response_class=HTMLResponse)
    def finding_detail(run_id: str, finding_id: str = Query(...)) -> HTMLResponse:
        bundle = bundle_for(run_id)
        view = bundle.find(finding_id)
        if view is None:
            raise HTTPException(status_code=404, detail="Finding not found")
        context = served_context(bundle)
        return html(render_template("partials/_finding_drawer.html", view=view, **context))

    @router.get("/static/{name}")
    def static_asset(name: str) -> Response:
        media_type = STATIC_ASSETS.get(name)
        if media_type is None:
            raise HTTPException(status_code=404, detail="Not found")
        payload = (resources.files("urt.ui") / "static" / name).read_bytes()
        return Response(
            content=payload,
            media_type=media_type,
            headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "public, max-age=3600"},
        )

    app.include_router(router)
