"""`/ui`: read-only server-rendered pages on the control-plane API (Option A).

Same partials as the static viewer, rendered in ``served`` mode: assets from
``/ui/static`` (vendored, no CDN), evidence through ``/v1/runs/{id}/artifacts/…``,
HTMX swapping fragments for facets, the finding drawer and the gate panel. Every
page also works without JavaScript (plain GET forms, ``?finding_id=`` drawer).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from importlib import resources
from typing import Any
from urllib.parse import quote, urlencode

from fastapi import APIRouter, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from ..constants import SEVERITY_ORDER, WAIVER_DEFAULT_EXPIRY_DAYS
from ..orchestrator import Orchestrator
from ..policy.waivers import waiver_is_active
from ..report import parse_eval_min_pass_rate
from .bundle import FindingView, RunBundle, load_bundle
from .csrf import CSRF_COOKIE, CSRF_FIELD, csrf_token_for, set_csrf_cookie, verify_csrf
from .filters import FindingFilters, filter_findings
from .forms import read_form
from .render import SERVED_CSP, render_template, served_context, sparkline

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

    # --- diff and trend (§4.5) ---

    @router.get("/diff", response_class=HTMLResponse)
    def diff_page(a: str = Query(default=""), b: str = Query(default="")) -> HTMLResponse:
        diff = None
        if a and b:
            for run_id in (a, b):
                if not orch.get_run(run_id):
                    raise HTTPException(status_code=404, detail=f"Run not found: {run_id}")
            diff = orch.diff(a, b)
        runs = orch.metadata_store.list_runs()
        return html(render_template("diff.html", mode="served", runs=runs, a=a, b=b, diff=diff))

    @router.get("/targets/{target_id}/trend", response_class=HTMLResponse)
    def trend_page(target_id: str) -> HTMLResponse:
        points = orch.trend(target_id)
        if not points:
            raise HTTPException(status_code=404, detail="No runs with findings for this target")
        return html(
            render_template(
                "trend.html",
                mode="served",
                target_id=target_id,
                points=points,
                asr_spark=sparkline([p.asr_overall for p in points], ymax=1.0),
                ch_spark=sparkline([p.critical_high for p in points]),
                eval_spark=sparkline([p.eval_pass_rate_run for p in points], ymax=1.0),
            )
        )

    # --- waivers (the only mutation the UI offers; append-only, CSRF-protected) ---

    def page(template: str, request: Request, status_code: int = 200, **context: Any) -> HTMLResponse:
        token = csrf_token_for(request)
        response = html(
            render_template(template, mode="served", csrf_token=token, csrf_field=CSRF_FIELD, **context),
            status_code=status_code,
        )
        if request.cookies.get(CSRF_COOKIE) != token:
            set_csrf_cookie(response, token)
        return response

    def default_expiry() -> str:
        return (datetime.now(timezone.utc) + timedelta(days=WAIVER_DEFAULT_EXPIRY_DAYS)).replace(microsecond=0).isoformat()

    def run_choices() -> list[dict[str, str]]:
        return [{"run_id": row["run_id"], "name": str(row.get("name", ""))} for row in orch.metadata_store.list_runs()]

    def control_choices_for(view: FindingView) -> list[tuple[str, str]]:
        record = view.record
        choices: list[tuple[str, str]] = [("category", str(record.get("category", "")))]
        if record.get("sub_category"):
            choices.append(("sub_category", str(record["sub_category"])))
        for framework, label in view.mapping_chips:
            choices.append((framework, label))
        choices.append(("finding_id", view.finding_id))
        return [(label, value) for label, value in choices if value]

    def preview_for(run_id: str, *, control_id: str, target_id: str) -> dict[str, Any] | None:
        if not orch.get_run(run_id):
            raise HTTPException(status_code=404, detail="Run not found")
        matches = orch.waiver_preview(run_id, control_id=control_id, target_id=target_id or "*")
        if matches is None:
            return None
        return {"run_id": run_id, "control_id": control_id, "target_id": target_id or "*", "count": len(matches), "matches": matches}

    @router.get("/waivers", response_class=HTMLResponse)
    def waivers_list(request: Request, run_id: str = Query(default=""), show: str = Query(default="all")) -> HTMLResponse:
        if show not in {"all", "active", "expired"}:
            raise HTTPException(status_code=400, detail="show must be all, active or expired")
        rows = [{**row, "active": waiver_is_active(row)} for row in orch.list_waivers()]
        if show == "active":
            rows = [row for row in rows if row["active"]]
        elif show == "expired":
            rows = [row for row in rows if not row["active"]]
        previews: dict[str, int | None] = {}
        if run_id:
            if not orch.get_run(run_id):
                raise HTTPException(status_code=404, detail="Run not found")
            for row in rows:
                matches = orch.waiver_preview(run_id, control_id=str(row["control_id"]), target_id=str(row["target_id"]))
                previews[str(row["waiver_id"])] = None if matches is None else len(matches)
        return page(
            "waivers_list.html", request, waivers=rows, run_id=run_id, show=show, previews=previews, runs=run_choices()
        )

    @router.get("/waivers/new", response_class=HTMLResponse)
    def waiver_new(
        request: Request,
        run_id: str = Query(default=""),
        finding_id: str = Query(default=""),
        target_id: str = Query(default=""),
        control_id: str = Query(default=""),
    ) -> Response:
        if CSRF_FIELD in request.query_params:
            # The no-JS "Preview" button submits the whole form with GET; keep the token out of URLs.
            clean = [(k, v) for k, v in request.query_params.multi_items() if k != CSRF_FIELD]
            return RedirectResponse(f"/ui/waivers/new?{urlencode(clean)}", status_code=303, headers=PAGE_HEADERS)
        finding: FindingView | None = None
        choices: list[tuple[str, str]] = []
        if finding_id:
            if not run_id:
                raise HTTPException(status_code=400, detail="finding_id requires run_id")
            finding = bundle_for(run_id).find(finding_id)
            if finding is None:
                raise HTTPException(status_code=404, detail="Finding not found")
            choices = control_choices_for(finding)
            target_id = target_id or str(finding.record.get("target_id", ""))
        values = {"target_id": target_id, "control_id": control_id, "reason": "", "owner": "", "expires_at": default_expiry()}
        preview = preview_for(run_id, control_id=control_id, target_id=target_id) if run_id and control_id else None
        return page(
            "waiver_new.html",
            request,
            run_id=run_id,
            finding=finding,
            control_choices=choices,
            values=values,
            preview=preview,
            error=None,
        )

    @router.get("/runs/{run_id}/waiver-preview", response_class=HTMLResponse)
    def waiver_preview_fragment(
        run_id: str, control_id: str = Query(default=""), target_id: str = Query(default="*")
    ) -> HTMLResponse:
        if not control_id.strip():
            return html('<div id="waiver-preview" class="preview"><p class="muted">Choose a control id to preview.</p></div>')
        preview = preview_for(run_id, control_id=control_id, target_id=target_id)
        if preview is None:
            raise HTTPException(status_code=404, detail="Findings not available for run")
        return html(render_template("partials/_waiver_preview.html", mode="served", preview=preview))

    @router.post("/waivers", response_class=HTMLResponse)
    async def waiver_create(request: Request) -> Response:
        form = await read_form(request)
        verify_csrf(request, form.get(CSRF_FIELD))
        run_id = form.get("run_id", "").strip()
        values = {key: form.get(key, "").strip() for key in ("target_id", "control_id", "reason", "owner", "expires_at")}
        missing = [key for key, value in values.items() if not value]
        error: str | None = None
        if missing:
            error = f"Required: {', '.join(missing)}"
        else:
            try:
                orch.create_waiver({"waiver_id": str(uuid.uuid4()), **values})
            except ValueError as exc:
                error = str(exc)
        if error:
            return page(
                "waiver_new.html",
                request,
                status_code=400,
                run_id=run_id,
                finding=None,
                control_choices=[],
                values=values,
                preview=None,
                error=error,
            )
        target = f"/ui/waivers?run_id={quote(run_id, safe='')}" if run_id else "/ui/waivers"
        return RedirectResponse(target, status_code=303, headers=PAGE_HEADERS)

    @router.post("/waivers/{waiver_id}/revoke")
    async def waiver_revoke(request: Request, waiver_id: str) -> Response:
        form = await read_form(request)
        verify_csrf(request, form.get(CSRF_FIELD))
        if orch.revoke_waiver(waiver_id, note=form.get("note") or None) is None:
            raise HTTPException(status_code=404, detail="Waiver not found")
        run_id = form.get("run_id", "").strip()
        target = f"/ui/waivers?run_id={quote(run_id, safe='')}" if run_id else "/ui/waivers"
        return RedirectResponse(target, status_code=303, headers=PAGE_HEADERS)

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
