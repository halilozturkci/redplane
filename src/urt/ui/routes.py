"""`/ui`: read-only server-rendered pages on the control-plane API (Option A).

Same partials as the static viewer, rendered in ``served`` mode: assets from
``/ui/static`` (vendored, no CDN), evidence through ``/v1/runs/{id}/artifacts/…``,
HTMX swapping fragments for facets, the finding drawer and the gate panel. Every
page also works without JavaScript (plain GET forms, ``?finding_id=`` drawer).
"""

from __future__ import annotations

import hmac
import os
import uuid
from datetime import datetime, timedelta, timezone
from importlib import resources
from typing import Any
from urllib.parse import quote, urlencode

from fastapi import APIRouter, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from ..auth import SESSION_COOKIE, clear_session_cookie, failed_auth_delay, key_matches, safe_next, set_session_cookie
from ..constants import SEVERITY_ORDER, WAIVER_DEFAULT_EXPIRY_DAYS
from ..diff import comparable, comparable_runs
from ..orchestrator import Orchestrator
from ..policy.waivers import waiver_is_active
from ..report import parse_eval_min_pass_rate
from ..specs import (
    SpecInputError,
    SpecValidation,
    capabilities,
    form_to_payload,
    list_templates,
    load_template,
    parse_spec_text,
    payload_to_form,
    probe_spec,
    spec_to_yaml,
    templates_dir,
    validate_spec_payload,
)
from ..types import ValidationError
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

    def configured_key() -> str | None:
        return getattr(app.state, "api_key", None)

    def page(template: str, request: Request, status_code: int = 200, **context: Any) -> HTMLResponse:
        """Full page: CSRF token issued/embedded, session state for the nav."""
        nonce, token = csrf_token_for(request)
        context.setdefault("mode", "served")
        context.setdefault("session_active", bool(configured_key()) and SESSION_COOKIE in request.cookies)
        response = html(
            render_template(template, csrf_token=token, csrf_field=CSRF_FIELD, **context),
            status_code=status_code,
        )
        if request.cookies.get(CSRF_COOKIE) != nonce:
            set_csrf_cookie(response, nonce)
        return response

    @router.get("", response_class=HTMLResponse)
    @router.get("/", response_class=HTMLResponse)
    def runs_list(
        request: Request,
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
        return page(
            "runs_list.html",
            request,
            rows=rows,
            targets=targets,
            filters={"target": target, "name_prefix": name_prefix, "gate_threshold": threshold or ""},
        )

    @router.get("/runs/{run_id}", response_class=HTMLResponse)
    def run_detail(
        request: Request,
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
        return page("run_detail.html", request, **context)

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
        return page("findings_page.html", request, **context)

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

    # --- login (G13): cookie session for the pages when URT_API_KEY is set ---

    @router.get("/login", response_class=HTMLResponse)
    def login_form(request: Request, next: str = Query(default="/ui")) -> HTMLResponse:
        return page(
            "login.html", request, key_configured=bool(configured_key()), next=safe_next(next), error=None
        )

    @router.post("/login", response_class=HTMLResponse)
    async def login_submit(request: Request) -> Response:
        fields = await read_form(request)
        verify_csrf(request, fields.get(CSRF_FIELD))
        key = configured_key()
        target = safe_next(fields.get("next"))
        if not key:
            return RedirectResponse(target, status_code=303, headers=PAGE_HEADERS)
        if not key_matches(fields.get("api_key"), key):
            await failed_auth_delay()
            return page(
                "login.html", request, status_code=401, key_configured=True, next=target, error="Wrong API key."
            )
        response = RedirectResponse(target, status_code=303, headers=PAGE_HEADERS)
        set_session_cookie(response, key)
        return response

    @router.post("/logout")
    async def logout(request: Request) -> Response:
        fields = await read_form(request)
        verify_csrf(request, fields.get(CSRF_FIELD))
        response = RedirectResponse("/ui/login", status_code=303, headers=PAGE_HEADERS)
        clear_session_cookie(response, request=request)
        return response

    # --- diff and trend (§4.5) ---

    @router.get("/diff", response_class=HTMLResponse)
    def diff_page(request: Request, a: str = Query(default=""), b: str = Query(default="")) -> HTMLResponse:
        diff = None
        for run_id in (a, b):
            if run_id and not orch.get_run(run_id):
                raise HTTPException(status_code=404, detail=f"Run not found: {run_id}")
        if a and b:
            diff = orch.diff(a, b)
        runs = orch.list_runs()
        by_id = {row["run_id"]: row for row in runs}
        anchor = by_id.get(a) if a else None
        candidates = comparable_runs(runs, anchor) if anchor else []
        unrelated = bool(anchor and b and b in by_id and not comparable(anchor, by_id[b]))
        return page(
            "diff.html", request, runs=runs, candidates=candidates, a=a, b=b, diff=diff, unrelated=unrelated
        )

    @router.get("/targets/{target_id}/trend", response_class=HTMLResponse)
    def trend_page(request: Request, target_id: str) -> HTMLResponse:
        points = orch.trend(target_id)
        if not points:
            raise HTTPException(status_code=404, detail="No runs with findings for this target")
        return page(
                "trend.html",
                request,
                target_id=target_id,
                points=points,
                asr_spark=sparkline([p.asr_overall for p in points], ymax=1.0),
                ch_spark=sparkline([p.critical_high for p in points]),
                eval_spark=sparkline([p.eval_pass_rate_run for p in points], ymax=1.0),
        )

    # --- spec builder (§4.7): validate-only + probe; no Run button ---

    def specs_page(
        request: Request,
        *,
        form: dict[str, str],
        yaml_text: str,
        template_name: str = "",
        validation: dict[str, Any] | None = None,
        probe: list[dict[str, Any]] | None = None,
        error: str | None = None,
        status_code: int = 200,
    ) -> HTMLResponse:
        var = form.get("target_auth_var", "").strip()
        return page(
            "specs.html",
            request,
            status_code=status_code,
            caps=capabilities(),
            templates=list_templates(),
            templates_dir=str(templates_dir()),
            template_name=template_name,
            form=form,
            yaml_text=yaml_text,
            auth_var_set=(var in os.environ) if var else None,
            validation=validation,
            probe=probe,
            error=error,
        )

    def _payload_from_yaml(text: str) -> tuple[dict[str, Any] | None, str | None]:
        try:
            return parse_spec_text(text), None
        except SpecInputError as exc:
            raise HTTPException(status_code=413, detail=str(exc)) from exc
        except ValidationError as exc:
            return None, str(exc)

    @router.get("/specs", response_class=HTMLResponse)
    def specs_get(request: Request, template: str = Query(default="")) -> HTMLResponse:
        form = payload_to_form({})
        yaml_text = ""
        if template:
            row = load_template(template)
            if row is None:
                raise HTTPException(status_code=404, detail="Template not found")
            yaml_text = row["yaml"]
            payload, _ = _payload_from_yaml(yaml_text)
            form = payload_to_form(payload or {})
        return specs_page(request, form=form, yaml_text=yaml_text, template_name=template)

    @router.post("/specs/build", response_class=HTMLResponse)
    async def specs_build(request: Request) -> HTMLResponse:
        fields = await read_form(request)
        verify_csrf(request, fields.get(CSRF_FIELD))
        payload = form_to_payload(fields)
        return specs_page(request, form=payload_to_form(payload), yaml_text=spec_to_yaml(payload))

    @router.post("/specs/load", response_class=HTMLResponse)
    async def specs_load(request: Request) -> HTMLResponse:
        fields = await read_form(request)
        verify_csrf(request, fields.get(CSRF_FIELD))
        yaml_text = fields.get("yaml", "")
        payload, error = _payload_from_yaml(yaml_text)
        form = payload_to_form(payload or {})
        return specs_page(request, form=form, yaml_text=yaml_text, error=error, status_code=400 if error else 200)

    @router.post("/specs/validate", response_class=HTMLResponse)
    async def specs_validate(request: Request) -> HTMLResponse:
        fields = await read_form(request)
        verify_csrf(request, fields.get(CSRF_FIELD))
        yaml_text = fields.get("yaml", "")
        payload, error = _payload_from_yaml(yaml_text)
        if payload is None:
            validation = SpecValidation(ok=False, errors=[error or "unparseable"]).to_dict()
            form = payload_to_form({})
        else:
            validation = validate_spec_payload(payload).to_dict()
            form = payload_to_form(payload)
        return specs_page(request, form=form, yaml_text=yaml_text, validation=validation)

    @router.post("/specs/probe", response_class=HTMLResponse)
    async def specs_probe(request: Request) -> HTMLResponse:
        fields = await read_form(request)
        verify_csrf(request, fields.get(CSRF_FIELD))
        yaml_text = fields.get("yaml", "")
        payload, error = _payload_from_yaml(yaml_text)
        if payload is None:
            validation = SpecValidation(ok=False, errors=[error or "unparseable"])
            form = payload_to_form({})
        else:
            validation = validate_spec_payload(payload)
            form = payload_to_form(payload)
        probe = probe_spec(validation.spec) if validation.ok and validation.spec is not None else None
        return specs_page(request, form=form, yaml_text=yaml_text, validation=validation.to_dict(), probe=probe)

    # --- waivers (the only mutation the UI offers; append-only, CSRF-protected) ---

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
