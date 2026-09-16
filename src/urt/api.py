"""FastAPI control-plane for Redplane.

`POST /v1/runs` is asynchronous (#18): the spec is validated, recorded as `queued`
and handed to the process's single `RunWorker` thread; the response is `202` with
the `run_id` and `GET /v1/runs/{id}` reports `queued → running → completed|failed`
plus the orchestrator's stage events. `?wait=true` keeps the old synchronous
contract (the request blocks until the run returns) for tests and scripts.
"""

from __future__ import annotations

import os
import re
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.responses import FileResponse, JSONResponse

from .artifact_policy import artifact_response_policy
from .auth import api_key_from_env, install_auth
from .constants import (
    ARTIFACT_RESPONSE_HEADERS,
    DEFAULT_ARTIFACT_ROOT,
    DEFAULT_METADATA_DB,
    LEGACY_RAW_DOWNLOAD_ALLOWLIST,
    REDACTED_BUNDLE_MIN_VERSION,
    SEVERITY_ORDER,
    STAGE_EVENTS_FILE,
)
from .gateway.traces import TracePathError
from .gateway_client import GatewayUnavailable, fetch_sessions
from .jobs import RunWorker
from .orchestrator import Orchestrator
from .policy.waivers import waiver_is_active
from .report import parse_eval_min_pass_rate
from .specs import (
    SpecInputError,
    SpecValidation,
    capabilities,
    list_templates,
    load_template,
    payload_from_request,
    probe_spec,
    validate_spec_payload,
)
from .storage.artifact_store import ArtifactPathError
from .storage.metadata_store import WaiverExistsError, WaiverRevokedError
from .types import RunSpec, ValidationError
from .ui.routes import mount_ui

# Bundle files exposed as JSON content (G1). Never accept a path from the client here.
BUNDLE_JSON_ENDPOINTS = {
    "scorecard": "scorecard.json",
    "summary": "run_summary.json",
    "manifest": "run_manifest.json",
    "invocations": "engine_invocations.json",
    "stages": STAGE_EVENTS_FILE,
}

_ARTIFACT_HEADERS = ARTIFACT_RESPONSE_HEADERS


def _artifact_response(path: Path, relative_path: str) -> FileResponse:
    # The API never renders the viewer inline: same-origin as the JSON API.
    policy = artifact_response_policy(relative_path)
    if policy.inline:
        return FileResponse(path, media_type=policy.media_type, headers=policy.headers)
    return FileResponse(
        path,
        media_type=policy.media_type,
        headers=policy.headers,
        filename=policy.filename,
        content_disposition_type="attachment",
    )


def _build_orchestrator() -> Orchestrator:
    artifact_root = os.getenv("URT_ARTIFACT_ROOT", DEFAULT_ARTIFACT_ROOT)
    metadata_db = os.getenv("URT_METADATA_DB", DEFAULT_METADATA_DB)
    return Orchestrator(artifact_root=artifact_root, metadata_db=metadata_db)


def create_app(orchestrator: Orchestrator | None = None, *, api_key: str | None = None) -> FastAPI:
    """Build the API. Pass an `Orchestrator` to point it at non-default stores (tests).

    `api_key` (default: `URT_API_KEY` from the environment) turns on the shared-secret
    gate described in `urt.auth`; None leaves everything open (loopback use).
    """
    orch = orchestrator or _build_orchestrator()
    # A previous process may have died mid-run: its `queued`/`running` rows are marked
    # failed now, before anything can be submitted, and are never re-executed.
    orch.recover_interrupted_runs()
    worker = RunWorker(orch)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        worker.start()
        try:
            yield
        finally:
            worker.stop(timeout=5)

    app = FastAPI(title="Redplane API", version="0.1.0", lifespan=lifespan)
    app.state.orchestrator = orch
    app.state.run_worker = worker
    install_auth(app, api_key if api_key is not None else api_key_from_env())

    def _require_run(run_id: str) -> dict[str, Any]:
        run = orch.get_run(run_id)
        if not run:
            raise HTTPException(status_code=404, detail="Run not found")
        return run

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    def _check_threshold(threshold: str | None) -> None:
        if threshold is not None and threshold.lower() not in SEVERITY_ORDER:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported threshold '{threshold}'. Supported: {list(SEVERITY_ORDER)}",
            )

    @app.get("/v1/runs")
    def list_runs(gate_threshold: str | None = Query(default=None)) -> list[dict[str, Any]]:
        _check_threshold(gate_threshold)
        return orch.list_runs(gate_threshold=gate_threshold)

    @app.post("/v1/runs", status_code=202)
    def create_run(payload: dict[str, Any], wait: bool = Query(default=False)) -> Response:
        """Queue a run (`202` + `run_id`; poll `GET /v1/runs/{id}`). `?wait=true` executes
        in the request instead: `200` completed / `500` failed, as before #18."""
        try:
            spec = RunSpec.from_dict(payload)
        except ValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        if wait:
            result = orch.execute(spec)
            if result.get("status") != "completed":
                raise HTTPException(status_code=500, detail=result)
            return JSONResponse(result, status_code=200)

        run_id = worker.submit(spec)
        location = f"/v1/runs/{run_id}"
        row = orch.get_run(run_id) or {}
        return JSONResponse(
            {"run_id": run_id, "status": row.get("status", "queued"), "location": location},
            status_code=202,
            headers={"Location": location},
        )

    @app.get("/v1/runs/{run_id}")
    def get_run(run_id: str) -> dict[str, Any]:
        return _require_run(run_id)

    @app.get("/v1/runs/{run_id}/findings")
    def get_findings(run_id: str) -> list[dict[str, Any]]:
        _require_run(run_id)
        return orch.get_findings(run_id)

    @app.get("/v1/runs/{run_id}/artifacts")
    def get_artifacts(run_id: str) -> list[dict[str, Any]]:
        _require_run(run_id)
        return orch.list_artifacts(run_id)

    def _require_redacted_bundle(run_id: str) -> None:
        if orch.bundle_is_redacted(run_id):
            return
        version = orch.bundle_format_version(run_id) or "unknown"
        raise HTTPException(
            status_code=409,
            detail=(
                f"Bundle format version {version} predates write-time redaction "
                f"({REDACTED_BUNDLE_MIN_VERSION}); only {list(LEGACY_RAW_DOWNLOAD_ALLOWLIST)} are served "
                "raw for such bundles, and the zip is not. Other files may contain expanded credentials. "
                "Use the JSON endpoints (/manifest, /summary, /invocations, /findings), which redact "
                "at read time. See README 'Output, Reports, and Audit Format'."
            ),
        )

    @app.get("/v1/runs/{run_id}/artifacts.zip")
    def get_artifacts_zip(run_id: str) -> Response:
        _require_run(run_id)
        _require_redacted_bundle(run_id)
        try:
            payload = orch.artifact_zip(run_id)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Run directory not found") from exc
        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "-", run_id)
        return Response(
            content=payload,
            media_type="application/zip",
            headers={
                **_ARTIFACT_HEADERS,
                "Content-Disposition": f'attachment; filename="{safe_name}.zip"',
            },
        )

    @app.get("/v1/runs/{run_id}/artifacts/{relative_path:path}")
    def get_artifact_file(run_id: str, relative_path: str) -> FileResponse:
        _require_run(run_id)
        if relative_path not in LEGACY_RAW_DOWNLOAD_ALLOWLIST:
            _require_redacted_bundle(run_id)
        try:
            path = orch.artifact_path(run_id, relative_path)
        except ArtifactPathError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid artifact path: {exc}") from exc
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Artifact not found") from exc
        return _artifact_response(path, relative_path)

    @app.get("/v1/runs/{run_id}/stages")
    def get_stages(run_id: str) -> list[dict[str, Any]]:
        """Orchestrator stage events so far (`[]` for a run that has not started). Discrete
        stages — engine/evaluator started or ended on a target — not a progress fraction."""
        _require_run(run_id)
        return orch.stage_events(run_id) or []

    for endpoint_name, bundle_file in BUNDLE_JSON_ENDPOINTS.items():
        if endpoint_name == "stages":
            continue

        def _make_bundle_reader(file_name: str) -> Callable[[str], Any]:
            def read_bundle(run_id: str) -> Any:
                _require_run(run_id)
                content = orch.read_bundle_json(run_id, file_name)
                if content is None:
                    raise HTTPException(status_code=404, detail=f"{file_name} not available for run")
                return content

            read_bundle.__name__ = f"get_{file_name.removesuffix('.json')}"
            return read_bundle

        app.add_api_route(
            f"/v1/runs/{{run_id}}/{endpoint_name}",
            _make_bundle_reader(bundle_file),
            methods=["GET"],
        )

    @app.get("/v1/runs/{run_id}/coverage")
    def get_coverage(run_id: str) -> dict[str, Any]:
        _require_run(run_id)
        coverage = orch.coverage(run_id)
        if coverage is None:
            raise HTTPException(status_code=404, detail="Run directory not found")
        return coverage

    @app.get("/v1/runs/{run_id}/gate")
    def get_gate(
        run_id: str,
        threshold: str = Query(default="high"),
        ignore_waivers: bool = Query(default=False),
        eval_min_pass_rate: str | None = Query(default=None),
    ) -> dict[str, Any]:
        _require_run(run_id)
        _check_threshold(threshold)
        try:
            eval_min = parse_eval_min_pass_rate(eval_min_pass_rate)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        result = orch.gate(run_id, threshold=threshold, ignore_waivers=ignore_waivers, eval_min_pass_rate=eval_min)
        if result is None:
            raise HTTPException(status_code=404, detail="Findings not available for run")
        return result.to_dict()

    # --- spec builder (G4): validate-only and probe; nothing here executes a run ---

    @app.get("/v1/capabilities")
    def get_capabilities() -> dict[str, Any]:
        return capabilities()

    @app.get("/v1/templates")
    def get_templates() -> list[dict[str, Any]]:
        return list_templates()

    @app.get("/v1/templates/{name}")
    def get_template(name: str) -> dict[str, Any]:
        row = load_template(name)
        if row is None:
            raise HTTPException(status_code=404, detail="Template not found")
        return row

    class _SpecTextError(Exception):
        """Unparseable spec text: a validation outcome, reported in-band by /validate."""

    def _spec_payload(body: dict[str, Any]) -> dict[str, Any]:
        try:
            return payload_from_request(body)
        except SpecInputError as exc:
            status = 413 if "exceeds" in str(exc) else 400
            raise HTTPException(status_code=status, detail=str(exc)) from exc
        except ValidationError as exc:
            raise _SpecTextError(str(exc)) from exc

    @app.post("/v1/specs/validate")
    def validate_spec(body: dict[str, Any]) -> dict[str, Any]:
        try:
            payload = _spec_payload(body)
        except _SpecTextError as exc:
            return SpecValidation(ok=False, errors=[str(exc)]).to_dict()
        return validate_spec_payload(payload).to_dict()

    @app.post("/v1/specs/probe")
    def probe_spec_endpoint(body: dict[str, Any]) -> dict[str, Any]:
        try:
            payload = _spec_payload(body)
        except _SpecTextError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        validation = validate_spec_payload(payload)
        if not validation.ok or validation.spec is None:
            raise HTTPException(status_code=400, detail={"errors": validation.errors})
        rows = probe_spec(validation.spec)
        return {"ok": all(row["ok"] for row in rows), "targets": rows}

    # --- gateway traces (G10): read-only over the trace root; works with the gateway down ---

    @app.get("/v1/traces")
    def list_trace_days() -> dict[str, Any]:
        return {"trace_root": str(orch.gateway_traces.root), "days": orch.gateway_traces.days()}

    @app.get("/v1/traces/{day}")
    def list_traces(
        day: str,
        target_id: str | None = Query(default=None),
        status_code: int | None = Query(default=None),
        run_id: str | None = Query(default=None),
    ) -> list[dict[str, Any]]:
        try:
            return orch.gateway_traces.list_day(day, target_id=target_id or None, status_code=status_code, run_id=run_id or None)
        except TracePathError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/v1/traces/{day}/{trace_id}")
    def get_trace(day: str, trace_id: str) -> dict[str, Any]:
        """The trace as the gateway stored it: headers redacted, bodies truncated to
        `audit.max_body_bytes`; `audit_path` is relative to the trace root."""
        try:
            trace = orch.gateway_traces.get_on_day(day, trace_id)
        except TracePathError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if trace is None:
            raise HTTPException(status_code=404, detail="Trace not found")
        return trace

    @app.get("/v1/runs/{run_id}/traces")
    def get_run_traces(run_id: str) -> dict[str, Any]:
        _require_run(run_id)
        linked = orch.run_traces(run_id)
        if linked is None:
            raise HTTPException(status_code=404, detail="Run not found")
        return linked

    @app.get("/v1/gateway/sessions")
    def get_gateway_sessions() -> dict[str, Any]:
        """Sessions of the running gateway (`URT_GATEWAY_URL`): ids, last use and presence
        flags only. `503` when no gateway is configured or reachable."""
        try:
            return fetch_sessions()
        except GatewayUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @app.get("/v1/runs/{run_a}/diff/{run_b}")
    def get_diff(run_a: str, run_b: str) -> dict[str, Any]:
        _require_run(run_a)
        _require_run(run_b)
        diff = orch.diff(run_a, run_b)
        if diff is None:
            raise HTTPException(status_code=404, detail="Findings not available for one of the runs")
        return diff.to_dict()

    @app.get("/v1/targets/{target_id}/trend")
    def get_trend(target_id: str) -> dict[str, Any]:
        points = orch.trend(target_id)
        if not points:
            raise HTTPException(status_code=404, detail="No runs with findings for this target")
        return {"target_id": target_id, "points": [point.to_dict() for point in points]}

    @app.post("/v1/waivers")
    def create_waiver(payload: dict[str, Any]) -> dict[str, Any]:
        required = ["target_id", "control_id", "reason", "owner", "expires_at"]
        missing = [key for key in required if key not in payload]
        if missing:
            raise HTTPException(status_code=400, detail=f"Missing required fields: {missing}")

        waiver_payload = {
            "waiver_id": payload.get("waiver_id") or str(uuid.uuid4()),
            "target_id": str(payload["target_id"]),
            "control_id": str(payload["control_id"]),
            "reason": str(payload["reason"]),
            "owner": str(payload["owner"]),
            "expires_at": str(payload["expires_at"]),
        }

        try:
            return orch.create_waiver(waiver_payload)
        except WaiverExistsError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.get("/v1/waivers")
    def list_waivers(
        target_id: str | None = Query(default=None),
        active: bool | None = Query(default=None),
    ) -> list[dict[str, Any]]:
        rows = [{**row, "active": waiver_is_active(row)} for row in orch.list_waivers(target_id)]
        if active is None:
            return rows
        return [row for row in rows if row["active"] is active]

    @app.get("/v1/waivers/{waiver_id}")
    def get_waiver(waiver_id: str) -> dict[str, Any]:
        row = orch.get_waiver(waiver_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Waiver not found")
        return row

    @app.patch("/v1/waivers/{waiver_id}")
    def patch_waiver(waiver_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Only `expires_at` is mutable. `{"revoke": true}` sets it to now and is terminal.
        Waivers are never deleted; every change is appended to the waiver's event history."""
        allowed = {"expires_at", "revoke"}
        unknown = sorted(set(payload) - allowed)
        if unknown or not payload:
            raise HTTPException(
                status_code=400,
                detail=f"Only {sorted(allowed)} may be patched (append-only: reason/owner/control never change); got {unknown}",
            )
        revoke = payload.get("revoke")
        if revoke is not None and revoke is not True:
            raise HTTPException(status_code=400, detail="revoke must be the JSON boolean true")
        try:
            if revoke is True:
                row = orch.revoke_waiver(waiver_id)
            else:
                row = orch.update_waiver_expiry(waiver_id, str(payload["expires_at"]))
        except WaiverRevokedError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if row is None:
            raise HTTPException(status_code=404, detail="Waiver not found")
        return row

    @app.get("/v1/runs/{run_id}/waiver-preview")
    def waiver_preview(
        run_id: str,
        control_id: str = Query(default=""),
        target_id: str = Query(default="*"),
    ) -> dict[str, Any]:
        _require_run(run_id)
        if not control_id.strip():
            raise HTTPException(status_code=400, detail="control_id is required")
        matches = orch.waiver_preview(run_id, control_id=control_id, target_id=target_id)
        if matches is None:
            raise HTTPException(status_code=404, detail="Findings not available for run")
        return {"run_id": run_id, "control_id": control_id, "target_id": target_id, "count": len(matches), "matches": matches}

    mount_ui(app, orch)
    return app


def __getattr__(name: str) -> Any:
    # `urt.api:app` stays importable for uvicorn without building the default
    # stores as an import side effect.
    if name == "app":
        return create_app()
    raise AttributeError(name)
