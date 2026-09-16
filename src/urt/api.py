"""FastAPI control-plane for Redplane.

`POST /v1/runs` is synchronous: the request blocks until the orchestrator
returns, bounded only by `budget.max_duration_seconds` (14400 s for
`weekly_deep`). Async job submission is tracked separately (#18).
"""

from __future__ import annotations

import os
import re
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.responses import FileResponse

from .constants import (
    DEFAULT_ARTIFACT_ROOT,
    DEFAULT_METADATA_DB,
    LEGACY_RAW_DOWNLOAD_ALLOWLIST,
    REDACTED_BUNDLE_MIN_VERSION,
    SEVERITY_ORDER,
)
from .orchestrator import Orchestrator
from .storage.artifact_store import ArtifactPathError
from .types import RunSpec, ValidationError

# Bundle files exposed as JSON content (G1). Never accept a path from the client here.
BUNDLE_JSON_ENDPOINTS = {
    "scorecard": "scorecard.json",
    "summary": "run_summary.json",
    "manifest": "run_manifest.json",
    "invocations": "engine_invocations.json",
}

# Served inline. Everything else is an attachment with a generic type so the
# browser never renders attacker-influenced tool output in the API origin.
INLINE_MEDIA_TYPES = {
    ".json": "application/json",
    ".jsonl": "application/x-ndjson",
    ".md": "text/markdown; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
    ".log": "text/plain; charset=utf-8",
    ".csv": "text/csv; charset=utf-8",
    ".yaml": "text/plain; charset=utf-8",
    ".yml": "text/plain; charset=utf-8",
}
ATTACHMENT_MEDIA_TYPES = {
    ".html": "text/html; charset=utf-8",
}


_ARTIFACT_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    # Artifacts are attacker-influenced tool output; never let them script or be
    # cached if a UI is ever served from this origin.
    "Content-Security-Policy": "default-src 'none'; sandbox",
    "Cache-Control": "no-store",
}


def _artifact_response(path: Path, relative_path: str) -> FileResponse:
    suffix = path.suffix.lower()
    headers = dict(_ARTIFACT_HEADERS)
    if suffix in INLINE_MEDIA_TYPES:
        return FileResponse(path, media_type=INLINE_MEDIA_TYPES[suffix], headers=headers)
    media_type = ATTACHMENT_MEDIA_TYPES.get(suffix, "application/octet-stream")
    return FileResponse(
        path,
        media_type=media_type,
        headers=headers,
        filename=Path(relative_path).name,
        content_disposition_type="attachment",
    )


def _build_orchestrator() -> Orchestrator:
    artifact_root = os.getenv("URT_ARTIFACT_ROOT", DEFAULT_ARTIFACT_ROOT)
    metadata_db = os.getenv("URT_METADATA_DB", DEFAULT_METADATA_DB)
    return Orchestrator(artifact_root=artifact_root, metadata_db=metadata_db)


def create_app(orchestrator: Orchestrator | None = None) -> FastAPI:
    """Build the API. Pass an `Orchestrator` to point it at non-default stores (tests)."""
    orch = orchestrator or _build_orchestrator()
    app = FastAPI(title="Redplane API", version="0.1.0")
    app.state.orchestrator = orch

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

    @app.post("/v1/runs")
    def create_run(payload: dict[str, Any]) -> dict[str, Any]:
        try:
            spec = RunSpec.from_dict(payload)
        except ValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        result = orch.execute(spec)
        if result.get("status") != "completed":
            raise HTTPException(status_code=500, detail=result)
        return result

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

    for endpoint_name, bundle_file in BUNDLE_JSON_ENDPOINTS.items():

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

    @app.get("/v1/runs/{run_id}/gate")
    def get_gate(
        run_id: str,
        threshold: str = Query(default="high"),
        ignore_waivers: bool = Query(default=False),
    ) -> dict[str, Any]:
        _require_run(run_id)
        _check_threshold(threshold)
        result = orch.gate(run_id, threshold=threshold, ignore_waivers=ignore_waivers)
        if result is None:
            raise HTTPException(status_code=404, detail="Findings not available for run")
        return result.to_dict()

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
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.get("/v1/waivers")
    def list_waivers(target_id: str | None = Query(default=None)) -> list[dict[str, Any]]:
        return orch.list_waivers(target_id)

    return app


def __getattr__(name: str) -> Any:
    # `urt.api:app` stays importable for uvicorn without building the default
    # stores as an import side effect.
    if name == "app":
        return create_app()
    raise AttributeError(name)
