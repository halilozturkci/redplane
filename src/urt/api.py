"""FastAPI control-plane for Redplane.

`POST /v1/runs` is synchronous: the request blocks until the orchestrator
returns, bounded only by `budget.max_duration_seconds` (14400 s for
`weekly_deep`). Async job submission is tracked separately (#18).
"""

from __future__ import annotations

import os
import uuid
from typing import Any

from fastapi import FastAPI, HTTPException, Query

from .constants import DEFAULT_ARTIFACT_ROOT, DEFAULT_METADATA_DB, SEVERITY_ORDER
from .orchestrator import Orchestrator
from .types import RunSpec, ValidationError


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

    @app.get("/v1/runs")
    def list_runs() -> list[dict[str, Any]]:
        return orch.list_runs()

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

    @app.get("/v1/runs/{run_id}/gate")
    def get_gate(
        run_id: str,
        threshold: str = Query(default="high"),
        ignore_waivers: bool = Query(default=False),
    ) -> dict[str, Any]:
        _require_run(run_id)
        if threshold.lower() not in SEVERITY_ORDER:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported threshold '{threshold}'. Supported: {list(SEVERITY_ORDER)}",
            )
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
