"""Run orchestration for Redplane."""

from __future__ import annotations

import os
import re
import traceback
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any

from .adapters import create_engine_adapter, create_evaluator_adapter, create_target_adapter
from .adapters.engine_base import EngineContext
from .adapters.evaluator_base import EvalContext
from .audit import build_artifacts_index
from .constants import (
    AUDIT_BUNDLE_FILES,
    BUNDLE_FORMAT_VERSION,
    DEFAULT_ARTIFACT_ROOT,
    DEFAULT_GATEWAY_TRACE_ROOT,
    DEFAULT_METADATA_DB,
    DEFAULT_RUN_PROFILE,
    GATEWAY_TRACE_ROOT_ENV,
    REDACTED_BUNDLE_MIN_VERSION,
    RUN_PROFILE_DEFAULTS,
    SEVERITY_ORDER,
    STAGE_EVENTS_FILE,
    TERMINAL_RUN_STATUSES,
)
from .diff import RunDiff, TrendPoint, diff_runs
from .gateway.traces import TraceIndex
from .jobs import current_worker_id, worker_is_alive
from .normalization import build_scorecard, normalize_findings
from .policy.waivers import parse_expiry, preview_matches, waiver_is_active
from .redaction import REDACTED, Scrubber, redact_bundle_payload, redact_run_spec_payload
from .report import (
    GateResult,
    gate_finding_row,
    gate_result,
    load_findings,
    render_csv,
    render_markdown,
    scorecard_eval_pass_rate,
)
from .runtime import BudgetTracker
from .storage import ArtifactStore, MetadataStore
from .types import EngineRunResult, EvalRunResult, RunRecord, RunSpec, UnifiedFinding
from .ui import load_bundle
from .ui.render import render_run_page


def _parse_version(value: str | None) -> tuple[int, ...]:
    if not value:
        return (0,)
    try:
        return tuple(int(part) for part in str(value).split("."))
    except ValueError:
        return (0,)


# A non-terminal row whose worker cannot be checked (no `worker_id`, another host) is
# treated as interrupted only after this long without an update.
STALE_RUN_AFTER_SECONDS = 24 * 60 * 60
INTERRUPTED_MESSAGE = (
    "interrupted: the process executing this run exited before it finished "
    "(status was {status}); the bundle on disk is partial and the run was not re-executed"
)
STOPPED_MESSAGE = (
    "interrupted: the control plane was stopped while this run was {status}; the engine process "
    "group was terminated, the bundle on disk is partial and the run was not re-executed"
)


class RunInterrupted(RuntimeError):
    """Raised inside `execute` when the run was asked to stop (control-plane shutdown)."""


class StageLog:
    """Append-only orchestrator stage events, rewritten to `stage_events.json` on every
    append so a poller sees the current stage while the run is still executing."""

    def __init__(self, store: ArtifactStore, run_id: str) -> None:
        self._store = store
        self._run_id = run_id
        self.events: list[dict[str, Any]] = []

    def record(self, stage: str, status: str, **fields: Any) -> None:
        event = {"at": datetime.now(timezone.utc).isoformat(), "stage": stage, "status": status, **fields}
        self.events.append(event)
        self._store.write_json(self._run_id, STAGE_EVENTS_FILE, self.events)


class Orchestrator:
    """Coordinates run execution across targets and engines."""

    def __init__(
        self,
        *,
        artifact_root: str = DEFAULT_ARTIFACT_ROOT,
        metadata_db: str = DEFAULT_METADATA_DB,
        gateway_trace_root: str | None = None,
    ):
        self.artifact_store = ArtifactStore(artifact_root)
        self.metadata_store = MetadataStore(metadata_db)
        # Read-only: the gateway owns this tree; the orchestrator only links runs to it.
        self.gateway_traces = TraceIndex(
            gateway_trace_root or os.environ.get(GATEWAY_TRACE_ROOT_ENV) or DEFAULT_GATEWAY_TRACE_ROOT
        )
        self._interrupt_requested: set[str] = set()

    def interrupt_run(self, run_id: str) -> None:
        """Ask a run executing in this process to stop at its next stage boundary (the
        worker also kills the tool process group, so the boundary comes quickly)."""
        self._interrupt_requested.add(run_id)

    def _check_interrupted(self, run_id: str) -> None:
        if run_id in self._interrupt_requested:
            raise RunInterrupted(STOPPED_MESSAGE.format(status="running"))

    @staticmethod
    def _utc_now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _new_run_id(spec: RunSpec) -> str:
        # The run id is a directory name, a URL segment and a Content-Disposition
        # filename; keep it to a safe alphabet.
        slug = re.sub(r"[^a-z0-9._-]+", "-", spec.name.lower()).strip("-") or "run"
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        return f"run-{slug}-{ts}-{uuid.uuid4().hex[:8]}"

    def enqueue_run(self, spec: RunSpec, *, worker_id: str) -> str:
        """Record a run as `queued` for `worker_id` and return its id. `execute(spec,
        run_id=...)` later moves the same row to `running`; nothing is written to disk
        until then (the spec, credentials included, lives only in the worker's memory)."""
        run_id = self._new_run_id(spec)
        self.metadata_store.create_run(
            self.metadata_store.new_record(
                run_id=run_id, name=spec.name, profile=spec.run_profile, status="queued", worker_id=worker_id
            )
        )
        return run_id

    def _start_run_record(self, spec: RunSpec, run_id: str | None, worker_id: str) -> tuple[str, str, str]:
        """Create the `running` row (CLI / sync path) or promote the `queued` one (worker).
        Returns `(run_id, created_at, started_at)`. A row that is not `queued` is never
        executed twice."""
        started = self._utc_now()
        if run_id is None:
            run_id = self._new_run_id(spec)
            self.metadata_store.create_run(
                RunRecord(
                    run_id=run_id,
                    name=spec.name,
                    profile=spec.run_profile,
                    status="running",
                    created_at=started,
                    updated_at=started,
                    worker_id=worker_id,
                    started_at=started,
                )
            )
            return run_id, started, started
        row = self.metadata_store.get_run(run_id)
        if row is None:
            raise ValueError(f"Run {run_id!r} was never queued")
        if row["status"] != "queued":
            raise RuntimeError(f"Run {run_id!r} is {row['status']}, not queued; refusing to execute it again")
        self.metadata_store.update_run(run_id, status="running", updated_at=started, worker_id=worker_id, started_at=started)
        return run_id, str(row["created_at"]), started

    def execute(self, spec: RunSpec, *, run_id: str | None = None, worker_id: str | None = None) -> dict[str, Any]:
        """Execute `spec` to completion in this thread and write the audit bundle.

        Without `run_id` (the `urt run` / `?wait=true` path) a new `running` row is
        created; with one (the background worker) the previously `queued` row is
        promoted. Both paths are this one function.
        """
        run_id, now, started_at = self._start_run_record(spec, run_id, worker_id or current_worker_id())
        # The in-memory spec holds expanded `${VAR}` credentials; nothing this run
        # writes or returns may. `store` scrubs known secret values from every write
        # (including adapter raw logs); the spec copy is additionally key-redacted.
        scrubber = Scrubber.from_spec(spec)
        store = self.artifact_store.scrubbed(scrubber)
        redacted_spec = scrubber.scrub(redact_run_spec_payload(spec.to_dict()))
        store.write_json(run_id, "resolved_spec.json", redacted_spec)
        stages = StageLog(store, run_id)
        stages.record(
            "run",
            "started",
            targets=[t.target_id for t in spec.targets],
            engines=[e.name for e in spec.engines],
            evaluators=[e.name for e in spec.evaluators],
        )

        run_started = perf_counter()
        all_findings: list[UnifiedFinding] = []
        all_eval_results: list[EvalRunResult] = []
        engine_summaries: list[dict[str, Any]] = []
        evaluator_summaries: list[dict[str, Any]] = []
        target_probe_results: list[dict[str, Any]] = []
        engine_invocations: list[dict[str, Any]] = []
        budget = BudgetTracker(spec.budget)

        try:
            for target_spec in spec.targets:
                target_adapter = create_target_adapter(target_spec)
                target_adapter.apply_runtime(
                    connect_seconds=spec.timeouts.connect_seconds,
                    request_seconds=spec.timeouts.request_seconds,
                )
                ok, detail = target_adapter.healthcheck()
                target_probe_results.append(
                    {
                        "target_id": target_spec.target_id,
                        "target_type": target_spec.target_type,
                        "ok": ok,
                        "detail": detail,
                        "checked_at": self._utc_now(),
                    }
                )
                stages.record("target", "ok" if ok else "failed", target_id=target_spec.target_id, message=str(detail))
                if not ok:
                    all_findings.append(
                        UnifiedFinding(
                            finding_id=f"{run_id}:{target_spec.target_id}:healthcheck",
                            run_id=run_id,
                            target_id=target_spec.target_id,
                            engine="platform",
                            category="misconfiguration",
                            sub_category="target_healthcheck",
                            severity="high",
                            confidence=0.98,
                            attack_vector="connectivity",
                            attack_complexity="n/a",
                            success=True,
                            description=f"Target healthcheck failed: {detail}",
                            repro_steps=["Verify endpoint and credentials", "Run healthcheck again"],
                            metadata={"detail": detail},
                        )
                    )
                    continue

                session_id = target_adapter.start_session()
                try:
                    target_engine_results: list[EngineRunResult] = []
                    for engine_spec in spec.engines:
                        self._check_interrupted(run_id)
                        budget.check(stage=f"before engine {engine_spec.name} on {target_spec.target_id}")
                        engine_adapter = create_engine_adapter(engine_spec)
                        context = EngineContext(
                            run_id=run_id,
                            run_name=spec.name,
                            run_profile=spec.run_profile,
                            target=target_spec,
                            artifact_store=store,
                            timeout_seconds=spec.timeouts.engine_seconds,
                            seed=spec.seed,
                            evidence_level=spec.evidence_level,
                            enabled_scenarios=list(engine_spec.enabled_scenarios),
                            connect_seconds=spec.timeouts.connect_seconds,
                            request_seconds=spec.timeouts.request_seconds,
                        )

                        invocation_started = perf_counter()
                        invocation_started_at = self._utc_now()
                        stages.record("engine", "started", engine=engine_spec.name, target_id=target_spec.target_id)
                        result = self._safe_run_engine(engine_adapter, context)
                        invocation_duration = perf_counter() - invocation_started
                        invocation_ended_at = self._utc_now()
                        # A killed tool must not pass as an ordinary fail_open failure.
                        self._check_interrupted(run_id)
                        stages.record(
                            "engine",
                            result.status,
                            engine=engine_spec.name,
                            target_id=target_spec.target_id,
                            message=result.message,
                            duration_seconds=round(invocation_duration, 4),
                            finding_count=len(result.findings),
                        )
                        budget.observe_metrics(result.metrics)
                        budget.check(stage=f"after engine {engine_spec.name} on {target_spec.target_id}")

                        all_findings.extend(result.findings)
                        target_engine_results.append(result)
                        summary = {
                            "engine": result.engine,
                            "target_id": result.target_id,
                            "status": result.status,
                            "message": result.message,
                            "metrics": result.metrics,
                            "artifacts": result.artifacts,
                        }
                        engine_summaries.append(summary)
                        engine_invocations.append(
                            {
                                "engine": result.engine,
                                "target_id": result.target_id,
                                "started_at": invocation_started_at,
                                "ended_at": invocation_ended_at,
                                "duration_seconds": round(invocation_duration, 4),
                                "status": result.status,
                                "message": result.message,
                                "metrics": result.metrics,
                                "artifacts": result.artifacts,
                                "fail_open": engine_spec.fail_open,
                            }
                        )
                        # Rewritten after every invocation so progress is observable on disk.
                        store.write_json(run_id, "engine_invocations.json", engine_invocations)

                        if result.status in {"failed"} and not engine_spec.fail_open:
                            raise RuntimeError(
                                f"Engine {engine_spec.name} failed on target {target_spec.target_id} with fail_open=false"
                            )

                    # Run evaluators after all engines for this target
                    target_findings = [f for f in all_findings if f.target_id == target_spec.target_id]

                    for evaluator_spec in spec.evaluators:
                        self._check_interrupted(run_id)
                        budget.check(
                            stage=f"before evaluator {evaluator_spec.name} on {target_spec.target_id}"
                        )
                        evaluator_adapter = create_evaluator_adapter(evaluator_spec)
                        sidecar_path = self._write_engine_findings_sidecar(
                            store,
                            run_id=run_id,
                            evaluator_name=evaluator_spec.name,
                            target_id=target_spec.target_id,
                            findings=target_findings,
                            engine_results=target_engine_results,
                        )
                        eval_context = EvalContext(
                            run_id=run_id,
                            run_name=spec.name,
                            target=target_spec,
                            artifact_store=store,
                            timeout_seconds=spec.timeouts.engine_seconds,
                            seed=spec.seed,
                            engine_findings=target_findings,
                            engine_results=list(target_engine_results),
                            evidence_level=spec.evidence_level,
                            enabled_scenarios=[],
                            run_profile=spec.run_profile,
                            engine_findings_path=sidecar_path,
                        )
                        stages.record("evaluator", "started", evaluator=evaluator_spec.name, target_id=target_spec.target_id)
                        eval_result = self._safe_run_evaluator(evaluator_adapter, eval_context)
                        self._check_interrupted(run_id)
                        stages.record(
                            "evaluator",
                            eval_result.status,
                            evaluator=evaluator_spec.name,
                            target_id=target_spec.target_id,
                            message=eval_result.message,
                            score_count=len(eval_result.scores),
                        )
                        budget.observe_metrics(eval_result.metrics)
                        budget.check(
                            stage=f"after evaluator {evaluator_spec.name} on {target_spec.target_id}"
                        )
                        all_eval_results.append(eval_result)
                        all_findings.extend(eval_result.findings)
                        evaluator_summaries.append({
                            "evaluator": eval_result.evaluator,
                            "target_id": eval_result.target_id,
                            "status": eval_result.status,
                            "message": eval_result.message,
                            "metrics": eval_result.metrics,
                            "score_count": len(eval_result.scores),
                            "fail_open": evaluator_spec.fail_open,
                        })
                        if eval_result.status in {"failed"} and not evaluator_spec.fail_open:
                            raise RuntimeError(
                                f"Evaluator {evaluator_spec.name} failed on target {target_spec.target_id} with fail_open=false"
                            )
                finally:
                    target_adapter.end_session(session_id)

            stages.record("normalize", "started", finding_count=len(all_findings))
            normalized = normalize_findings(all_findings, policy_profiles=spec.policy_profiles)
            normalized = [scrubber.scrub_finding(item) for item in normalized]
            scorecard = build_scorecard(run_id, normalized, eval_results=all_eval_results or None)

            findings_path = store.write_json(
                run_id,
                "findings.json",
                [f.to_dict() for f in normalized],
            )
            scorecard_path = store.write_json(
                run_id,
                "scorecard.json",
                scorecard.to_dict(),
            )
            run_summary_path = store.write_json(
                run_id,
                "run_summary.json",
                {
                    "run_id": run_id,
                    "name": spec.name,
                    "profile": spec.run_profile,
                    "targets": [t.target_id for t in spec.targets],
                    "engines": [e.name for e in spec.engines],
                    "evaluators": [e.name for e in spec.evaluators],
                    "engine_summaries": engine_summaries,
                    "evaluator_summaries": evaluator_summaries,
                },
            )
            store.write_json(run_id, "engine_invocations.json", engine_invocations)

            run_root = store.run_dir(run_id)
            # The manifest is written before the reports so the static viewer can
            # show duration, budget and probe results; report paths are deterministic.
            run_duration = perf_counter() - run_started
            completed_at = self._utc_now()
            gateway_link = self.gateway_traces.traces_for_run(run_id, started_at=started_at, ended_at=completed_at)
            run_manifest = {
                "run_id": run_id,
                "name": spec.name,
                "run_profile": spec.run_profile,
                "status": "completed",
                "created_at": now,
                "started_at": started_at,
                "completed_at": completed_at,
                "duration_seconds": round(run_duration, 4),
                "bundle_format_version": BUNDLE_FORMAT_VERSION,
                "required_bundle_files": list(AUDIT_BUNDLE_FILES),
                "targets": redacted_spec["targets"],
                "engines": redacted_spec["engines"],
                "policy_profiles": spec.policy_profiles,
                "target_probe_results": target_probe_results,
                "engine_invocation_count": len(engine_invocations),
                "finding_count": len(normalized),
                "budget": budget.snapshot(),
                # Gateway traces this run produced (idea 3). `trace_ids` = exact `run_id`
                # tags only; the weaker time-window join stays labelled inside `gateway_traces`.
                "gateway_traces": gateway_link,
                "trace_ids": gateway_link["by_run_id"],
                "report_paths": {
                    "markdown": str(run_root / "report.md"),
                    "html": str(run_root / "report.html"),
                    "csv": str(run_root / "report.csv"),
                },
            }
            store.write_json(run_id, "run_manifest.json", run_manifest)
            # Recorded before the reports so the index they build covers the final log.
            stages.record("run", "completed", finding_count=len(normalized), duration_seconds=round(run_duration, 4))

            self.write_reports(run_id, store=store)
            artifacts_index_path = str(run_root / "artifacts_index.json")

            self.metadata_store.insert_findings(normalized)
            self.metadata_store.update_run(
                run_id,
                status="completed",
                updated_at=self._utc_now(),
                scorecard_path=scorecard_path,
                findings_path=findings_path,
            )

            return scrubber.scrub({
                "run_id": run_id,
                "status": "completed",
                "scorecard": scorecard.to_dict(),
                "scorecard_path": scorecard_path,
                "findings_path": findings_path,
                "summary_path": run_summary_path,
                "manifest_path": str(run_root / "run_manifest.json"),
                "artifacts_index_path": artifacts_index_path,
                "engine_summaries": engine_summaries,
            })

        except Exception as exc:  # noqa: BLE001
            error_trace = traceback.format_exc()
            error_path = store.write_text(run_id, "run_error.log", error_trace)
            error_message = scrubber.scrub_text(str(exc))
            stages.record("run", "failed", message=error_message)
            failed_at = self._utc_now()
            self.metadata_store.update_run(
                run_id,
                status="failed",
                updated_at=failed_at,
                error_message=error_message,
            )
            gateway_link = self.gateway_traces.traces_for_run(run_id, started_at=started_at, ended_at=failed_at)
            store.write_json(
                run_id,
                "run_manifest.json",
                {
                    "run_id": run_id,
                    "name": spec.name,
                    "run_profile": spec.run_profile,
                    "status": "failed",
                    "created_at": now,
                    "started_at": started_at,
                    "failed_at": failed_at,
                    "bundle_format_version": BUNDLE_FORMAT_VERSION,
                    "error": error_message,
                    "target_probe_results": target_probe_results,
                    "engine_invocations": engine_invocations,
                    "budget": budget.snapshot(),
                    "gateway_traces": gateway_link,
                    "trace_ids": gateway_link["by_run_id"],
                },
            )
            self._write_failure_reports(run_id, store)
            return {
                "run_id": run_id,
                "status": "failed",
                "error": error_message,
                "error_log_path": error_path,
            }
        finally:
            self._interrupt_requested.discard(run_id)

    # --- run lifecycle bookkeeping (async submissions, crash recovery) ---

    def mark_run_failed(self, run_id: str, message: str) -> None:
        """Record a failure for a run whose `execute` never got to write one (worker
        error, interrupted process). Writes a failed manifest unless one exists. A row
        that is already terminal is left as it is."""
        row = self.metadata_store.get_run(run_id)
        if row is None or row.get("status") in TERMINAL_RUN_STATUSES:
            return
        now = self._utc_now()
        self.metadata_store.update_run(run_id, status="failed", updated_at=now, error_message=message)
        if self.artifact_store.read_json(run_id, "run_manifest.json") is None:
            self.artifact_store.write_json(
                run_id,
                "run_manifest.json",
                {
                    "run_id": run_id,
                    "name": row.get("name"),
                    "run_profile": row.get("profile"),
                    "status": "failed",
                    "created_at": row.get("created_at"),
                    "failed_at": now,
                    "bundle_format_version": BUNDLE_FORMAT_VERSION,
                    "error": message,
                    "engine_invocations": self.artifact_store.read_json(run_id, "engine_invocations.json") or [],
                },
            )
        self.artifact_store.write_text(run_id, "run_error.log", f"{message}\n")
        events = self.artifact_store.read_json(run_id, STAGE_EVENTS_FILE) or []
        events.append({"at": now, "stage": "run", "status": "failed", "message": message})
        self.artifact_store.write_json(run_id, STAGE_EVENTS_FILE, events)

    @staticmethod
    def _age_seconds(timestamp: str | None) -> float | None:
        if not timestamp:
            return None
        try:
            parsed = datetime.fromisoformat(str(timestamp))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - parsed).total_seconds()

    def run_is_stale(self, row: dict[str, Any]) -> bool:
        """A `queued`/`running` row whose worker process is gone (same host, dead pid), or
        whose worker cannot be checked and that has not been updated for a day."""
        if row.get("status") in TERMINAL_RUN_STATUSES:
            return False
        alive = worker_is_alive(row.get("worker_id"))
        if alive is not None:
            return not alive
        age = self._age_seconds(row.get("updated_at"))
        return age is not None and age > STALE_RUN_AFTER_SECONDS

    def recover_interrupted_runs(self) -> list[str]:
        """Mark stale `queued`/`running` rows `failed` (see `run_is_stale`). Called when a
        control-plane process starts. Never re-executes anything. Returns the run ids."""
        recovered: list[str] = []
        for row in self.metadata_store.list_unfinished_runs():
            if not self.run_is_stale(row):
                continue
            self.mark_run_failed(row["run_id"], INTERRUPTED_MESSAGE.format(status=row["status"]))
            recovered.append(row["run_id"])
        return recovered

    def _decorate_run_row(self, row: dict[str, Any]) -> dict[str, Any]:
        """Lifecycle fields every run row carries: `terminal`, `stale`, `stage_event_count`."""
        events = self.artifact_store.read_json(row["run_id"], STAGE_EVENTS_FILE)
        return {
            **row,
            "terminal": row.get("status") in TERMINAL_RUN_STATUSES,
            "stale": self.run_is_stale(row),
            "stage_event_count": len(events) if isinstance(events, list) else 0,
        }

    def run_traces(self, run_id: str) -> dict[str, Any] | None:
        """Gateway traces linked to a run: the manifest's `gateway_traces` (recorded at the
        end of the run) resolved to summary rows from the trace root; None for an unknown
        run, an empty link before the manifest exists."""
        if not self.metadata_store.get_run(run_id):
            return None
        manifest = self.artifact_store.read_json(run_id, "run_manifest.json") or {}
        link = manifest.get("gateway_traces") if isinstance(manifest.get("gateway_traces"), dict) else None
        if link is None:
            link = {"window": None, "by_run_id": [], "by_time_window": [], "all_trace_ids": []}
        return {
            "run_id": run_id,
            "trace_root": str(self.gateway_traces.root),
            **link,
            "trace_ids": list(link.get("by_run_id") or []),
            "traces": self.gateway_traces.summaries_for(link),
        }

    def stage_events(self, run_id: str) -> list[dict[str, Any]] | None:
        """Orchestrator stage events so far; None for an unknown run, [] before it starts."""
        if not self.metadata_store.get_run(run_id):
            return None
        events = self.artifact_store.read_json(run_id, STAGE_EVENTS_FILE)
        return list(events) if isinstance(events, list) else []

    def _write_failure_reports(self, run_id: str, store: ArtifactStore) -> None:
        # Best effort: the failure is already recorded in SQLite and the manifest, and
        # a reviewer needs report.html to see it. A renderer bug must not replace the
        # recorded failure with an unhandled exception.
        try:
            self.write_reports(run_id, store=store)
        except Exception as exc:  # noqa: BLE001
            store.write_text(run_id, "report_error.log", f"report rendering failed: {exc}\n")

    def write_reports(self, run_id: str, *, store: ArtifactStore | None = None) -> dict[str, str]:
        """(Re)render report.md/html/csv from the bundle on disk and rebuild the index.

        `report.html` is the self-contained viewer: it embeds the redacted bundle
        content and the waivers active right now. Run it again (`urt report`) to
        refresh waiver state. Returns the written paths.
        """
        target_store = store or self.artifact_store
        run_root = target_store.run_dir(run_id)
        scorecard = target_store.read_json(run_id, "scorecard.json") or {}
        findings = target_store.read_json(run_id, "findings.json") or []

        paths = {
            "markdown": target_store.write_text(run_id, "report.md", render_markdown(scorecard, findings)),
            "csv": target_store.write_text(run_id, "report.csv", render_csv(findings)),
        }
        # The file list on the page comes from an index built before the page exists;
        # the final index (written below) then includes the page itself.
        target_store.write_json(run_id, "artifacts_index.json", build_artifacts_index(run_root))
        bundle = load_bundle(run_root, waivers=self.list_waivers())
        paths["html"] = target_store.write_text(run_id, "report.html", render_run_page(bundle, mode="static"))
        target_store.write_json(run_id, "artifacts_index.json", build_artifacts_index(run_root))
        return paths

    def _write_engine_findings_sidecar(
        self,
        store: ArtifactStore,
        *,
        run_id: str,
        evaluator_name: str,
        target_id: str,
        findings: list[UnifiedFinding],
        engine_results: list[EngineRunResult],
    ) -> str:
        payload = {
            "schema": "urt.engine_findings.v1",
            "run_id": run_id,
            "target_id": target_id,
            "evaluator": evaluator_name,
            "engine_findings": [item.to_dict() for item in findings],
            "engine_summaries": [
                {
                    "engine": item.engine,
                    "status": item.status,
                    "message": item.message,
                    "metrics": item.metrics,
                }
                for item in engine_results
            ],
        }
        return store.write_json(
            run_id,
            f"raw/{evaluator_name}/{target_id}_engine_findings.json",
            payload,
        )

    def _safe_run_engine(self, engine_adapter, context: EngineContext) -> EngineRunResult:
        try:
            return engine_adapter.run(context)
        except Exception as exc:  # noqa: BLE001
            finding = UnifiedFinding(
                finding_id=f"{context.run_id}:{context.target.target_id}:{engine_adapter.name}:exception",
                run_id=context.run_id,
                target_id=context.target.target_id,
                engine=engine_adapter.name,
                category="execution",
                sub_category="engine_exception",
                severity="high",
                confidence=0.99,
                attack_vector="tool_runtime",
                attack_complexity="n/a",
                success=True,
                description=f"Engine raised exception: {exc}",
                repro_steps=["Inspect traceback", "Verify adapter params"],
                metadata={"traceback": traceback.format_exc()},
            )
            return EngineRunResult(
                engine=engine_adapter.name,
                target_id=context.target.target_id,
                findings=[finding],
                artifacts=[],
                metrics={"executed": False},
                status="failed",
                message=str(exc),
            )

    def _safe_run_evaluator(self, evaluator_adapter, context: EvalContext) -> EvalRunResult:
        try:
            return evaluator_adapter.evaluate(context)
        except Exception as exc:  # noqa: BLE001
            finding = UnifiedFinding(
                finding_id=f"{context.run_id}:{context.target.target_id}:{evaluator_adapter.name}:exception",
                run_id=context.run_id,
                target_id=context.target.target_id,
                engine=evaluator_adapter.name,
                category="execution",
                sub_category="evaluator_exception",
                severity="high",
                confidence=0.99,
                attack_vector="tool_runtime",
                attack_complexity="n/a",
                success=True,
                description=f"Evaluator raised exception: {exc}",
                repro_steps=["Inspect traceback", "Verify evaluator params"],
                metadata={"traceback": traceback.format_exc()},
            )
            return EvalRunResult(
                evaluator=evaluator_adapter.name,
                target_id=context.target.target_id,
                findings=[finding],
                artifacts=[],
                metrics={"executed": False},
                status="failed",
                message=str(exc),
            )

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        row = self.metadata_store.get_run(run_id)
        return None if row is None else self._decorate_run_row(self._mask_legacy_error(row))

    def _mask_legacy_error(self, row: dict[str, Any]) -> dict[str, Any]:
        # SQLite `error_message` is free text; pre-1.1 runs wrote it unscrubbed
        # (`TimeoutExpired` copies the argv). Same rule as the manifest `error`.
        if row.get("error_message") and not self.bundle_is_redacted(row["run_id"]):
            return {**row, "error_message": REDACTED}
        return row

    def list_runs(self, *, gate_threshold: str | None = None) -> list[dict[str, Any]]:
        """Run rows enriched from the bundle (targets, engines, counts, ASR, gate summary).

        Fields whose source file is absent (e.g. failed runs without a scorecard) are
        None rather than zero. `gate_threshold` defaults to the run profile's
        `gate_threshold`; pass one explicitly to evaluate every row at that level.
        """
        if gate_threshold is not None and gate_threshold.lower() not in SEVERITY_ORDER:
            raise ValueError(f"Unsupported threshold: {gate_threshold}")
        waivers = self.list_waivers()
        return [
            self._enrich_run_row(row, waivers=waivers, gate_threshold=gate_threshold)
            for row in self.metadata_store.list_runs()
        ]

    def _enrich_run_row(
        self,
        row: dict[str, Any],
        *,
        waivers: list[dict[str, Any]],
        gate_threshold: str | None,
    ) -> dict[str, Any]:
        run_id = row["run_id"]
        scorecard = self.artifact_store.read_json(run_id, "scorecard.json")
        summary = self.artifact_store.read_json(run_id, "run_summary.json") or {}
        manifest = self.artifact_store.read_json(run_id, "run_manifest.json") or {}
        resolved_spec = self.artifact_store.read_json(run_id, "resolved_spec.json") or {}

        engine_summaries = summary.get("engine_summaries", [])
        executed = sorted({s["engine"] for s in engine_summaries if s.get("status") != "skipped"})
        skipped = sorted({s["engine"] for s in engine_summaries if s.get("status") == "skipped"} - set(executed))

        enriched = self._decorate_run_row(self._mask_legacy_error(dict(row)))
        enriched.update(
            {
                "targets": summary.get("targets") or [t.get("target_id") for t in resolved_spec.get("targets", [])],
                "engines": summary.get("engines") or [e.get("name") for e in resolved_spec.get("engines", [])],
                "evaluators": summary.get("evaluators") or [e.get("name") for e in resolved_spec.get("evaluators", [])],
                "engines_executed": executed,
                "engines_skipped": skipped,
                "finding_count": scorecard.get("total_findings") if scorecard else None,
                "severity_counts": (
                    {level: scorecard.get(level) for level in ("critical", "high", "medium", "low", "info")}
                    if scorecard
                    else None
                ),
                "asr_overall": scorecard.get("asr_overall") if scorecard else None,
                "eval_pass_rate": scorecard.get("eval_pass_rate") if scorecard else None,
                "duration_seconds": manifest.get("duration_seconds"),
                "bundle_format_version": manifest.get("bundle_format_version"),
                "gate": self._gate_summary(row, waivers=waivers, threshold=gate_threshold),
            }
        )
        return enriched

    def _gate_summary(
        self,
        row: dict[str, Any],
        *,
        waivers: list[dict[str, Any]],
        threshold: str | None,
    ) -> dict[str, Any] | None:
        findings_path = row.get("findings_path")
        if not findings_path or not Path(findings_path).exists():
            return None
        profile_defaults = RUN_PROFILE_DEFAULTS.get(row.get("profile", ""), RUN_PROFILE_DEFAULTS[DEFAULT_RUN_PROFILE])
        effective = (threshold or profile_defaults.get("gate_threshold", "high")).lower()
        result = gate_result(load_findings(findings_path), threshold=effective, waivers=waivers)
        return {
            "threshold": effective,
            "ok": result.ok,
            "blocking_count": len(result.blocking),
            "waived_count": len(result.waived),
        }

    def get_findings(self, run_id: str) -> list[dict[str, Any]]:
        # Read-time key redaction covers rows written by pre-1.1 code (e.g. the
        # `metadata.env_overrides` dict); write-time scrubbing covers everything else.
        findings = redact_bundle_payload(
            self.metadata_store.get_findings(run_id), legacy=not self.bundle_is_redacted(run_id)
        )
        for item in findings:
            # evidence_refs are absolute filesystem paths; expose the bundle-relative
            # form so clients can fetch them through the artifact endpoints.
            item["evidence_artifacts"] = [
                self.artifact_store.relative_artifact_path(run_id, str(ref))
                for ref in item.get("evidence_refs", [])
            ]
        return findings

    def list_artifacts(self, run_id: str) -> list[dict[str, Any]]:
        run = self.metadata_store.get_run(run_id)
        if not run:
            return []
        index = self.artifact_store.read_json(run_id, "artifacts_index.json")
        if index is not None:
            return index
        return build_artifacts_index(self.artifact_store.run_dir(run_id))

    def read_bundle_json(self, run_id: str, file_name: str) -> Any | None:
        """Content of one bundle JSON file (`AUDIT_BUNDLE_FILES`), None when absent."""
        if file_name not in AUDIT_BUNDLE_FILES or not file_name.endswith(".json"):
            raise ValueError(f"Not a bundle JSON file: {file_name}")
        if not self.metadata_store.get_run(run_id):
            return None
        content = self.artifact_store.read_json(run_id, file_name)
        if content is None:
            return None
        return redact_bundle_payload(content, legacy=not self.bundle_is_redacted(run_id))

    def coverage(self, run_id: str) -> dict[str, Any] | None:
        """Framework coverage matrix (targets × OWASP LLM / Agentic / ATLAS labels) as JSON."""
        if not self.metadata_store.get_run(run_id):
            return None
        try:
            run_dir = self.artifact_store.existing_run_dir(run_id)
        except ValueError:
            return None
        if run_dir is None:
            return None
        return load_bundle(run_dir, waivers=self.list_waivers()).coverage()

    def bundle_format_version(self, run_id: str) -> str | None:
        manifest = self.artifact_store.read_json(run_id, "run_manifest.json")
        if not isinstance(manifest, dict):
            return None
        version = manifest.get("bundle_format_version")
        return None if version is None else str(version)

    def bundle_is_redacted(self, run_id: str) -> bool:
        """True when the bundle was written with write-time redaction (>= 1.1).

        Pre-1.1 bundles may hold expanded credentials in the spec-bearing files, so
        raw downloads of those files and of the whole directory must be refused.
        """
        return _parse_version(self.bundle_format_version(run_id)) >= _parse_version(REDACTED_BUNDLE_MIN_VERSION)

    def artifact_path(self, run_id: str, relative_path: str) -> Path:
        """Filesystem path of one artifact, confined to the run directory (see ArtifactStore)."""
        return self.artifact_store.resolve_artifact(run_id, relative_path)

    def artifact_zip(self, run_id: str) -> bytes:
        return self.artifact_store.zip_run(run_id)

    def gate(
        self,
        run_id: str,
        *,
        threshold: str = "high",
        ignore_waivers: bool = False,
        eval_min_pass_rate: float | None = None,
    ) -> GateResult | None:
        """Structured gate verdict for a run; None when findings are not available yet."""
        run = self.metadata_store.get_run(run_id)
        if not run:
            return None
        findings_path = run.get("findings_path")
        if not findings_path or not Path(findings_path).exists():
            return None
        findings = load_findings(findings_path)
        waivers = [] if ignore_waivers else self.list_waivers()
        return gate_result(
            findings,
            threshold=threshold,
            waivers=waivers,
            eval_min_pass_rate=eval_min_pass_rate,
            eval_pass_rate=scorecard_eval_pass_rate(self.artifact_store.read_json(run_id, "scorecard.json")),
        )

    def _run_findings(self, run_id: str) -> list[UnifiedFinding] | None:
        run = self.metadata_store.get_run(run_id)
        if not run:
            return None
        findings_path = run.get("findings_path")
        if not findings_path or not Path(findings_path).exists():
            return None
        return load_findings(findings_path)

    def diff(self, run_a: str, run_b: str) -> RunDiff | None:
        """Compare two runs' findings and scorecards; None when either has no findings yet."""
        findings_a = self._run_findings(run_a)
        findings_b = self._run_findings(run_b)
        if findings_a is None or findings_b is None:
            return None
        return diff_runs(
            run_a,
            findings_a,
            self.artifact_store.read_json(run_a, "scorecard.json"),
            run_b,
            findings_b,
            self.artifact_store.read_json(run_b, "scorecard.json"),
        )

    def trend(self, target_id: str) -> list[TrendPoint]:
        """Per-run numbers for one target, oldest first. Empty when no run has findings
        for that target (the caller decides whether that is a 404)."""
        points: list[TrendPoint] = []
        for row in self.metadata_store.list_runs():
            findings = self._run_findings(row["run_id"])
            if findings is None:
                continue
            summary = self.artifact_store.read_json(row["run_id"], "run_summary.json") or {}
            declared = {str(t) for t in summary.get("targets") or []}
            mine = [f for f in findings if f.target_id == target_id]
            if not mine and target_id not in declared:
                continue
            per_target = build_scorecard(row["run_id"], mine)
            points.append(
                TrendPoint(
                    run_id=row["run_id"],
                    name=str(row.get("name", "")),
                    created_at=str(row.get("created_at", "")),
                    status=str(row.get("status", "")),
                    total_findings=per_target.total_findings,
                    critical=per_target.critical,
                    high=per_target.high,
                    critical_high=per_target.critical + per_target.high,
                    asr_overall=per_target.asr_overall,
                    success_count=per_target.success_count,
                    total_attacks=per_target.total_attacks,
                    eval_pass_rate_run=scorecard_eval_pass_rate(
                        self.artifact_store.read_json(row["run_id"], "scorecard.json")
                    ),
                )
            )
        points.sort(key=lambda point: point.created_at)
        return points

    def create_waiver(self, waiver_payload: dict[str, Any]) -> dict[str, Any]:
        from .types import WaiverRecord

        waiver = WaiverRecord(**waiver_payload)
        if parse_expiry(waiver.expires_at) is None:
            raise ValueError(f"expires_at must be an ISO-8601 timestamp, got {waiver.expires_at!r}")
        self.metadata_store.create_waiver(waiver)
        return self._with_active(asdict(waiver))

    def list_waivers(self, target_id: str | None = None) -> list[dict[str, Any]]:
        return self.metadata_store.list_waivers(target_id)

    @staticmethod
    def _with_active(waiver: dict[str, Any]) -> dict[str, Any]:
        return {**waiver, "active": waiver_is_active(waiver)}

    def get_waiver(self, waiver_id: str) -> dict[str, Any] | None:
        """One waiver with its `active` flag and append-only `events` history."""
        row = self.metadata_store.get_waiver(waiver_id)
        if row is None:
            return None
        return {**self._with_active(row), "events": self.metadata_store.list_waiver_events(waiver_id)}

    def update_waiver_expiry(self, waiver_id: str, expires_at: str) -> dict[str, Any] | None:
        if parse_expiry(expires_at) is None:
            raise ValueError(f"expires_at must be an ISO-8601 timestamp, got {expires_at!r}")
        row = self.metadata_store.update_waiver_expiry(waiver_id, expires_at, event="expiry_changed")
        return None if row is None else self._with_active(row)

    def revoke_waiver(self, waiver_id: str, *, note: str | None = None) -> dict[str, Any] | None:
        """Revoke = expire now, terminally. The row stays (append-only audit); the gate stops
        applying it; later expiry changes raise `WaiverRevokedError`."""
        row = self.metadata_store.update_waiver_expiry(waiver_id, self._utc_now(), event="revoked", note=note)
        return None if row is None else self._with_active(row)

    def waiver_preview(
        self,
        run_id: str,
        *,
        control_id: str,
        target_id: str,
    ) -> list[dict[str, Any]] | None:
        """Findings of `run_id` a waiver with these ids would match (same `control_matches`
        rules as the gate). None when the run has no findings file yet."""
        run = self.metadata_store.get_run(run_id)
        if not run:
            return None
        findings_path = run.get("findings_path")
        if not findings_path or not Path(findings_path).exists():
            return None
        matches = preview_matches(load_findings(findings_path), control_id=control_id, target_id=target_id)
        rows = [gate_finding_row(finding) for finding in matches]
        rows.sort(key=lambda row: (-SEVERITY_ORDER.get(str(row["severity"]).lower(), -1), str(row["finding_id"])))
        return rows
