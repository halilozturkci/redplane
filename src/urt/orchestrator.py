"""Run orchestration for Redplane."""

from __future__ import annotations

import json
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
    DEFAULT_METADATA_DB,
    RUN_PROFILE_DEFAULTS,
    SEVERITY_ORDER,
)
from .normalization import build_scorecard, normalize_findings
from .redaction import redact_run_spec_payload
from .report import GateResult, gate_result, load_findings, render_csv, render_html, render_markdown
from .runtime import BudgetTracker
from .storage import ArtifactStore, MetadataStore
from .types import EngineRunResult, EvalRunResult, RunRecord, RunSpec, UnifiedFinding


class Orchestrator:
    """Coordinates run execution across targets and engines."""

    def __init__(
        self,
        *,
        artifact_root: str = DEFAULT_ARTIFACT_ROOT,
        metadata_db: str = DEFAULT_METADATA_DB,
    ):
        self.artifact_store = ArtifactStore(artifact_root)
        self.metadata_store = MetadataStore(metadata_db)

    @staticmethod
    def _utc_now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _new_run_id(spec: RunSpec) -> str:
        slug = spec.name.lower().replace(" ", "-")
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        return f"run-{slug}-{ts}-{uuid.uuid4().hex[:8]}"

    def execute(self, spec: RunSpec) -> dict[str, Any]:
        run_id = self._new_run_id(spec)
        now = self._utc_now()
        run_record = RunRecord(
            run_id=run_id,
            name=spec.name,
            profile=spec.run_profile,
            status="running",
            created_at=now,
            updated_at=now,
        )
        self.metadata_store.create_run(run_record)
        # The in-memory spec holds expanded `${VAR}` credentials; the bundle must not.
        redacted_spec = redact_run_spec_payload(spec.to_dict())
        self.artifact_store.write_json(run_id, "resolved_spec.json", redacted_spec)

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
                        budget.check(stage=f"before engine {engine_spec.name} on {target_spec.target_id}")
                        engine_adapter = create_engine_adapter(engine_spec)
                        context = EngineContext(
                            run_id=run_id,
                            run_name=spec.name,
                            run_profile=spec.run_profile,
                            target=target_spec,
                            artifact_store=self.artifact_store,
                            timeout_seconds=spec.timeouts.engine_seconds,
                            seed=spec.seed,
                            evidence_level=spec.evidence_level,
                            enabled_scenarios=list(engine_spec.enabled_scenarios),
                            connect_seconds=spec.timeouts.connect_seconds,
                            request_seconds=spec.timeouts.request_seconds,
                        )

                        invocation_started = perf_counter()
                        invocation_started_at = self._utc_now()
                        result = self._safe_run_engine(engine_adapter, context)
                        invocation_duration = perf_counter() - invocation_started
                        invocation_ended_at = self._utc_now()
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

                        if result.status in {"failed"} and not engine_spec.fail_open:
                            raise RuntimeError(
                                f"Engine {engine_spec.name} failed on target {target_spec.target_id} with fail_open=false"
                            )

                    # Run evaluators after all engines for this target
                    target_findings = [f for f in all_findings if f.target_id == target_spec.target_id]

                    for evaluator_spec in spec.evaluators:
                        budget.check(
                            stage=f"before evaluator {evaluator_spec.name} on {target_spec.target_id}"
                        )
                        evaluator_adapter = create_evaluator_adapter(evaluator_spec)
                        sidecar_path = self._write_engine_findings_sidecar(
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
                            artifact_store=self.artifact_store,
                            timeout_seconds=spec.timeouts.engine_seconds,
                            seed=spec.seed,
                            engine_findings=target_findings,
                            engine_results=list(target_engine_results),
                            evidence_level=spec.evidence_level,
                            enabled_scenarios=[],
                            run_profile=spec.run_profile,
                            engine_findings_path=sidecar_path,
                        )
                        eval_result = self._safe_run_evaluator(evaluator_adapter, eval_context)
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

            normalized = normalize_findings(all_findings, policy_profiles=spec.policy_profiles)
            scorecard = build_scorecard(run_id, normalized, eval_results=all_eval_results or None)

            findings_path = self.artifact_store.write_json(
                run_id,
                "findings.json",
                [f.to_dict() for f in normalized],
            )
            scorecard_path = self.artifact_store.write_json(
                run_id,
                "scorecard.json",
                scorecard.to_dict(),
            )
            run_summary_path = self.artifact_store.write_json(
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
            self.artifact_store.write_json(run_id, "engine_invocations.json", engine_invocations)

            markdown = render_markdown(scorecard.to_dict(), [f.to_dict() for f in normalized])
            html = render_html(scorecard.to_dict(), [f.to_dict() for f in normalized])
            csv_text = render_csv([f.to_dict() for f in normalized])
            report_md_path = self.artifact_store.write_text(run_id, "report.md", markdown)
            report_html_path = self.artifact_store.write_text(run_id, "report.html", html)
            report_csv_path = self.artifact_store.write_text(run_id, "report.csv", csv_text)

            run_duration = perf_counter() - run_started
            run_manifest = {
                "run_id": run_id,
                "name": spec.name,
                "run_profile": spec.run_profile,
                "status": "completed",
                "created_at": now,
                "completed_at": self._utc_now(),
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
                "report_paths": {
                    "markdown": report_md_path,
                    "html": report_html_path,
                    "csv": report_csv_path,
                },
            }
            self.artifact_store.write_json(run_id, "run_manifest.json", run_manifest)

            run_root = self.artifact_store.run_dir(run_id)
            artifacts_index = build_artifacts_index(run_root)
            artifacts_index_path = self.artifact_store.write_json(run_id, "artifacts_index.json", artifacts_index)
            artifacts_index = build_artifacts_index(run_root)
            artifacts_index_path = self.artifact_store.write_json(run_id, "artifacts_index.json", artifacts_index)

            self.metadata_store.insert_findings(normalized)
            self.metadata_store.update_run(
                run_id,
                status="completed",
                updated_at=self._utc_now(),
                scorecard_path=scorecard_path,
                findings_path=findings_path,
            )

            return {
                "run_id": run_id,
                "status": "completed",
                "scorecard": scorecard.to_dict(),
                "scorecard_path": scorecard_path,
                "findings_path": findings_path,
                "summary_path": run_summary_path,
                "manifest_path": str(run_root / "run_manifest.json"),
                "artifacts_index_path": artifacts_index_path,
                "engine_summaries": engine_summaries,
            }

        except Exception as exc:  # noqa: BLE001
            error_trace = traceback.format_exc()
            error_path = self.artifact_store.write_text(run_id, "run_error.log", error_trace)
            self.metadata_store.update_run(
                run_id,
                status="failed",
                updated_at=self._utc_now(),
                error_message=str(exc),
            )
            self.artifact_store.write_json(
                run_id,
                "run_manifest.json",
                {
                    "run_id": run_id,
                    "name": spec.name,
                    "run_profile": spec.run_profile,
                    "status": "failed",
                    "created_at": now,
                    "failed_at": self._utc_now(),
                    "bundle_format_version": BUNDLE_FORMAT_VERSION,
                    "error": str(exc),
                    "target_probe_results": target_probe_results,
                    "engine_invocations": engine_invocations,
                    "budget": budget.snapshot(),
                },
            )
            return {
                "run_id": run_id,
                "status": "failed",
                "error": str(exc),
                "error_log_path": error_path,
            }

    def _write_engine_findings_sidecar(
        self,
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
        return self.artifact_store.write_json(
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
        return self.metadata_store.get_run(run_id)

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

        enriched = dict(row)
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
        profile_defaults = RUN_PROFILE_DEFAULTS.get(row.get("profile", ""), RUN_PROFILE_DEFAULTS["nightly"])
        effective = (threshold or profile_defaults.get("gate_threshold", "high")).lower()
        result = gate_result(load_findings(findings_path), threshold=effective, waivers=waivers)
        return {
            "threshold": effective,
            "ok": result.ok,
            "blocking_count": len(result.blocking),
            "waived_count": len(result.waived),
        }

    def get_findings(self, run_id: str) -> list[dict[str, Any]]:
        findings = self.metadata_store.get_findings(run_id)
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
        return self.artifact_store.read_json(run_id, file_name)

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
        return gate_result(findings, threshold=threshold, waivers=waivers)

    def create_waiver(self, waiver_payload: dict[str, Any]) -> dict[str, Any]:
        from .types import WaiverRecord

        waiver = WaiverRecord(**waiver_payload)
        self.metadata_store.create_waiver(waiver)
        return asdict(waiver)

    def list_waivers(self, target_id: str | None = None) -> list[dict[str, Any]]:
        return self.metadata_store.list_waivers(target_id)
