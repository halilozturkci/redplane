"""Eval-after-attack sidecar is written before evaluator CLIs run."""

from __future__ import annotations

import json
from pathlib import Path

from urt.adapters.evaluator_base import EvalContext
from urt.orchestrator import Orchestrator
from urt.runtime import build_runtime_env
from urt.types import EngineRunResult, EvalRunResult, RunSpec, TargetSpec, UnifiedFinding


def _attack_finding(*, run_id: str, target_id: str) -> UnifiedFinding:
    return UnifiedFinding(
        finding_id=f"{run_id}:{target_id}:pyrit:attack:0",
        run_id=run_id,
        target_id=target_id,
        engine="pyrit",
        category="Violence",
        sub_category="prompt_attack",
        severity="high",
        confidence=0.9,
        attack_vector="PromptSending",
        attack_complexity="single_turn",
        success=True,
        description="PyRIT PromptSending attack succeeded for Violence",
    )


def test_orchestrator_writes_engine_findings_sidecar_for_evaluators(tmp_path: Path, monkeypatch) -> None:
    captured: dict[str, object] = {}

    class FakeEngine:
        name = "pyrit"

        def run(self, context):
            return EngineRunResult(
                engine="pyrit",
                target_id=context.target.target_id,
                status="completed",
                findings=[_attack_finding(run_id=context.run_id, target_id=context.target.target_id)],
                metrics={"total_attacks": 1, "successful_attacks": 1},
            )

    class FakeEvaluator:
        name = "custom_script"

        def evaluate(self, context: EvalContext):
            captured["engine_findings_path"] = context.engine_findings_path
            captured["engine_findings"] = list(context.engine_findings)
            captured["env"] = build_runtime_env(context)
            return EvalRunResult(
                evaluator="custom_script",
                target_id=context.target.target_id,
                status="completed",
            )

    monkeypatch.setattr("urt.orchestrator.create_engine_adapter", lambda _spec: FakeEngine())
    monkeypatch.setattr("urt.orchestrator.create_evaluator_adapter", lambda _spec: FakeEvaluator())

    spec = RunSpec.from_dict(
        {
            "name": "sidecar-run",
            "targets": [
                {
                    "id": "t1",
                    "type": "http",
                    "endpoint": "http://localhost/x",
                    "config": {"skip_healthcheck": True},
                }
            ],
            "engines": [{"name": "pyrit"}],
            "evaluators": [{"name": "custom_script", "params": {"command": "true"}}],
        }
    )
    orchestrator = Orchestrator(
        artifact_root=str(tmp_path / "art"),
        metadata_db=str(tmp_path / "db.sqlite"),
    )
    result = orchestrator.execute(spec)
    assert result["status"] == "completed"
    path = Path(str(captured["engine_findings_path"]))
    assert path.is_file()
    assert path.name == "t1_engine_findings.json"
    assert "custom_script" in path.as_posix()
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["schema"] == "urt.engine_findings.v1"
    assert payload["target_id"] == "t1"
    assert payload["engine_findings"][0]["success"] is True
    assert captured["env"]["URT_ENGINE_FINDINGS_PATH"] == str(path)


def test_eval_engine_findings_script_scores_sidecar_without_llm(tmp_path: Path) -> None:
    import subprocess
    import sys

    sidecar = tmp_path / "engine_findings.json"
    sidecar.write_text(
        json.dumps(
            {
                "schema": "urt.engine_findings.v1",
                "run_id": "run-1",
                "target_id": "t1",
                "engine_findings": [
                    {
                        "engine": "pyrit",
                        "category": "Violence",
                        "attack_vector": "PromptSending",
                        "success": True,
                    },
                    {
                        "engine": "pyrit",
                        "category": "HateUnfairness",
                        "attack_vector": "PromptSending",
                        "success": False,
                    },
                    {
                        "engine": "pyrit",
                        "category": "coverage_gap",
                        "attack_vector": "n/a",
                        "success": False,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "scores.json"
    script = Path(__file__).resolve().parents[1] / "scripts" / "eval_engine_findings.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--input", str(sidecar), "--output", str(output)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    by_metric = {item["metric"]: item for item in payload["scores"]}
    assert by_metric["refusal_rate"]["score"] == 0.5
    assert by_metric["attack_success_rate"]["score"] == 0.5
    assert by_metric["refusal_rate"]["passed"] is False
