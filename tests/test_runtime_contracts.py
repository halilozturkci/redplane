"""Tests for RunSpec runtime contracts that were previously schema-only."""

from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from urllib.error import HTTPError

from urt.adapters.engine_base import EngineContext
from urt.adapters.engines.garak_engine import GarakEngineAdapter
from urt.adapters.engines.promptfoo_engine import PromptfooEngineAdapter
from urt.adapters.targets.http_agent import HttpTargetAdapter
from urt.cli import main
from urt.config import load_run_spec
from urt.gateway.app import UniversalGateway, create_http_server
from urt.gateway.config import GatewayConfig
from urt.gateway.session_store import SessionEntry, SessionStore
from urt.orchestrator import Orchestrator
from urt.report import evaluate_gate
from urt.runtime import BudgetExceeded, BudgetTracker, build_runtime_env, limit_evidence_text
from urt.storage.artifact_store import ArtifactStore
from urt.types import (
    BudgetSpec,
    EngineRunResult,
    EngineSpec,
    EvalRunResult,
    RunSpec,
    TargetSpec,
    UnifiedFinding,
    ValidationError,
)


def _finding(**overrides) -> UnifiedFinding:
    payload = {
        "finding_id": "f1",
        "run_id": "r1",
        "target_id": "t1",
        "engine": "promptfoo",
        "category": "prompt_injection",
        "sub_category": "direct",
        "severity": "high",
        "confidence": 0.9,
        "attack_vector": "jailbreak",
        "attack_complexity": "easy",
        "success": True,
        "description": "attack",
        "mappings": {"owasp_llm": ["LLM01:2025 Prompt Injection"]},
    }
    payload.update(overrides)
    return UnifiedFinding(**payload)


def _engine_context(tmp_path: Path, **overrides) -> EngineContext:
    values = {
        "run_id": "run-1",
        "run_name": "test",
        "run_profile": "nightly",
        "target": TargetSpec.from_dict({"id": "t-1", "type": "http", "config": {"skip_healthcheck": True}}),
        "artifact_store": ArtifactStore(tmp_path / "artifacts"),
        "timeout_seconds": 30,
        "seed": 42,
        "evidence_level": "minimal",
        "enabled_scenarios": ["prompt_injection"],
    }
    values.update(overrides)
    return EngineContext(**values)


def test_profile_defaults_apply_when_budget_omitted():
    spec = RunSpec.from_dict(
        {
            "name": "profile-run",
            "run_profile": "pr_gate",
            "targets": [{"id": "t1", "type": "http", "endpoint": "http://localhost/x"}],
            "engines": [{"name": "promptfoo"}],
        }
    )
    assert spec.budget.max_duration_seconds == 900
    assert spec.timeouts.engine_seconds == 600
    assert spec.timeouts.connect_seconds == 5


def test_explicit_budget_overrides_profile_defaults():
    spec = RunSpec.from_dict(
        {
            "name": "profile-run",
            "run_profile": "pr_gate",
            "targets": [{"id": "t1", "type": "http", "endpoint": "http://localhost/x"}],
            "engines": [{"name": "promptfoo"}],
            "budget": {"max_duration_seconds": 12, "max_cost_usd": 3.5},
        }
    )
    assert spec.budget.max_duration_seconds == 12
    assert spec.budget.max_cost_usd == 3.5
    assert spec.timeouts.engine_seconds == 600


def test_evidence_level_rejects_unknown_values():
    with pytest.raises(ValidationError, match="evidence_level"):
        RunSpec.from_dict(
            {
                "name": "bad",
                "targets": [{"id": "t1", "type": "http", "endpoint": "http://localhost/x"}],
                "engines": [{"name": "promptfoo"}],
                "evidence_level": "verbose",
            }
        )


def test_load_run_spec_expands_env(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("URT_TEST_ENDPOINT", "http://expanded.example/invoke")
    spec_path = tmp_path / "spec.yaml"
    spec_path.write_text(
        "name: env-run\n"
        "targets:\n"
        "  - id: t1\n"
        "    type: http\n"
        "    endpoint: ${URT_TEST_ENDPOINT}\n"
        "engines:\n"
        "  - name: promptfoo\n",
        encoding="utf-8",
    )
    spec = load_run_spec(spec_path)
    assert spec.targets[0].endpoint == "http://expanded.example/invoke"


def test_budget_duration_and_cost_enforcement():
    tracker = BudgetTracker(BudgetSpec(max_duration_seconds=1, max_cost_usd=1.0))
    tracker.started -= 5
    with pytest.raises(BudgetExceeded, match="duration"):
        tracker.check(stage="unit")

    cost_tracker = BudgetTracker(BudgetSpec(max_duration_seconds=60, max_cost_usd=1.0))
    cost_tracker.observe_metrics({"cost_usd": 2.25})
    with pytest.raises(BudgetExceeded, match="cost"):
        cost_tracker.check(stage="unit")

    unmetered = BudgetTracker(BudgetSpec(max_duration_seconds=60, max_cost_usd=1.0))
    unmetered.check(stage="unit")
    assert unmetered.snapshot()["cost_enforcement"] == "unmetered"


def test_limit_evidence_text_truncates_minimal():
    text = "x" * 20_000
    clipped = limit_evidence_text(text, "minimal")
    assert len(clipped) < len(text)
    assert clipped.endswith("[TRUNCATED]")
    assert limit_evidence_text(text, "full") == text


def test_build_runtime_env_includes_seed_and_scenarios(tmp_path: Path):
    env = build_runtime_env(_engine_context(tmp_path))
    assert env["URT_SEED"] == "42"
    assert env["PYTHONHASHSEED"] == "42"
    assert env["URT_ENABLED_SCENARIOS"] == "prompt_injection"
    assert env["URT_EVIDENCE_LEVEL"] == "minimal"


def test_gate_honors_active_waivers():
    finding = _finding()
    expired = datetime.now(timezone.utc) - timedelta(days=1)
    future = datetime.now(timezone.utc) + timedelta(days=7)
    ok, message = evaluate_gate(
        [finding],
        "high",
        waivers=[
            {
                "target_id": "t1",
                "control_id": "LLM01:2025",
                "expires_at": future.isoformat(),
            }
        ],
    )
    assert ok is True
    assert "waived" in message

    failed, _ = evaluate_gate(
        [finding],
        "high",
        waivers=[
            {
                "target_id": "t1",
                "control_id": "LLM01:2025",
                "expires_at": expired.isoformat(),
            }
        ],
    )
    assert failed is False


def test_promptfoo_enabled_scenarios_filters_rows(tmp_path: Path):
    source = tmp_path / "rows.jsonl"
    source.write_text(
        json.dumps({"attack_prompt": "inj", "category": "prompt_injection"})
        + "\n"
        + json.dumps({"attack_prompt": "other", "category": "data_exfiltration"})
        + "\n",
        encoding="utf-8",
    )
    adapter = PromptfooEngineAdapter(
        EngineSpec.from_dict({"name": "promptfoo", "enabled_scenarios": ["prompt_injection"]})
    )
    prompts = adapter._load_prompts_from_file(source, field_name="attack_prompt", scenarios=["prompt_injection"])
    assert prompts == ["inj"]


def test_command_engine_injects_runtime_env(tmp_path: Path, monkeypatch):
    captured: dict[str, object] = {}

    def fake_run(command, **kwargs):
        captured["env"] = kwargs["env"]
        return SimpleNamespace(returncode=0, stdout="ok-stdout", stderr="")

    monkeypatch.setattr("urt.adapters.engines._command.subprocess.run", fake_run)
    adapter = GarakEngineAdapter(EngineSpec.from_dict({"name": "garak", "params": {"command": ["garak", "--version"]}}))
    context = _engine_context(tmp_path)
    result = adapter._result_from_command(context, ["garak", "--version"], artifact_name_prefix="garak")
    assert result.status == "completed"
    env = captured["env"]
    assert env["URT_SEED"] == "42"
    assert env["URT_ENABLED_SCENARIOS"] == "prompt_injection"
    stdout = Path(result.artifacts[0]).read_text(encoding="utf-8")
    assert stdout == "ok-stdout"


def test_http_target_uses_run_timeouts_and_rate_limits():
    adapter = HttpTargetAdapter(
        TargetSpec.from_dict(
            {
                "id": "t1",
                "type": "http",
                "endpoint": "http://example.test/invoke",
                "rate_limits": {"min_interval_seconds": 0.05},
            }
        )
    )
    adapter.apply_runtime(connect_seconds=3, request_seconds=7)
    assert adapter.connect_timeout_seconds == 3
    assert adapter.request_timeout_seconds == 7

    class DummyResp:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b'{"content":"ok"}'

    with patch("urt.adapters.targets.http_agent.request.urlopen", return_value=DummyResp()) as mocked:
        adapter.send("sess", [{"role": "user", "content": "hi"}])
        adapter.send("sess", [{"role": "user", "content": "hi"}])
        assert mocked.call_count == 2
        assert mocked.call_args.kwargs["timeout"] == 7


def test_orchestrator_evaluator_fail_open_and_engine_results(tmp_path: Path):
    captured: dict[str, object] = {}

    class OkEngine:
        name = "promptfoo"

        def run(self, context):
            return EngineRunResult(
                engine="promptfoo",
                target_id=context.target.target_id,
                status="completed",
                metrics={"executed": True},
            )

    class BoomEval:
        name = "custom_script"

        def evaluate(self, context):
            captured["engine_results"] = list(context.engine_results)
            return EvalRunResult(
                evaluator="custom_script",
                target_id=context.target.target_id,
                status="failed",
                message="boom",
            )

    spec = RunSpec.from_dict(
        {
            "name": "eval-fail",
            "targets": [{"id": "local", "type": "http", "endpoint": "http://localhost/x", "config": {"skip_healthcheck": True}}],
            "engines": [{"name": "promptfoo"}],
            "evaluators": [{"name": "custom_script", "fail_open": False}],
        }
    )
    orchestrator = Orchestrator(artifact_root=str(tmp_path / "art"), metadata_db=str(tmp_path / "db.sqlite"))
    with patch("urt.orchestrator.create_engine_adapter", return_value=OkEngine()), patch(
        "urt.orchestrator.create_evaluator_adapter", return_value=BoomEval()
    ):
        result = orchestrator.execute(spec)
    assert result["status"] == "failed"
    assert "fail_open=false" in result["error"]
    assert captured["engine_results"]
    assert captured["engine_results"][0].engine == "promptfoo"


def test_orchestrator_enforces_reported_cost_budget(tmp_path: Path):
    class CostlyEngine:
        name = "promptfoo"

        def run(self, context):
            return EngineRunResult(
                engine="promptfoo",
                target_id=context.target.target_id,
                status="completed",
                metrics={"cost_usd": 9.5},
            )

    spec = RunSpec.from_dict(
        {
            "name": "cost-run",
            "targets": [{"id": "local", "type": "http", "endpoint": "http://localhost/x", "config": {"skip_healthcheck": True}}],
            "engines": [{"name": "promptfoo"}],
            "budget": {"max_duration_seconds": 60, "max_cost_usd": 1.0},
        }
    )
    orchestrator = Orchestrator(artifact_root=str(tmp_path / "art"), metadata_db=str(tmp_path / "db.sqlite"))
    with patch("urt.orchestrator.create_engine_adapter", return_value=CostlyEngine()):
        result = orchestrator.execute(spec)
    assert result["status"] == "failed"
    assert "reported cost" in result["error"]


def test_init_template_includes_evaluators(tmp_path: Path):
    output = tmp_path / "run_spec.yaml"
    assert main(["init", "--output", str(output)]) == 0
    spec = load_run_spec(output)
    names = [item.name for item in spec.evaluators]
    assert names == [
        "deepeval",
        "promptfoo_eval",
        "giskard_eval",
        "inspect_eval",
        "azure_ai_eval",
        "custom_script",
    ]


def test_cli_waivers_create_and_gate(tmp_path: Path):
    artifact_root = tmp_path / "art"
    metadata_db = tmp_path / "meta.sqlite3"
    orchestrator = Orchestrator(artifact_root=str(artifact_root), metadata_db=str(metadata_db))
    spec = RunSpec.from_dict(
        {
            "name": "waiver-run",
            "targets": [{"id": "t1", "type": "http", "endpoint": "http://localhost/x", "config": {"skip_healthcheck": True}}],
            "engines": [{"name": "promptfoo", "params": {"command": ["true"]}}],
        }
    )
    with patch("urt.orchestrator.create_engine_adapter") as mocked:
        class HighFindingEngine:
            name = "promptfoo"

            def run(self, context):
                return EngineRunResult(
                    engine="promptfoo",
                    target_id=context.target.target_id,
                    status="completed",
                    findings=[_finding(run_id=context.run_id, target_id=context.target.target_id)],
                )

        mocked.return_value = HighFindingEngine()
        result = orchestrator.execute(spec)
    run_id = result["run_id"]
    expires = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
    assert (
        main(
            [
                "--artifact-root",
                str(artifact_root),
                "--metadata-db",
                str(metadata_db),
                "waivers",
                "create",
                "--target-id",
                "t1",
                "--control-id",
                "LLM01:2025",
                "--reason",
                "accepted",
                "--owner",
                "secops",
                "--expires-at",
                expires,
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "--artifact-root",
                str(artifact_root),
                "--metadata-db",
                str(metadata_db),
                "gate",
                "--run-id",
                run_id,
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "--artifact-root",
                str(artifact_root),
                "--metadata-db",
                str(metadata_db),
                "gate",
                "--run-id",
                run_id,
                "--ignore-waivers",
            ]
        )
        == 2
    )


def test_session_store_persists_thread_ids(tmp_path: Path):
    persist = tmp_path / "sessions.json"
    store = SessionStore(ttl_seconds=60, persist_path=persist)
    store.put("sess-1", SessionEntry(client=object(), thread_id="thread-abc"))
    restored = SessionStore(ttl_seconds=60, persist_path=persist)
    entry = restored.get("sess-1")
    assert entry is not None
    assert entry.thread_id == "thread-abc"
    assert entry.client is None


def test_gateway_api_key_rejects_unauthorized(tmp_path: Path):
    import json as json_lib
    import threading
    from urllib import request

    cfg = GatewayConfig.from_dict(
        {
            "gateway": {"host": "127.0.0.1", "port": 0, "api_key": "secret-key"},
            "routing": {"mode": "header", "default_target": "demo"},
            "audit": {"artifact_root": str(tmp_path / "gw")},
            "targets": {
                "demo": {
                    "connector": "generic_http_json",
                    "endpoint": "http://127.0.0.1:9/invoke",
                }
            },
        }
    )
    gateway = UniversalGateway(cfg)
    server = create_http_server(gateway)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        payload = json_lib.dumps({"messages": [{"role": "user", "content": "hi"}]}).encode("utf-8")
        req = request.Request(
            url=f"http://127.0.0.1:{port}/v1/chat/completions",
            method="POST",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with pytest.raises(HTTPError) as exc:
            request.urlopen(req, timeout=5)
        assert exc.value.code == 401
    finally:
        server.shutdown()
        thread.join(timeout=5)
