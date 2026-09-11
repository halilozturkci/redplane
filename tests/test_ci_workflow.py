"""CI workflow contracts: lock check, pytest, and runtime import smokes."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _ci() -> dict:
    path = ROOT / ".github" / "workflows" / "ci.yml"
    assert path.is_file(), "CI workflow must exist"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_ci_workflow_runs_on_pull_request_and_main() -> None:
    on = _ci()["on"]
    assert "pull_request" in on
    push = on["push"]
    assert "main" in push["branches"]


def test_ci_workflow_uses_python_3_11_and_node_22_22() -> None:
    job = _ci()["jobs"]["test"]
    steps = job["steps"]
    uses = [step.get("uses", "") for step in steps]
    with_by_use = {step.get("uses", ""): step.get("with", {}) for step in steps}
    assert any(u.startswith("actions/setup-python@") for u in uses)
    assert any(u.startswith("actions/setup-node@") for u in uses)
    python_with = next(v for k, v in with_by_use.items() if k.startswith("actions/setup-python@"))
    node_with = next(v for k, v in with_by_use.items() if k.startswith("actions/setup-node@"))
    assert str(python_with["python-version"]).startswith("3.11")
    assert str(node_with["node-version"]).startswith("22.22")


def test_ci_workflow_checks_lock_pytest_and_runtime_imports() -> None:
    steps = _ci()["jobs"]["test"]["steps"]
    runs = "\n".join(step.get("run", "") for step in steps)
    assert "uv lock --check" in runs
    assert "uv sync --extra dev" in runs
    assert "uv run pytest" in runs
    assert "import azure.ai.evaluation" in runs
    assert ", openai," in runs
    assert "uv run urt --help" in runs
    assert "uv tool install" not in runs
    assert "install_engine_tools" not in runs
