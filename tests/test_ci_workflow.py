"""CI workflow contracts: lock check, pytest, and toolchain floors."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _ci() -> dict:
    path = ROOT / ".github" / "workflows" / "ci.yml"
    assert path.is_file(), "CI workflow must exist"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _pins() -> dict[str, str]:
    pins: dict[str, str] = {}
    for line in (ROOT / "scripts" / "toolchain_pins.env").read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        pins[key] = value
    return pins


def _named_runs() -> dict[str, str]:
    steps = _ci()["jobs"]["test"]["steps"]
    return {step["name"]: step["run"] for step in steps if "name" in step and "run" in step}


def test_ci_workflow_runs_on_pull_request_and_main() -> None:
    on = _ci()["on"]
    assert "pull_request" in on
    assert "main" in on["push"]["branches"]


def test_ci_workflow_binds_python_3_11_and_pinned_node() -> None:
    job = _ci()["jobs"]["test"]
    uv_step = next(step for step in job["steps"] if str(step.get("uses", "")).startswith("astral-sh/setup-uv@"))
    node_step = next(step for step in job["steps"] if str(step.get("uses", "")).startswith("actions/setup-node@"))
    assert uv_step["with"]["python-version"] == "3.11"
    assert node_step["with"]["node-version"] == _pins()["URT_NODE_MIN"]
    assert not any(str(step.get("uses", "")).startswith("actions/setup-python@") for step in job["steps"])


def test_ci_workflow_named_steps_match_the_gate() -> None:
    runs = _named_runs()
    assert runs["Assert Node floor"] == "bash -c 'source scripts/require_node.sh && require_urt_node'"
    assert runs["Check lockfile"] == "uv lock --check"
    assert runs["Install runtime and pytest"] == "uv sync --extra dev --frozen"
    assert runs["Unit tests"] == "uv run pytest"
    assert runs["CLI smoke"] == "uv run urt --help"
    joined = "\n".join(runs.values())
    assert "uv tool install" not in joined
    assert "--extra mcs" not in joined
    assert "install_engine_tools" not in joined
