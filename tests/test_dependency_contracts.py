"""Packaging and installer contracts for the runtime lock / Promptfoo / MCS slice."""

from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _pyproject() -> dict:
    import tomllib

    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def _runtime_deps() -> list[str]:
    return list(_pyproject()["project"]["dependencies"])


def _pins() -> dict[str, str]:
    pins: dict[str, str] = {}
    for line in (ROOT / "scripts" / "toolchain_pins.env").read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        pins[key] = value
    return pins


def _write_fake_node(path: Path, version: str) -> None:
    path.write_text(f"#!/bin/sh\necho v{version}\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def test_runtime_does_not_depend_on_azure_ai_projects() -> None:
    assert all("azure-ai-projects" not in dep for dep in _runtime_deps())


def test_openai_is_capped_below_v3() -> None:
    openai_deps = [dep for dep in _runtime_deps() if dep.startswith("openai")]
    assert openai_deps == ["openai>=2.2,<3"]


def test_azure_ai_evaluation_floor_includes_redteam_extra() -> None:
    matches = [dep for dep in _runtime_deps() if dep.startswith("azure-ai-evaluation")]
    assert matches == ["azure-ai-evaluation[redteam]>=1.18.0"]


def test_uv_lock_is_committed_with_openai_2x() -> None:
    lock_path = ROOT / "uv.lock"
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert lock_path.is_file(), "uv.lock must be committed"
    assert "\nuv.lock\n" not in f"\n{gitignore}"
    lock_text = lock_path.read_text(encoding="utf-8")
    assert "azure-ai-projects" not in lock_text
    match = re.search(r'(?m)^name = "openai"\nversion = "([^"]+)"', lock_text)
    assert match is not None
    assert match.group(1).startswith("2."), match.group(1)


def test_toolchain_pins_are_node_22_22_and_promptfoo_0_123_0() -> None:
    pins = _pins()
    assert pins["URT_NODE_MIN"] == "22.22.0"
    assert pins["URT_PROMPTFOO_PACKAGE"] == "promptfoo@0.123.0"


def test_promptfoo_installer_uses_shared_pins() -> None:
    script = (ROOT / "scripts" / "install_promptfoo_local.sh").read_text(encoding="utf-8")
    assert "require_node.sh" in script
    assert "URT_PROMPTFOO_PACKAGE" in script
    assert "promptfoo@latest" not in script
    assert "Node.js 20+" not in script


def test_bootstrap_uses_shared_node_gate() -> None:
    script = (ROOT / "scripts" / "bootstrap_uv.sh").read_text(encoding="utf-8")
    assert "require_node.sh" in script
    assert "require_urt_node" in script
    assert "Node.js 20+" not in script


def test_require_node_rejects_below_floor(tmp_path: Path) -> None:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    _write_fake_node(bindir / "node", "22.14.0")
    env = os.environ.copy()
    env["PATH"] = f"{bindir}{os.pathsep}{env.get('PATH', '')}"
    result = subprocess.run(
        ["bash", "-c", f"source '{ROOT / 'scripts' / 'require_node.sh'}' && require_urt_node"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 1
    combined = f"{result.stdout}\n{result.stderr}"
    assert "22.14.0" in combined
    assert "22.22.0" in combined


def test_require_node_accepts_floor(tmp_path: Path) -> None:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    _write_fake_node(bindir / "node", "22.22.0")
    env = os.environ.copy()
    env["PATH"] = f"{bindir}{os.pathsep}{env.get('PATH', '')}"
    result = subprocess.run(
        ["bash", "-c", f"source '{ROOT / 'scripts' / 'require_node.sh'}' && require_urt_node"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_mcs_extra_pins_ga_client() -> None:
    extras = _pyproject()["project"]["optional-dependencies"]
    assert extras["mcs"] == ["microsoft-agents-copilotstudio-client==1.5.0"]
    assert extras["dev"] == ["pytest>=8.0.0"]


def test_uv_lock_pins_mcs_ga_client_1_5_0() -> None:
    lock_text = (ROOT / "uv.lock").read_text(encoding="utf-8")
    match = re.search(
        r'(?m)^name = "microsoft-agents-copilotstudio-client"\nversion = "([^"]+)"',
        lock_text,
    )
    assert match is not None
    assert match.group(1) == "1.5.0"


def test_testpypi_mcs_preview_script_is_removed() -> None:
    assert not (ROOT / "scripts" / "install_mcs_preview_packages.sh").exists()
    bootstrap = (ROOT / "scripts" / "bootstrap_uv.sh").read_text(encoding="utf-8")
    assert "uv sync --extra mcs" in bootstrap
    assert "URT_INSTALL_MCS_PREVIEW" not in bootstrap
    assert "test.pypi.org" not in bootstrap


def test_copilot_client_imports_ga_module_path() -> None:
    source = (ROOT / "src" / "urt" / "integrations" / "mcs_pyrit" / "copilot_client.py").read_text(
        encoding="utf-8"
    )
    assert "from microsoft_agents.copilotstudio.client import (" in source
    assert "ConnectionSettings" in source
    assert "CopilotClient" in source
    assert "PowerPlatformCloud" in source
    assert "AgentType" in source


def test_promptfoo_dataset_sample_has_no_machine_specific_node_path() -> None:
    sample = (ROOT / "templates" / "run_spec.promptfoo_dataset.sample.yaml").read_text(
        encoding="utf-8"
    )
    assert "/opt/homebrew" not in sample
    assert "node@24" not in sample
