"""Packaging and installer contracts for the runtime lock / Promptfoo / MCS slice."""

from __future__ import annotations

import os
import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _pyproject() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def _runtime_deps() -> list[str]:
    return list(_pyproject()["project"]["dependencies"])


def test_runtime_does_not_depend_on_azure_ai_projects() -> None:
    assert all("azure-ai-projects" not in dep for dep in _runtime_deps())


def test_openai_is_capped_below_v3() -> None:
    openai_deps = [dep for dep in _runtime_deps() if dep.startswith("openai")]
    assert openai_deps == ["openai>=2.2,<3"]


def test_azure_ai_evaluation_floor_includes_redteam_extra() -> None:
    matches = [dep for dep in _runtime_deps() if dep.startswith("azure-ai-evaluation")]
    assert matches == ["azure-ai-evaluation[redteam]>=1.18.0"]


def test_mcs_extra_is_declared_for_follow_up_pin() -> None:
    extras = _pyproject()["project"]["optional-dependencies"]
    assert "mcs" in extras
    assert extras["mcs"] == []
    assert "pytest>=8.0.0" in extras["dev"]


def test_uv_lock_is_committed_and_omits_azure_ai_projects() -> None:
    lock_path = ROOT / "uv.lock"
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert lock_path.is_file(), "uv.lock must be committed"
    assert "\nuv.lock\n" not in f"\n{gitignore}"
    lock_text = lock_path.read_text(encoding="utf-8")
    assert "azure-ai-projects" not in lock_text
    assert 'name = "openai"' in lock_text


def test_promptfoo_installer_pins_0_123_0_and_requires_node_22_22() -> None:
    script = (ROOT / "scripts" / "install_promptfoo_local.sh").read_text(encoding="utf-8")
    helper = (ROOT / "scripts" / "require_node_22_22.sh").read_text(encoding="utf-8")
    assert 'PROMPTFOO_PACKAGE="${PROMPTFOO_PACKAGE:-promptfoo@0.123.0}"' in script
    assert "require_node_22_22.sh" in script
    assert "22.22" in helper
    assert "promptfoo@latest" not in script
    assert "Node.js 20+" not in script


def test_bootstrap_requires_node_22_22() -> None:
    script = (ROOT / "scripts" / "bootstrap_uv.sh").read_text(encoding="utf-8")
    assert "require_node_22_22.sh" in script
    assert "22.22" in script
    assert "Node.js 20+" not in script


def test_mcs_preview_install_is_opt_in(tmp_path: Path) -> None:
    env = os.environ.copy()
    env.pop("URT_INSTALL_MCS_PREVIEW", None)
    env.pop("URT_SKIP_MCS_PREVIEW", None)
    env["HOME"] = str(tmp_path)
    result = subprocess.run(
        ["bash", str(ROOT / "scripts" / "install_mcs_preview_packages.sh")],
        check=False,
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        env=env,
    )
    assert result.returncode == 0
    combined = f"{result.stdout}\n{result.stderr}"
    assert "opt-in" in combined.lower() or "URT_INSTALL_MCS_PREVIEW" in combined
    assert "Installing Microsoft Copilot Studio preview packages" not in result.stdout


def test_promptfoo_dataset_sample_has_no_machine_specific_node_path() -> None:
    sample = (ROOT / "templates" / "run_spec.promptfoo_dataset.sample.yaml").read_text(
        encoding="utf-8"
    )
    assert "/opt/homebrew" not in sample
    assert "node@24" not in sample
