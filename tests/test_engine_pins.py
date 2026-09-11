"""Engine CLI pins must be the same string across installers, templates, and CLI."""

from __future__ import annotations

from pathlib import Path

from urt.cli import _template_payload
from urt.engine_pins import (
    DEEPTEAM,
    DEEPTEAM_HELP_COMMAND,
    DEEPTEAM_PYTHON,
    GARAK,
    GARAK_PYTHON,
    GARAK_VERSION_COMMAND,
    GISKARD,
    GISKARD_PYTHON,
    GISKARD_VERSION_COMMAND,
    INSPECT_AI,
    INSPECT_AI_PYTHON,
    INSPECT_HELP_COMMAND,
    INSTALL_TOOLS,
    POWERPWN,
    POWERPWN_HELP_COMMAND,
    POWERPWN_PYTHON,
)

REPO = Path(__file__).resolve().parents[1]
STALE_PINS = (
    "garak==0.14.0",
    "deepteam==1.0.6",
    "inspect-ai==0.3.185",
    "giskard==2.19.1",
    "inspect-ai[dev]",
    "giskard==3.",
)
PIN_SURFACES = (
    REPO / "scripts" / "install_engine_tools_uv.sh",
    REPO / "scripts" / "verify_engine_tooling.sh",
    REPO / "templates" / "run_spec.sample.yaml",
    REPO / "templates" / "run_spec.promptfoo_dataset.sample.yaml",
    REPO / "README.md",
    REPO / "docs" / "consultant-onboarding.md",
)


def test_install_script_pins_match_module() -> None:
    text = (REPO / "scripts" / "install_engine_tools_uv.sh").read_text(encoding="utf-8")
    for package, python in INSTALL_TOOLS:
        assert f'"{package}|{python}"' in text
    assert f'"{POWERPWN}|{POWERPWN_PYTHON}"' in text
    assert GARAK_PYTHON == "3.12"
    assert POWERPWN_PYTHON == "3.11"
    assert DEEPTEAM_PYTHON == "3.12"
    assert INSPECT_AI_PYTHON == "3.12"
    assert "inspect-ai[dev]" not in text
    assert "giskard==" not in text


def test_verify_script_giskard_pin_matches_module() -> None:
    text = (REPO / "scripts" / "verify_engine_tooling.sh").read_text(encoding="utf-8")
    assert GISKARD_VERSION_COMMAND in text
    assert f"--python {GISKARD_PYTHON}" in text


def test_cli_template_commands_match_engine_pins() -> None:
    payload = _template_payload()
    commands = {
        item["name"]: item["params"]["command"]
        for item in payload["engines"]
        if "command" in item["params"]
    }
    assert commands["garak"] == GARAK_VERSION_COMMAND
    assert commands["powerpwn"] == POWERPWN_HELP_COMMAND
    assert commands["deepteam"] == DEEPTEAM_HELP_COMMAND
    assert commands["inspect"] == INSPECT_HELP_COMMAND
    assert commands["giskard"] == GISKARD_VERSION_COMMAND


def test_sample_spec_commands_match_engine_pins() -> None:
    text = (REPO / "templates" / "run_spec.sample.yaml").read_text(encoding="utf-8")
    assert GARAK_VERSION_COMMAND in text
    assert POWERPWN_HELP_COMMAND in text
    assert DEEPTEAM_HELP_COMMAND in text
    assert INSPECT_HELP_COMMAND in text
    assert GISKARD_VERSION_COMMAND in text


def test_readme_and_docs_use_current_pins() -> None:
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    docs = (REPO / "docs" / "consultant-onboarding.md").read_text(encoding="utf-8")
    assert DEEPTEAM in readme
    assert INSPECT_AI in readme
    assert GISKARD in readme
    assert GISKARD in docs
    assert "Node.js >= 22.22.0" in readme
    assert "pin Node 24" not in readme
    sample = (REPO / "templates" / "run_spec.promptfoo_dataset.sample.yaml").read_text(encoding="utf-8")
    assert "node@24" not in sample
    assert "/opt/homebrew" not in sample


def test_pin_surfaces_have_no_stale_engine_versions() -> None:
    for path in PIN_SURFACES:
        text = path.read_text(encoding="utf-8")
        for stale in STALE_PINS:
            assert stale not in text, f"{stale} still in {path}"
