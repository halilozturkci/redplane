"""Engine CLI pins must match across installers, templates, and ``urt init``."""

from __future__ import annotations

import re
from pathlib import Path

from urt.cli import _template_payload
from urt.engine_pins import ENGINE_PINS, PIN_BY_PACKAGE, pin

REPO = Path(__file__).resolve().parents[1]
PIN_SURFACES = (
    REPO / "scripts" / "install_engine_tools_uv.sh",
    REPO / "scripts" / "verify_engine_tooling.sh",
    REPO / "templates" / "run_spec.sample.yaml",
    REPO / "templates" / "run_spec.promptfoo_dataset.sample.yaml",
    REPO / "README.md",
    REPO / "docs" / "consultant-onboarding.md",
)
_SPEC_RE = re.compile(r"(garak|powerpwn|deepteam|inspect-ai|giskard)==(\d+(?:\.\d+)*)")
_INSTALL_ROW_RE = re.compile(r'"((?:garak|powerpwn|deepteam|inspect-ai)==[^"|]+)\|([^"]+)"')
_FORBIDDEN = ("inspect-ai[dev]",)


def test_install_script_rows_match_uv_tool_pins() -> None:
    text = (REPO / "scripts" / "install_engine_tools_uv.sh").read_text(encoding="utf-8")
    found = set(_INSTALL_ROW_RE.findall(text))
    expected = {(item.spec, item.python) for item in ENGINE_PINS if item.uv_tool}
    assert found == expected
    assert pin("powerpwn").python == "3.11"
    assert "giskard==" not in text
    for token in _FORBIDDEN:
        assert token not in text


def test_cli_template_commands_use_install_script_specs() -> None:
    install_text = (REPO / "scripts" / "install_engine_tools_uv.sh").read_text(encoding="utf-8")
    install_specs = {spec for spec, _python in _INSTALL_ROW_RE.findall(install_text)}
    payload = _template_payload()
    commands = {
        item["name"]: item["params"]["command"]
        for item in payload["engines"]
        if "command" in item["params"]
    }
    for spec in install_specs:
        assert any(spec in command for command in commands.values()), spec
    assert commands["garak"] == pin("garak").uvx_command
    assert commands["powerpwn"] == pin("powerpwn").uvx_command
    assert commands["deepteam"] == pin("deepteam").uvx_command
    assert commands["inspect"] == pin("inspect-ai").uvx_command
    assert commands["giskard"] == pin("giskard").uvx_command


def test_sample_spec_commands_match_pin_table() -> None:
    text = (REPO / "templates" / "run_spec.sample.yaml").read_text(encoding="utf-8")
    for item in ENGINE_PINS:
        assert item.uvx_command in text


def test_verify_script_includes_pin_literals() -> None:
    text = (REPO / "scripts" / "verify_engine_tooling.sh").read_text(encoding="utf-8")
    for item in ENGINE_PINS:
        assert item.spec in text
    assert pin("giskard").uvx_command in text


def test_surfaces_only_use_canonical_pin_versions() -> None:
    for path in PIN_SURFACES:
        text = path.read_text(encoding="utf-8")
        for package, version in _SPEC_RE.findall(text):
            assert version == PIN_BY_PACKAGE[package].version, f"{package}=={version} in {path}"
        for token in _FORBIDDEN:
            assert token not in text, f"{token} in {path}"


def test_readme_node_contract_and_docs_pins() -> None:
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    docs = (REPO / "docs" / "consultant-onboarding.md").read_text(encoding="utf-8")
    assert "Node.js >= 22.22.0" in readme
    assert "pin Node 24" not in readme
    assert pin("deepteam").spec in readme
    assert pin("inspect-ai").spec in readme
    assert pin("giskard").spec in readme
    assert pin("giskard").spec in docs
    sample = (REPO / "templates" / "run_spec.promptfoo_dataset.sample.yaml").read_text(encoding="utf-8")
    assert "node@24" not in sample
    assert "/opt/homebrew" not in sample
