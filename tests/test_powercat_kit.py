"""Power CAT Kit identity: no invented npm name, GitHub is canonical."""

from __future__ import annotations

from pathlib import Path

from urt.cli import _template_payload
from urt.powercat_kit import (
    DEFAULT_COMMAND,
    DEPRECATED_NPM_PACKAGE,
    GITHUB_REPO,
    command_uses_deprecated_npm,
    command_uses_github_npx_kit,
    skip_reason_for_command,
)

REPO = Path(__file__).resolve().parents[1]
DEFAULT_COMMAND_SURFACES = (
    REPO / "src" / "urt" / "cli.py",
    REPO / "templates" / "run_spec.sample.yaml",
)


def test_default_command_is_native_launcher() -> None:
    assert DEFAULT_COMMAND == "copilot-studio-kit agent-review run"
    payload = _template_payload()
    engine_commands = {
        item["name"]: item["params"]["command"]
        for item in payload["engines"]
        if "command" in item["params"]
    }
    assert engine_commands["powercat"] == DEFAULT_COMMAND
    sample = (REPO / "templates" / "run_spec.sample.yaml").read_text(encoding="utf-8")
    assert DEFAULT_COMMAND in sample


def test_default_surfaces_do_not_launch_unpublished_or_invented_npm() -> None:
    for path in DEFAULT_COMMAND_SURFACES:
        text = path.read_text(encoding="utf-8")
        assert "npx -y @microsoft/copilot-studio-kit-cli" not in text
        assert "powerplatform-review-tool" not in text


def test_verify_script_does_not_npx_404_or_github_repo() -> None:
    text = (REPO / "scripts" / "verify_engine_tooling.sh").read_text(encoding="utf-8")
    assert "npx -y @microsoft/copilot-studio-kit-cli" not in text
    assert "npx -y github:microsoft/Power-CAT-Copilot-Studio-Kit" not in text
    assert GITHUB_REPO in text
    assert "copilot-studio-kit" in text


def test_skip_helpers_detect_unpublished_npm_and_github_npx() -> None:
    npm_cmd = ["npx", "-y", DEPRECATED_NPM_PACKAGE, "--help"]
    github_cmd = ["npx", "-y", "github:microsoft/Power-CAT-Copilot-Studio-Kit", "--help"]
    native_cmd = ["copilot-studio-kit", "agent-review", "run"]
    assert command_uses_deprecated_npm(npm_cmd) is True
    assert command_uses_github_npx_kit(github_cmd) is True
    assert skip_reason_for_command(npm_cmd)
    assert skip_reason_for_command(github_cmd)
    assert skip_reason_for_command(native_cmd) is None
    assert skip_reason_for_command(["npx", "some-other-tool"]) is None
