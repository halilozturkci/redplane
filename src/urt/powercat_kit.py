"""Canonical Power CAT Copilot Studio Kit identity.

Microsoft ships the Kit as a Power Platform solution and a GitHub Action in
``microsoft/Power-CAT-Copilot-Studio-Kit``. There is no public npm CLI. Do not
invent a package name and do not treat ``powerplatform-review-tool`` as Power CAT.
"""

from __future__ import annotations

GITHUB_REPO = "https://github.com/microsoft/Power-CAT-Copilot-Studio-Kit"
GITHUB_ACTION_PATH = "agent-review-pipeline"
NATIVE_LAUNCHER = "copilot-studio-kit"
DEFAULT_COMMAND = "copilot-studio-kit agent-review run"
DEPRECATED_NPM_PACKAGE = "@microsoft/copilot-studio-kit-cli"
_GITHUB_NPX_MARKERS = (
    "github:microsoft/Power-CAT-Copilot-Studio-Kit",
    "microsoft/Power-CAT-Copilot-Studio-Kit",
)

SKIP_NO_PUBLIC_CLI = (
    "Power CAT has no public npm CLI. Install the Copilot Studio Kit from "
    f"{GITHUB_REPO} (Power Platform solution / {GITHUB_ACTION_PATH} GitHub Action) "
    f"or provide a local `{NATIVE_LAUNCHER}` launcher."
)
SKIP_DEPRECATED_NPM = (
    f"`{DEPRECATED_NPM_PACKAGE}` is not a published npm package (E404). "
    f"Canonical source: {GITHUB_REPO}."
)
SKIP_GITHUB_NPX = (
    f"`npx github:microsoft/Power-CAT-Copilot-Studio-Kit` is not a CLI "
    f"(the repo has no root package.json). Canonical source: {GITHUB_REPO}."
)


def command_uses_deprecated_npm(command_list: list[str]) -> bool:
    return any(DEPRECATED_NPM_PACKAGE in part for part in command_list)


def command_uses_github_npx_kit(command_list: list[str]) -> bool:
    if not command_list or command_list[0] not in {"npx", "npm"}:
        return False
    joined = " ".join(command_list)
    return any(marker in joined for marker in _GITHUB_NPX_MARKERS)


def skip_reason_for_command(command_list: list[str]) -> str | None:
    """Return a skip reason when the command cannot launch a real Kit CLI."""
    if command_uses_deprecated_npm(command_list):
        return SKIP_DEPRECATED_NPM
    if command_uses_github_npx_kit(command_list):
        return SKIP_GITHUB_NPX
    return None


def skip_reason_missing_launcher(launcher: str) -> str:
    if launcher == NATIVE_LAUNCHER:
        return SKIP_NO_PUBLIC_CLI
    return f"powercat command launcher not found in PATH: {launcher}. {SKIP_NO_PUBLIC_CLI}"


def package_not_found_reason(reason: str) -> bool:
    """True only for the unpublished npm package skip, not GitHub-npx."""
    return reason == SKIP_DEPRECATED_NPM
