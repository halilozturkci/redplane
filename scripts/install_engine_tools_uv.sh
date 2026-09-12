#!/usr/bin/env bash
set -euo pipefail

if ! command -v uv >/dev/null 2>&1; then
  echo "uv is required to install engine CLIs."
  exit 1
fi

TOOLS=(
  "garak==0.17.0|3.12"
  "powerpwn==6.0.0|3.11"
  "deepteam==1.0.9|3.12"
  "inspect-ai==0.3.263|3.12"
)

GLOBAL_TOOL_PYTHON="${TOOL_PYTHON:-}"

for entry in "${TOOLS[@]}"; do
  tool="${entry%%|*}"
  default_python="${entry##*|}"
  python_version="${GLOBAL_TOOL_PYTHON:-${default_python}}"
  echo "Installing ${tool} (python=${python_version})"
  uv tool install --python "${python_version}" --force --refresh "${tool}"
done

echo "Python engine CLIs installed."
echo "Promptfoo local binary is installed by scripts/install_promptfoo_local.sh."
echo "MCS GA client is installed with: uv sync --extra mcs"
echo "Power CAT has no public npm CLI. Canonical source: https://github.com/microsoft/Power-CAT-Copilot-Studio-Kit"
echo "Giskard is launched via uvx runtime command because the package does not publish a standalone CLI binary."
