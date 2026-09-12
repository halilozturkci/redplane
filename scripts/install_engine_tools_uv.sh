#!/usr/bin/env bash
set -euo pipefail

if ! command -v uv >/dev/null 2>&1; then
  echo "uv is required to install engine CLIs."
  exit 1
fi

# spec|python|comma-separated --with packages (optional)
TOOLS=(
  "garak==0.17.0|3.12|"
  "powerpwn==6.0.0|3.11|"
  "deepteam==1.0.9|3.12|sentry-sdk"
  "inspect-ai==0.3.263|3.12|"
  "deepeval==4.2.2|3.12|"
)

GLOBAL_TOOL_PYTHON="${TOOL_PYTHON:-}"

for entry in "${TOOLS[@]}"; do
  tool="${entry%%|*}"
  rest="${entry#*|}"
  default_python="${rest%%|*}"
  withs="${rest#*|}"
  python_version="${GLOBAL_TOOL_PYTHON:-${default_python}}"
  with_args=()
  if [[ -n "${withs}" ]]; then
    IFS=',' read -ra pkgs <<< "${withs}"
    for pkg in "${pkgs[@]}"; do
      [[ -n "${pkg}" ]] || continue
      with_args+=(--with "${pkg}")
    done
  fi
  echo "Installing ${tool} (python=${python_version})"
  uv tool install --python "${python_version}" --force --refresh "${with_args[@]}" "${tool}"
done

echo "Python engine CLIs installed."
echo "Promptfoo local binary is installed by scripts/install_promptfoo_local.sh."
echo "MCS GA client is installed with: uv sync --extra mcs"
echo "Power CAT CLI runs via npx at runtime (@microsoft/copilot-studio-kit-cli)."
echo "Giskard v3 is launched via uvx because the scan extra does not publish a standalone CLI binary."
