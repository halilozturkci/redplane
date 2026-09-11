#!/usr/bin/env bash
set -euo pipefail

# Gate before any filesystem side effects. TestPyPI MCS install is opt-in.
if [[ "${URT_INSTALL_MCS_PREVIEW:-0}" != "1" ]]; then
  echo "Skipping MCS preview package install (TestPyPI path is opt-in). Set URT_INSTALL_MCS_PREVIEW=1 to install."
  exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
STATE_DIR="${ROOT_DIR}/.urt_state"
LOG_DIR="${STATE_DIR}/logs"
LOG_FILE="${LOG_DIR}/install_mcs_preview.log"

mkdir -p "${LOG_DIR}"
exec > >(tee -a "${LOG_FILE}") 2>&1

if ! command -v uv >/dev/null 2>&1; then
  echo "uv is required to install MCS preview packages."
  exit 1
fi

PYTHON_BIN="${ROOT_DIR}/.venv/bin/python"
if [[ ! -x "${PYTHON_BIN}" ]]; then
  echo "Expected virtualenv python at ${PYTHON_BIN}. Run scripts/bootstrap_uv.sh first."
  exit 1
fi

INDEX_FLAGS=(
  "-i"
  "https://test.pypi.org/simple/"
  "--extra-index-url"
  "https://pypi.org/simple/"
)

PACKAGES=(
  "microsoft-agents-core"
  "microsoft-agents-authorization"
  "microsoft-agents-connector"
  "microsoft-agents-client"
  "microsoft-agents-builder"
  "microsoft-agents-authentication-msal"
  "microsoft-agents-copilotstudio-client"
  "microsoft-agents-hosting-aiohttp"
  "microsoft-agents-storage"
  "microsoft-agents-activity"
)

echo "Installing Microsoft Copilot Studio preview packages into ${ROOT_DIR}/.venv"
for package in "${PACKAGES[@]}"; do
  echo "Installing ${package}"
  uv pip install --python "${PYTHON_BIN}" "${INDEX_FLAGS[@]}" "${package}"
done

echo "MCS preview package install completed."
