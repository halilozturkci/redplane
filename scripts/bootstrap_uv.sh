#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
STATE_DIR="${ROOT_DIR}/.urt_state"
LOG_DIR="${STATE_DIR}/logs"

mkdir -p "${LOG_DIR}" "${STATE_DIR}/artifacts" "${STATE_DIR}/metadata"
exec > >(tee -a "${LOG_DIR}/bootstrap.log") 2>&1

if ! command -v uv >/dev/null 2>&1; then
  echo "uv is required. Install it first: https://docs.astral.sh/uv/getting-started/installation/"
  exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "npm is required for promptfoo local install and powercat runtime. Install Node.js 20+."
  exit 1
fi

if ! command -v npx >/dev/null 2>&1; then
  echo "npx is required for powercat engine. Install Node.js 20+."
  exit 1
fi

cd "${ROOT_DIR}"

echo "[1/5] Syncing URT runtime with uv"
uv sync

echo "[2/5] Installing Python engine CLIs with isolated uv tool environments"
"${SCRIPT_DIR}/install_engine_tools_uv.sh"

echo "[3/5] Installing promptfoo local binary"
"${SCRIPT_DIR}/install_promptfoo_local.sh"

echo "[4/5] Installing Microsoft Copilot Studio preview packages"
"${SCRIPT_DIR}/install_mcs_preview_packages.sh"

echo "[5/5] Verifying local toolchain"
"${SCRIPT_DIR}/verify_engine_tooling.sh"

echo "Bootstrap completed."
