#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=require_node.sh
source "${SCRIPT_DIR}/require_node.sh"

if ! command -v npm >/dev/null 2>&1; then
  echo "npm is required to install promptfoo locally. Install Node.js >= ${URT_NODE_MIN}."
  exit 1
fi

require_urt_node || exit 1

NODE_TOOLS_ROOT="${NODE_TOOLS_ROOT:-${HOME}/.urt-tools}"
PROMPTFOO_DIR="${PROMPTFOO_DIR:-${NODE_TOOLS_ROOT}/promptfoo}"
PROMPTFOO_PACKAGE="${PROMPTFOO_PACKAGE:-${URT_PROMPTFOO_PACKAGE}}"
PROMPTFOO_LINK_DIR="${PROMPTFOO_LINK_DIR:-${HOME}/.local/bin}"

mkdir -p "${PROMPTFOO_DIR}"
mkdir -p "${PROMPTFOO_LINK_DIR}"

echo "Installing ${PROMPTFOO_PACKAGE} under ${PROMPTFOO_DIR}"
npm install --prefix "${PROMPTFOO_DIR}" --no-audit --no-fund "${PROMPTFOO_PACKAGE}"

PROMPTFOO_BIN="${PROMPTFOO_DIR}/node_modules/.bin/promptfoo"
if [[ ! -x "${PROMPTFOO_BIN}" ]]; then
  echo "promptfoo binary not found after install: ${PROMPTFOO_BIN}"
  exit 1
fi

ln -sf "${PROMPTFOO_BIN}" "${PROMPTFOO_LINK_DIR}/promptfoo"

echo "Promptfoo local binary: ${PROMPTFOO_BIN}"
echo "Symlink created: ${PROMPTFOO_LINK_DIR}/promptfoo"
if [[ ":${PATH}:" != *":${PROMPTFOO_LINK_DIR}:"* ]]; then
  echo "PATH note: add '${PROMPTFOO_LINK_DIR}' to PATH to call promptfoo directly."
fi
