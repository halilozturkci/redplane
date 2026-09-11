#!/usr/bin/env bash
set -euo pipefail

if ! command -v npm >/dev/null 2>&1; then
  echo "npm is required to install promptfoo locally. Install Node.js >= 22.22.0."
  exit 1
fi

if ! command -v node >/dev/null 2>&1; then
  echo "Node.js >= 22.22.0 is required to install promptfoo@0.123.0."
  exit 1
fi

if ! node -e 'const p=process.versions.node.split(".").map(Number); if (p[0]<22 || (p[0]===22 && p[1]<22)) process.exit(1)'; then
  echo "promptfoo@0.123.0 requires Node.js >= 22.22.0 (found $(node -v))."
  exit 1
fi

NODE_TOOLS_ROOT="${NODE_TOOLS_ROOT:-${HOME}/.urt-tools}"
PROMPTFOO_DIR="${PROMPTFOO_DIR:-${NODE_TOOLS_ROOT}/promptfoo}"
PROMPTFOO_PACKAGE="${PROMPTFOO_PACKAGE:-promptfoo@0.123.0}"
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
