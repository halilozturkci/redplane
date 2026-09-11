#!/usr/bin/env bash
# Shared Node floor for Promptfoo. Source this file; do not execute it.

_URT_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=toolchain_pins.env
source "${_URT_SCRIPT_DIR}/toolchain_pins.env"

require_urt_node() {
  if ! command -v node >/dev/null 2>&1; then
    echo "Node.js >= ${URT_NODE_MIN} is required for ${URT_PROMPTFOO_PACKAGE}."
    return 1
  fi
  local raw
  raw="$(node -v | sed 's/^v//')"
  if [[ "$(printf '%s\n%s\n' "${URT_NODE_MIN}" "${raw}" | sort -V | head -n1)" != "${URT_NODE_MIN}" ]]; then
    echo "${URT_PROMPTFOO_PACKAGE} requires Node.js >= ${URT_NODE_MIN} (found $(node -v))."
    return 1
  fi
}
