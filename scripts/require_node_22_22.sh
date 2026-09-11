#!/usr/bin/env bash
# Shared Node floor for promptfoo@0.123.0. Source this file; do not execute it.

require_node_22_22() {
  local reason="${1:-promptfoo@0.123.0}"
  if ! command -v node >/dev/null 2>&1; then
    echo "Node.js >= 22.22.0 is required for ${reason}."
    return 1
  fi
  if ! node -e 'const p=process.versions.node.split(".").map(Number); if (p[0]<22 || (p[0]===22 && p[1]<22)) process.exit(1)'; then
    echo "${reason} requires Node.js >= 22.22.0 (found $(node -v))."
    return 1
  fi
}
