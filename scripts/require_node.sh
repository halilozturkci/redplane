#!/usr/bin/env bash
# Shared Node floor for Promptfoo. Source this file; do not execute it.

_URT_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=toolchain_pins.env
source "${_URT_SCRIPT_DIR}/toolchain_pins.env"

# Compare dotted versions without GNU version-sort (BSD / macOS sort rejects that flag).
_urt_version_ge() {
  local have="$1"
  local need="$2"
  have="${have%%-*}"
  have="${have%%+*}"
  need="${need%%-*}"
  need="${need%%+*}"
  local IFS=.
  local -a have_parts=($have)
  local -a need_parts=($need)
  local i h n
  for ((i = 0; i < 3; i++)); do
    h="${have_parts[i]:-0}"
    n="${need_parts[i]:-0}"
    h="${h%%[!0-9]*}"
    n="${n%%[!0-9]*}"
    h="${h:-0}"
    n="${n:-0}"
    if ((10#$h > 10#$n)); then
      return 0
    fi
    if ((10#$h < 10#$n)); then
      return 1
    fi
  done
  return 0
}

require_urt_node() {
  if ! command -v node >/dev/null 2>&1; then
    echo "Node.js >= ${URT_NODE_MIN} is required for ${URT_PROMPTFOO_PACKAGE}."
    return 1
  fi
  local raw
  raw="$(node -v | sed 's/^v//')"
  if ! _urt_version_ge "${raw}" "${URT_NODE_MIN}"; then
    echo "${URT_PROMPTFOO_PACKAGE} requires Node.js >= ${URT_NODE_MIN} (found $(node -v))."
    return 1
  fi
}
