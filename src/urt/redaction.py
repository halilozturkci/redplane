"""Write-time redaction for run specs and audit bundle files.

`load_run_spec` expands `${VAR}` before validation, so a `RunSpec` in memory holds
real credentials. Anything derived from it that is persisted or printed must pass
through here first. Key-name heuristics come from `gateway.redaction`; on top of
that, every leaf under a target's `auth` block is masked because that block is,
by contract, credentials regardless of key naming.
"""

from __future__ import annotations

import copy
from typing import Any

from .gateway.redaction import redact_payload

REDACTED = "***REDACTED***"


def _mask_leaves(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _mask_leaves(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_mask_leaves(item) for item in value]
    if value is None:
        return None
    return REDACTED


def redact_target_payload(target: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of a serialized `TargetSpec` safe to persist."""
    out = copy.deepcopy(target)
    if "auth" in out:
        out["auth"] = _mask_leaves(out["auth"])
    return redact_payload(out)


def redact_run_spec_payload(spec_payload: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of a serialized `RunSpec` safe to persist or print."""
    out = copy.deepcopy(spec_payload)
    targets = out.get("targets")
    if isinstance(targets, list):
        out["targets"] = [
            redact_target_payload(item) if isinstance(item, dict) else item for item in targets
        ]
    return redact_payload(out)
