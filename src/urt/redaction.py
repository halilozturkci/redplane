"""Write-time redaction for run specs, audit bundle files and CLI/API output.

`load_run_spec` expands `${VAR}` before validation, so a `RunSpec` in memory holds
real credentials. Two layers keep them out of everything the run persists or prints:

1. **Key/position rules** (`redact_run_spec_payload`): every leaf under a target's
   `auth` block is masked (credentials by contract, regardless of key naming), then
   the `gateway.redaction.redact_payload` key heuristics run over the whole payload.
2. **Value scrubbing** (`Scrubber`): the set of known secret *values* — every
   `${VAR}` substitution recorded by `config.expand_env_vars` plus every value the
   key/position rules would mask — is replaced wherever it appears as a substring:
   argv in `params.command`, `endpoint` query strings, tool stdout/stderr echoes,
   tracebacks, `error_message`. This is what catches secrets in fields no key
   heuristic can name.
"""

from __future__ import annotations

import copy
from typing import TYPE_CHECKING, Any, Iterable

from .constants import MIN_SECRET_LENGTH
from .gateway.redaction import _is_sensitive_key, redact_payload

if TYPE_CHECKING:
    from .types import RunSpec, UnifiedFinding

REDACTED = "***REDACTED***"

_AUTH_SCHEME_PREFIXES = ("Bearer ", "Basic ", "bearer ", "basic ")


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
    """Return a copy of a serialized `RunSpec` (or run manifest) safe to persist or print."""
    out = copy.deepcopy(spec_payload)
    targets = out.get("targets")
    if isinstance(targets, list):
        out["targets"] = [
            redact_target_payload(item) if isinstance(item, dict) else item for item in targets
        ]
    return redact_payload(out)


# Pre-1.1 finding metadata carried the params.env dict under this key; 1.1 records
# `env_override_keys` (names only). Any surviving dict here is credentials by position.
LEGACY_ENV_DICT_KEY = "env_overrides"
# Argv fields that pre-1.1 bundles wrote without value scrubbing.
_ARGV_KEYS = {"command"}


def _mask_positional(value: Any, *, legacy: bool) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            name = str(key)
            if name == LEGACY_ENV_DICT_KEY or (legacy and name in _ARGV_KEYS):
                out[name] = _mask_leaves(item)
            else:
                out[name] = _mask_positional(item, legacy=legacy)
        return out
    if isinstance(value, list):
        return [_mask_positional(item, legacy=legacy) for item in value]
    return value


def redact_bundle_payload(content: Any, *, legacy: bool = False) -> Any:
    """Read-time redaction for bundle JSON of any format version.

    Dict payloads (spec, manifest, summary) get the spec rules (auth leaves +
    key heuristics); lists (findings, invocations) get the key heuristics. Any
    `env_overrides` dict is masked by position. With `legacy=True` (bundle written
    before value scrubbing existed) `command` argv is masked too, since a secret
    passed on the command line was never scrubbed from it.
    """
    if isinstance(content, dict):
        redacted = redact_run_spec_payload(content)
    else:
        redacted = redact_payload(content)
    return _mask_positional(redacted, legacy=legacy)


def _leaf_strings(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for item in value.values():
            yield from _leaf_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _leaf_strings(item)
    elif isinstance(value, str):
        yield value


def _sensitive_values(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key, item in value.items():
            if _is_sensitive_key(str(key)):
                yield from _leaf_strings(item)
            else:
                yield from _sensitive_values(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _sensitive_values(item)


def _with_bare_tokens(values: Iterable[str]) -> set[str]:
    out: set[str] = set()
    for value in values:
        out.add(value)
        for prefix in _AUTH_SCHEME_PREFIXES:
            if value.startswith(prefix):
                out.add(value[len(prefix):])
    return {item for item in out if len(item) >= MIN_SECRET_LENGTH}


def collect_secret_values(spec_payload: dict[str, Any]) -> set[str]:
    """Secret values by position or key: target `auth` leaves, every
    `engines[].params.env` / `evaluators[].params.env` value (adapters already treat
    them as credentials and record keys only), and values of sensitive keys anywhere
    in the spec (plus the bare token behind a `Bearer `/`Basic ` prefix)."""
    values: set[str] = set()
    for target in spec_payload.get("targets", []) or []:
        if isinstance(target, dict):
            values.update(_leaf_strings(target.get("auth", {})))
    for section in ("engines", "evaluators"):
        for item in spec_payload.get(section, []) or []:
            if isinstance(item, dict):
                params = item.get("params") or {}
                if isinstance(params, dict):
                    values.update(_leaf_strings(params.get("env", {})))
    values.update(_sensitive_values(spec_payload))
    return _with_bare_tokens(values)


class Scrubber:
    """Replace known secret values wherever they occur in text or JSON-like payloads."""

    def __init__(self, secret_values: Iterable[str]):
        # Longest first so "Bearer <token>" is replaced before the bare "<token>".
        self._values = sorted(
            {str(v) for v in secret_values if len(str(v)) >= MIN_SECRET_LENGTH},
            key=len,
            reverse=True,
        )

    @classmethod
    def from_spec(cls, spec: "RunSpec") -> "Scrubber":
        return cls(collect_secret_values(spec.to_dict()) | set(spec.secret_values))

    def __bool__(self) -> bool:
        return bool(self._values)

    def scrub_text(self, text: str) -> str:
        for value in self._values:
            if value in text:
                text = text.replace(value, REDACTED)
        return text

    def scrub_bytes(self, payload: bytes) -> bytes:
        """Scrub UTF-8 text payloads; binary payloads are returned unchanged."""
        if not self._values:
            return payload
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            return payload
        return self.scrub_text(text).encode("utf-8")

    def scrub(self, payload: Any) -> Any:
        if not self._values:
            return payload
        if isinstance(payload, str):
            return self.scrub_text(payload)
        if isinstance(payload, dict):
            return {key: self.scrub(value) for key, value in payload.items()}
        if isinstance(payload, list):
            return [self.scrub(item) for item in payload]
        if isinstance(payload, tuple):
            return tuple(self.scrub(item) for item in payload)
        return payload

    def scrub_finding(self, finding: "UnifiedFinding") -> "UnifiedFinding":
        from .types import UnifiedFinding

        if not self._values:
            return finding
        return UnifiedFinding(**self.scrub(finding.to_dict()))
