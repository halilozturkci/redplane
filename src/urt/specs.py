"""Spec builder backend (§4.7 / G4): capabilities, templates, validate-only, probe.

Shared by `urt validate` / `urt probe` and the `/v1/specs/*`, `/v1/templates`,
`/v1/capabilities` endpoints plus the `/ui/specs` page. Two rules the browser
side relies on and this module enforces server-side:

- **`${VAR}` is the only way to put a credential in a spec.** Any literal under a
  target's `auth` is a validation error here (the CLI still accepts literals for
  local one-offs; the builder does not). The response says whether each referenced
  variable is *set*, never what it holds.
- **Nothing expanded is returned.** The resolved spec is the same key-redacted,
  value-scrubbed view `urt validate` prints.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import expand_env_vars
from .constants import (
    DEFAULT_RUN_PROFILE,
    RUN_PROFILE_DEFAULTS,
    SEVERITY_ORDER,
    SUPPORTED_ENGINES,
    SUPPORTED_EVALUATORS,
    SUPPORTED_EVIDENCE_LEVELS,
    SUPPORTED_PROFILES,
    SUPPORTED_TARGETS,
)
from .policy.mapping import MITRE_ATLAS_MAP, OWASP_AGENTIC_MAP, OWASP_LLM_MAP
from .redaction import Scrubber, redact_run_spec_payload
from .types import RunSpec, ValidationError

TEMPLATES_DIR_ENV = "URT_TEMPLATES_DIR"
DEFAULT_TEMPLATES_DIR = "templates"
TEMPLATE_NAME = re.compile(r"^run_spec[A-Za-z0-9._-]*\.ya?ml$")
ENV_REF = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")
ENV_TOKEN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
MAX_SPEC_BYTES = 256 * 1024
POLICY_PROFILES = ("owasp_llm", "owasp_agentic", "mitre_atlas")
_ = (OWASP_LLM_MAP, OWASP_AGENTIC_MAP, MITRE_ATLAS_MAP)  # the three frameworks POLICY_PROFILES names


class SpecInputError(ValueError):
    """Malformed request (not a spec validation failure)."""


def capabilities() -> dict[str, Any]:
    """What the spec builder may offer, straight from `constants`."""
    return {
        "targets": sorted(SUPPORTED_TARGETS),
        "engines": sorted(SUPPORTED_ENGINES),
        "evaluators": sorted(SUPPORTED_EVALUATORS),
        "profiles": sorted(SUPPORTED_PROFILES),
        "default_profile": DEFAULT_RUN_PROFILE,
        "evidence_levels": sorted(SUPPORTED_EVIDENCE_LEVELS),
        "profile_defaults": RUN_PROFILE_DEFAULTS,
        "policy_profiles": sorted(POLICY_PROFILES),
        "severity_levels": sorted(SEVERITY_ORDER, key=lambda level: -SEVERITY_ORDER[level]),
    }


# --- templates ------------------------------------------------------------------------


def templates_dir() -> Path:
    return Path(os.environ.get(TEMPLATES_DIR_ENV) or DEFAULT_TEMPLATES_DIR)


def _yaml():
    try:
        import yaml  # type: ignore
    except ImportError as exc:  # pragma: no cover - PyYAML is a hard dependency
        raise RuntimeError("PyYAML is required") from exc
    return yaml


def parse_spec_text(text: str) -> dict[str, Any]:
    """YAML (or JSON, a YAML subset) → mapping. Raises `SpecInputError` when not a mapping."""
    if len(text.encode("utf-8")) > MAX_SPEC_BYTES:
        raise SpecInputError(f"spec text exceeds {MAX_SPEC_BYTES} bytes")
    try:
        data = _yaml().safe_load(text)
    except Exception as exc:  # noqa: BLE001 - yaml raises several error classes
        raise ValidationError(f"YAML parse error: {exc}") from exc
    if not isinstance(data, dict):
        raise ValidationError("Run spec must be a YAML/JSON object")
    return data


def spec_to_yaml(payload: dict[str, Any]) -> str:
    return _yaml().safe_dump(payload, sort_keys=False, allow_unicode=True)


def template_kind(payload: dict[str, Any]) -> tuple[str | None, str]:
    """(`metadata.spec_kind`, badge) — badge is `smoke` only when the spec says so; a
    spec without the marker is treated as `real` so nothing quietly passes as a smoke run."""
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    spec_kind = metadata.get("spec_kind")
    spec_kind = None if spec_kind is None else str(spec_kind)
    return spec_kind, "smoke" if spec_kind == "smoke" else "real"


def list_templates(directory: Path | None = None) -> list[dict[str, Any]]:
    root = directory or templates_dir()
    rows: list[dict[str, Any]] = []
    if not root.is_dir():
        return rows
    for path in sorted(root.iterdir()):
        if not path.is_file() or not TEMPLATE_NAME.match(path.name):
            continue
        try:
            payload = parse_spec_text(path.read_text(encoding="utf-8"))
        except (ValidationError, SpecInputError, OSError):
            continue
        spec_kind, kind = template_kind(payload)
        metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
        rows.append(
            {
                "name": path.name,
                "spec_name": str(payload.get("name", "")),
                "run_profile": str(payload.get("run_profile", DEFAULT_RUN_PROFILE)),
                "spec_kind": spec_kind,
                "kind": kind,
                "description": str(metadata.get("description", "")).strip(),
                "targets": [str(t.get("type", "")) for t in payload.get("targets", []) if isinstance(t, dict)],
                "engines": [str(e.get("name", "")) for e in payload.get("engines", []) if isinstance(e, dict)],
            }
        )
    return rows


def load_template(name: str, directory: Path | None = None) -> dict[str, Any] | None:
    """Template text by file name; None unless the name is one `list_templates` returned."""
    if not TEMPLATE_NAME.match(name) or "/" in name or "\\" in name:
        return None
    root = directory or templates_dir()
    listed = {row["name"]: row for row in list_templates(root)}
    if name not in listed:
        return None
    return {**listed[name], "yaml": (root / name).read_text(encoding="utf-8")}


# --- validation -----------------------------------------------------------------------


def env_var_names(payload: Any) -> list[str]:
    names: set[str] = set()

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, str):
            names.update(ENV_TOKEN.findall(value))

    walk(payload)
    return sorted(names)


def env_var_status(payload: Any) -> list[dict[str, Any]]:
    """`${VAR}` references in the raw payload with a set/unset boolean — never the value."""
    return [{"name": name, "set": name in os.environ} for name in env_var_names(payload)]


def auth_literal_errors(payload: dict[str, Any]) -> list[str]:
    """Every leaf under `targets[*].auth` must be exactly one `${VAR}` reference or a
    string whose credential part is one (`Bearer ${VAR}`, `Basic ${VAR}`)."""
    errors: list[str] = []
    targets = payload.get("targets")
    if not isinstance(targets, list):
        return errors

    def check(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                check(item, f"{path}.{key}")
        elif isinstance(value, list):
            for index, item in enumerate(value):
                check(item, f"{path}[{index}]")
        elif value is None or value == "":
            return
        else:
            text = str(value)
            credential = text.split(" ", 1)[1] if text.lower().startswith(("bearer ", "basic ")) else text
            if not ENV_REF.match(credential.strip()):
                errors.append(
                    f"{path}: must reference an environment variable (${{VAR}}); "
                    "literal credentials are not accepted by the spec builder"
                )

    for index, target in enumerate(targets):
        if isinstance(target, dict) and isinstance(target.get("auth"), dict):
            check(target["auth"], f"targets[{index}].auth")
    return errors


@dataclass(slots=True)
class SpecValidation:
    ok: bool
    errors: list[str] = field(default_factory=list)
    resolved_spec: dict[str, Any] | None = None
    profile_defaults: dict[str, Any] = field(default_factory=dict)
    env_vars: list[dict[str, Any]] = field(default_factory=list)
    spec_kind: str | None = None
    kind: str = "real"
    spec: RunSpec | None = field(default=None, repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "errors": list(self.errors),
            "resolved_spec": self.resolved_spec,
            "profile_defaults": self.profile_defaults,
            "env_vars": list(self.env_vars),
            "spec_kind": self.spec_kind,
            "kind": self.kind,
        }


def validate_spec_payload(payload: dict[str, Any]) -> SpecValidation:
    """Validate-only: never executes anything, never returns an expanded value."""
    errors = auth_literal_errors(payload)
    env_vars = env_var_status(payload)
    spec_kind, kind = template_kind(payload)
    profile = str(payload.get("run_profile", DEFAULT_RUN_PROFILE)).strip().lower()
    profile_defaults = RUN_PROFILE_DEFAULTS.get(profile, {})

    substituted: set[str] = set()
    spec: RunSpec | None = None
    resolved: dict[str, Any] | None = None
    try:
        spec = RunSpec.from_dict(expand_env_vars(payload, collected=substituted))
        spec.secret_values = frozenset(substituted)
    except (ValidationError, ValueError, TypeError) as exc:
        errors.append(str(exc))
    if spec is not None and not errors:
        resolved = Scrubber.from_spec(spec).scrub(redact_run_spec_payload(spec.to_dict()))
    return SpecValidation(
        ok=not errors,
        errors=errors,
        resolved_spec=resolved,
        profile_defaults=profile_defaults,
        env_vars=env_vars,
        spec_kind=spec_kind,
        kind=kind,
        spec=spec if not errors else None,
    )


def payload_from_request(body: dict[str, Any]) -> dict[str, Any]:
    """`{"yaml": "..."}` or `{"spec": {...}}` → raw payload. `SpecInputError` when neither."""
    if isinstance(body.get("spec"), dict):
        return dict(body["spec"])
    if isinstance(body.get("yaml"), str):
        return parse_spec_text(body["yaml"])
    raise SpecInputError("Body must contain 'yaml' (string) or 'spec' (object)")


# --- probe ----------------------------------------------------------------------------


def probe_spec(spec: RunSpec) -> list[dict[str, Any]]:
    """Healthcheck every target (same as `urt probe`); rows are scrubbed of secret values."""
    from .adapters import create_target_adapter

    rows: list[dict[str, Any]] = []
    for target in spec.targets:
        adapter = create_target_adapter(target)
        adapter.apply_runtime(
            connect_seconds=spec.timeouts.connect_seconds,
            request_seconds=spec.timeouts.request_seconds,
        )
        ok, detail = adapter.healthcheck()
        rows.append({"target_id": target.target_id, "type": target.target_type, "ok": ok, "detail": detail})
    return Scrubber.from_spec(spec).scrub(rows)


# --- form <-> payload (the /ui/specs structured editor) ------------------------------------

AUTH_MODES = ("none", "bearer", "api_key", "header")


def payload_to_form(payload: dict[str, Any]) -> dict[str, str]:
    """Flatten the common spec shape (one target) into form fields. Anything the form
    cannot express stays only in the YAML editor."""
    form: dict[str, str] = {
        "name": str(payload.get("name", "")),
        "run_profile": str(payload.get("run_profile", DEFAULT_RUN_PROFILE)),
        "evidence_level": str(payload.get("evidence_level", "standard")),
        "seed": "" if payload.get("seed") is None else str(payload.get("seed")),
        "spec_kind": str((payload.get("metadata") or {}).get("spec_kind", "") or ""),
    }
    for profile in POLICY_PROFILES:
        if profile in (payload.get("policy_profiles") or POLICY_PROFILES):
            form[f"policy_{profile}"] = "on"
    targets = payload.get("targets") or [{}]
    target = targets[0] if isinstance(targets[0], dict) else {}
    form["target_id"] = str(target.get("id", ""))
    form["target_type"] = str(target.get("type", "http"))
    form["target_endpoint"] = str(target.get("endpoint", "") or "")
    form["target_skip_healthcheck"] = "on" if (target.get("config") or {}).get("skip_healthcheck") else ""
    mode, var, header = "none", "", ""
    auth = target.get("auth") or {}
    if isinstance(auth.get("api_key"), str) and ENV_REF.match(auth["api_key"]):
        mode, var = "api_key", ENV_REF.match(auth["api_key"]).group(1)
    elif isinstance(auth.get("headers"), dict) and auth["headers"]:
        header, value = next(iter(auth["headers"].items()))
        text = str(value)
        if header == "Authorization" and text.startswith("Bearer ") and ENV_REF.match(text[7:]):
            mode, var, header = "bearer", ENV_REF.match(text[7:]).group(1), ""
        elif ENV_REF.match(text):
            mode, var = "header", ENV_REF.match(text).group(1)
    form["target_auth_mode"] = mode
    form["target_auth_var"] = var
    form["target_auth_header"] = str(header)
    for engine in payload.get("engines") or []:
        if isinstance(engine, dict) and engine.get("name") in SUPPORTED_ENGINES:
            form[f"engine_{engine['name']}"] = "on"
            command = (engine.get("params") or {}).get("command")
            if command:
                form[f"engine_{engine['name']}_command"] = str(command)
    for evaluator in payload.get("evaluators") or []:
        if isinstance(evaluator, dict) and evaluator.get("name") in SUPPORTED_EVALUATORS:
            form[f"evaluator_{evaluator['name']}"] = "on"
    return form


def form_to_payload(form: dict[str, str]) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "name": form.get("name", "").strip(),
        "run_profile": form.get("run_profile", DEFAULT_RUN_PROFILE).strip() or DEFAULT_RUN_PROFILE,
    }
    if form.get("spec_kind", "").strip():
        payload["metadata"] = {"spec_kind": form["spec_kind"].strip()}
    target: dict[str, Any] = {"id": form.get("target_id", "").strip(), "type": form.get("target_type", "http").strip()}
    if form.get("target_endpoint", "").strip():
        target["endpoint"] = form["target_endpoint"].strip()
    mode = form.get("target_auth_mode", "none")
    var = form.get("target_auth_var", "").strip()
    if mode != "none" and var:
        ref = f"${{{var}}}"
        if mode == "bearer":
            target["auth"] = {"headers": {"Authorization": f"Bearer {ref}"}}
        elif mode == "api_key":
            target["auth"] = {"api_key": ref}
        elif mode == "header":
            target["auth"] = {"headers": {form.get("target_auth_header", "").strip() or "Authorization": ref}}
    if form.get("target_skip_healthcheck"):
        target["config"] = {"skip_healthcheck": True}
    payload["targets"] = [target]
    payload["engines"] = [
        {"name": engine, **({"params": {"command": form[f"engine_{engine}_command"].strip()}} if form.get(f"engine_{engine}_command", "").strip() else {})}
        for engine in sorted(SUPPORTED_ENGINES)
        if form.get(f"engine_{engine}")
    ]
    evaluators = [{"name": evaluator} for evaluator in sorted(SUPPORTED_EVALUATORS) if form.get(f"evaluator_{evaluator}")]
    if evaluators:
        payload["evaluators"] = evaluators
    policies = [profile for profile in POLICY_PROFILES if form.get(f"policy_{profile}")]
    if policies:
        payload["policy_profiles"] = policies
    if form.get("evidence_level", "").strip():
        payload["evidence_level"] = form["evidence_level"].strip()
    if form.get("seed", "").strip():
        try:
            payload["seed"] = int(form["seed"].strip())
        except ValueError:
            payload["seed"] = form["seed"].strip()
    return payload
