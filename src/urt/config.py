"""Configuration loading and validation helpers."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .types import RunSpec, ValidationError


def expand_env_vars(obj: Any) -> Any:
    """Recursively expand `${VAR}` tokens in nested YAML/JSON payloads."""
    if isinstance(obj, dict):
        return {str(key): expand_env_vars(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [expand_env_vars(value) for value in obj]
    if isinstance(obj, str):
        return os.path.expandvars(obj)
    return obj


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        import yaml  # type: ignore
    except ImportError as exc:
        raise RuntimeError("PyYAML is required to load YAML specs. Install with `pip install PyYAML`.") from exc

    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValidationError("Run spec must be a JSON/YAML object")
    return data


def load_run_spec(path: str | Path) -> RunSpec:
    spec_path = Path(path)
    if not spec_path.exists():
        raise FileNotFoundError(f"Run spec not found: {spec_path}")

    suffix = spec_path.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        payload = _load_yaml(spec_path)
    elif suffix == ".json":
        payload = json.loads(spec_path.read_text(encoding="utf-8"))
    else:
        raise ValidationError("Unsupported run spec format. Use .yaml, .yml, or .json")

    return RunSpec.from_dict(expand_env_vars(payload))


def dump_run_spec(path: str | Path, payload: dict[str, Any]) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    suffix = output_path.suffix.lower()

    if suffix in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise RuntimeError("PyYAML is required to write YAML specs. Install with `pip install PyYAML`.") from exc
        output_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
        return

    if suffix == ".json":
        output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return

    raise ValidationError("Unsupported output format. Use .yaml/.yml/.json")
