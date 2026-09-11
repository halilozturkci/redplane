"""Audit bundle helpers."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_artifacts_index(run_root: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for file_path in sorted([p for p in run_root.rglob("*") if p.is_file()]):
        rel = file_path.relative_to(run_root).as_posix()
        entries.append(
            {
                "path": rel,
                "size_bytes": file_path.stat().st_size,
                "sha256": sha256_file(file_path),
            }
        )
    return entries
