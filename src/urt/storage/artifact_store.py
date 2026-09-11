"""Filesystem artifact storage backend."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class ArtifactStore:
    """Stores run artifacts on local filesystem."""

    def __init__(self, root_dir: str | Path):
        self.root_dir = Path(root_dir)
        self.root_dir.mkdir(parents=True, exist_ok=True)

    def run_dir(self, run_id: str) -> Path:
        path = self.root_dir / run_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def write_json(self, run_id: str, file_name: str, payload: Any) -> str:
        path = self.run_dir(run_id) / file_name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return str(path)

    def write_text(self, run_id: str, file_name: str, content: str) -> str:
        path = self.run_dir(run_id) / file_name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return str(path)

    def write_bytes(self, run_id: str, file_name: str, payload: bytes) -> str:
        path = self.run_dir(run_id) / file_name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return str(path)

    def copy_file(self, run_id: str, source_file: str | Path, dest_name: str | None = None) -> str:
        src = Path(source_file)
        if not src.exists():
            raise FileNotFoundError(src)
        dst = self.run_dir(run_id) / (dest_name or src.name)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(src.read_bytes())
        return str(dst)

    def list_run_files(self, run_id: str) -> list[Path]:
        root = self.run_dir(run_id)
        return sorted([p for p in root.rglob("*") if p.is_file()])
