"""Filesystem artifact storage backend."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..redaction import Scrubber


class ArtifactStore:
    """Stores run artifacts on local filesystem.

    With a `Scrubber` attached (see `scrubbed()`), every write — JSON, text, bytes
    and copied files — has known secret values replaced before it touches disk.
    """

    def __init__(self, root_dir: str | Path, *, scrubber: "Scrubber | None" = None):
        self.root_dir = Path(root_dir)
        self.root_dir.mkdir(parents=True, exist_ok=True)
        self.scrubber = scrubber

    def scrubbed(self, scrubber: "Scrubber") -> "ArtifactStore":
        """A view on the same root that scrubs `scrubber`'s values from every write."""
        return ArtifactStore(self.root_dir, scrubber=scrubber)

    def run_dir(self, run_id: str) -> Path:
        path = self.root_dir / run_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def write_json(self, run_id: str, file_name: str, payload: Any) -> str:
        if self.scrubber:
            payload = self.scrubber.scrub(payload)
        path = self.run_dir(run_id) / file_name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return str(path)

    def write_text(self, run_id: str, file_name: str, content: str) -> str:
        if self.scrubber:
            content = self.scrubber.scrub_text(content)
        path = self.run_dir(run_id) / file_name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return str(path)

    def write_bytes(self, run_id: str, file_name: str, payload: bytes) -> str:
        if self.scrubber:
            payload = self.scrubber.scrub_bytes(payload)
        path = self.run_dir(run_id) / file_name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return str(path)

    def copy_file(self, run_id: str, source_file: str | Path, dest_name: str | None = None) -> str:
        src = Path(source_file)
        if not src.exists():
            raise FileNotFoundError(src)
        payload = src.read_bytes()
        if self.scrubber:
            payload = self.scrubber.scrub_bytes(payload)
        dst = self.run_dir(run_id) / (dest_name or src.name)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(payload)
        return str(dst)

    def list_run_files(self, run_id: str) -> list[Path]:
        root = self.run_dir(run_id)
        return sorted([p for p in root.rglob("*") if p.is_file()])
