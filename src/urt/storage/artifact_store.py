"""Filesystem artifact storage backend."""

from __future__ import annotations

import io
import json
import os
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..redaction import Scrubber


class ArtifactPathError(ValueError):
    """Raised when a client-supplied artifact path would escape the run directory."""


def _validate_segment(value: str, *, what: str) -> None:
    if not value or value in {".", ".."} or "/" in value or "\\" in value or "\x00" in value:
        raise ArtifactPathError(f"Invalid {what}")


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

    def existing_run_dir(self, run_id: str) -> Path | None:
        """Run directory without the mkdir side effect; None when absent."""
        _validate_segment(run_id, what="run_id")
        path = self.root_dir / run_id
        return path if path.is_dir() and not path.is_symlink() else None

    def read_json(self, run_id: str, file_name: str) -> Any | None:
        """Read a bundle JSON file; None when the run or file does not exist."""
        run_root = self.existing_run_dir(run_id)
        if run_root is None:
            return None
        path = run_root / file_name
        if not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def resolve_artifact(self, run_id: str, relative_path: str) -> Path:
        """Map a bundle-relative path to a regular file strictly inside the run directory.

        Rejects absolute paths, `.`/`..`/empty segments, backslashes and any symlink
        component (even one that points back inside the run). Raises
        `ArtifactPathError` for rejected paths and `FileNotFoundError` when the run
        or file is absent.
        """
        run_root = self.existing_run_dir(run_id)
        if run_root is None:
            raise FileNotFoundError(f"Run directory not found: {run_id}")

        if not relative_path or "\\" in relative_path or "\x00" in relative_path:
            raise ArtifactPathError("Invalid artifact path")
        # Split on the raw string: PurePosixPath would silently collapse "." segments
        # and a leading "/" shows up here as an empty first segment.
        segments = relative_path.split("/")
        if any(segment in {"", ".", ".."} for segment in segments):
            raise ArtifactPathError("Invalid artifact path")

        current = run_root
        for part in segments:
            current = current / part
            if current.is_symlink():
                raise ArtifactPathError("Symlinked artifacts are not served")

        resolved = current.resolve()
        if not resolved.is_relative_to(run_root.resolve()):
            raise ArtifactPathError("Artifact path escapes the run directory")
        if not resolved.is_file():
            raise FileNotFoundError(f"Artifact not found: {relative_path}")
        return resolved

    def relative_artifact_path(self, run_id: str, absolute_ref: str) -> str | None:
        """Bundle-relative form of an absolute evidence ref, or None if it is outside the run."""
        try:
            run_root = self.existing_run_dir(run_id)
        except ArtifactPathError:
            return None
        if run_root is None:
            return None
        ref = Path(absolute_ref)
        if not ref.is_absolute():
            return None
        try:
            rel = ref.resolve().relative_to(run_root.resolve())
        except (ValueError, OSError):
            return None
        return rel.as_posix()

    def zip_run(self, run_id: str) -> bytes:
        """Zip every regular file in the run directory (symlinks skipped) under `<run_id>/`."""
        run_root = self.existing_run_dir(run_id)
        if run_root is None:
            raise FileNotFoundError(f"Run directory not found: {run_id}")
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for file_path in self._regular_files(run_root):
                archive.write(file_path, arcname=f"{run_id}/{file_path.relative_to(run_root).as_posix()}")
        return buffer.getvalue()

    @staticmethod
    def _regular_files(run_root: Path) -> list[Path]:
        # os.walk(followlinks=False) never descends into symlinked directories.
        files: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(run_root, followlinks=False):
            dirnames[:] = sorted(name for name in dirnames if not (Path(dirpath) / name).is_symlink())
            for name in filenames:
                candidate = Path(dirpath) / name
                if candidate.is_symlink() or not candidate.is_file():
                    continue
                files.append(candidate)
        return sorted(files)

    @staticmethod
    def _atomic_write(path: Path, payload: bytes) -> None:
        # Progress files (stage events, engine invocations) are rewritten while another
        # thread or process may be reading them; a rename makes each version whole.
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        tmp.write_bytes(payload)
        os.replace(tmp, path)

    def write_json(self, run_id: str, file_name: str, payload: Any) -> str:
        if self.scrubber:
            payload = self.scrubber.scrub(payload)
        path = self.run_dir(run_id) / file_name
        self._atomic_write(path, json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8"))
        return str(path)

    def write_text(self, run_id: str, file_name: str, content: str) -> str:
        if self.scrubber:
            content = self.scrubber.scrub_text(content)
        path = self.run_dir(run_id) / file_name
        self._atomic_write(path, content.encode("utf-8"))
        return str(path)

    def write_bytes(self, run_id: str, file_name: str, payload: bytes) -> str:
        if self.scrubber:
            payload = self.scrubber.scrub_bytes(payload)
        path = self.run_dir(run_id) / file_name
        self._atomic_write(path, payload)
        return str(path)

    def copy_file(self, run_id: str, source_file: str | Path, dest_name: str | None = None) -> str:
        src = Path(source_file)
        if not src.exists():
            raise FileNotFoundError(src)
        payload = src.read_bytes()
        if self.scrubber:
            payload = self.scrubber.scrub_bytes(payload)
        dst = self.run_dir(run_id) / (dest_name or src.name)
        self._atomic_write(dst, payload)
        return str(dst)

    def list_run_files(self, run_id: str) -> list[Path]:
        root = self.run_dir(run_id)
        return sorted([p for p in root.rglob("*") if p.is_file()])
