"""G2: artifact reads are confined to the run directory (no traversal, no symlinks)."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from urt.storage.artifact_store import ArtifactPathError, ArtifactStore


@pytest.fixture
def store(tmp_path: Path) -> ArtifactStore:
    root = tmp_path / "artifacts"
    store = ArtifactStore(root)
    store.write_text("run-a", "report.md", "# a")
    store.write_text("run-a", "raw/garak/t1_stdout.log", "stdout")
    store.write_text("run-b", "report.md", "# b")
    (tmp_path / "outside.txt").write_text("secret", encoding="utf-8")
    (root / "run-a" / "link-out.txt").symlink_to(tmp_path / "outside.txt")
    (root / "run-a" / "link-dir").symlink_to(root / "run-b")
    (root / "run-a" / "link-in.md").symlink_to(root / "run-a" / "report.md")
    return store


def test_resolve_artifact_returns_files_inside_the_run(store: ArtifactStore):
    resolved = store.resolve_artifact("run-a", "raw/garak/t1_stdout.log")
    assert resolved.read_text(encoding="utf-8") == "stdout"
    assert store.resolve_artifact("run-a", "report.md").read_text(encoding="utf-8") == "# a"


@pytest.mark.parametrize(
    "relative_path",
    [
        "../run-b/report.md",
        "raw/../../run-b/report.md",
        "/etc/passwd",
        "raw/./garak/t1_stdout.log",
        "",
        "raw//garak/t1_stdout.log",
        "raw\\garak\\t1_stdout.log",
    ],
)
def test_resolve_artifact_rejects_traversal_and_malformed_paths(store: ArtifactStore, relative_path: str):
    with pytest.raises(ArtifactPathError):
        store.resolve_artifact("run-a", relative_path)


@pytest.mark.parametrize("relative_path", ["link-out.txt", "link-dir/report.md", "link-in.md"])
def test_resolve_artifact_rejects_symlinks_even_when_they_point_inside(store: ArtifactStore, relative_path: str):
    with pytest.raises(ArtifactPathError):
        store.resolve_artifact("run-a", relative_path)


@pytest.mark.parametrize("run_id", ["../run-b", "run-a/..", "", ".", "run-x"])
def test_resolve_artifact_rejects_bad_or_unknown_run_ids(store: ArtifactStore, run_id: str):
    with pytest.raises((ArtifactPathError, FileNotFoundError)):
        store.resolve_artifact(run_id, "report.md")


def test_resolve_artifact_missing_file_is_not_found(store: ArtifactStore):
    with pytest.raises(FileNotFoundError):
        store.resolve_artifact("run-a", "nope.json")
    with pytest.raises(FileNotFoundError):
        store.resolve_artifact("run-a", "raw")  # a directory, not a file


def test_zip_run_contains_regular_files_only(store: ArtifactStore):
    payload = store.zip_run("run-a")
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        names = sorted(archive.namelist())
        assert names == ["run-a/raw/garak/t1_stdout.log", "run-a/report.md"]
        assert archive.read("run-a/report.md") == b"# a"


def test_relative_artifact_path_maps_absolute_refs_into_the_bundle(store: ArtifactStore):
    inside = store.root_dir / "run-a" / "raw" / "garak" / "t1_stdout.log"
    assert store.relative_artifact_path("run-a", str(inside)) == "raw/garak/t1_stdout.log"
    assert store.relative_artifact_path("run-a", str(store.root_dir / "run-b" / "report.md")) is None
    assert store.relative_artifact_path("run-a", "/etc/passwd") is None
    assert store.relative_artifact_path("run-a", "not/absolute") is None
