"""`urt report` renders the self-contained viewer with the waivers stored right now."""

from __future__ import annotations

from pathlib import Path

from conftest import TARGET_ID, Bundle

from urt.cli import main


def _cli(bundle: Bundle, *args: str) -> list[str]:
    return [
        "--artifact-root",
        str(bundle.orchestrator.artifact_store.root_dir),
        "--metadata-db",
        str(bundle.orchestrator.metadata_store.db_path),
        *args,
    ]


def test_report_html_reflects_waivers_created_after_the_run(rich_bundle: Bundle, capsys):
    run_id = rich_bundle.run_id
    before = (rich_bundle.run_dir / "report.html").read_text(encoding="utf-8")
    assert "w-garak-dan" not in before

    assert (
        main(
            _cli(
                rich_bundle,
                "waivers",
                "create",
                "--target-id",
                TARGET_ID,
                "--control-id",
                "mitigation.MitigationBypass",
                "--reason",
                "known DAN bypass",
                "--owner",
                "sec-lead",
                "--expires-at",
                "2099-01-01T00:00:00+00:00",
                "--waiver-id",
                "w-garak-dan",
            )
        )
        == 0
    )
    capsys.readouterr()

    assert main(_cli(rich_bundle, "report", "--run-id", run_id, "--format", "html")) == 0
    printed = capsys.readouterr().out
    assert "w-garak-dan" in printed
    assert "Gate failed: at least one finding severity &gt;= HIGH (1 waived)" in printed

    # --in-place rewrites the bundle's own report files and the index.
    assert main(_cli(rich_bundle, "report", "--run-id", run_id, "--in-place")) == 0
    after = (rich_bundle.run_dir / "report.html").read_text(encoding="utf-8")
    assert "w-garak-dan" in after
    index = {row["path"]: row for row in rich_bundle.read_json("artifacts_index.json")}
    import hashlib

    assert index["report.html"]["sha256"] == hashlib.sha256(after.encode("utf-8")).hexdigest()
    assert f"Report bundle refreshed in {rich_bundle.run_dir}" in capsys.readouterr().out


def test_report_output_dir_writes_the_viewer_and_warns_about_relative_links(rich_bundle: Bundle, tmp_path: Path, capsys):
    out = tmp_path / "reports"
    assert main(_cli(rich_bundle, "report", "--run-id", rich_bundle.run_id, "--output-dir", str(out))) == 0
    assert (out / "report.html").exists()
    assert (out / "report.md").exists()
    assert (out / "report.csv").exists()
    html = (out / "report.html").read_text(encoding="utf-8")
    assert 'id="redplane-data"' in html
    assert "relative to the run directory" in capsys.readouterr().out
