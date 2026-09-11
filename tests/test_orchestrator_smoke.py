from pathlib import Path

from urt.orchestrator import Orchestrator
from urt.types import RunSpec


def test_orchestrator_smoke(tmp_path: Path):
    artifact_root = tmp_path / "artifacts"
    metadata_db = tmp_path / "meta.sqlite3"

    spec = RunSpec.from_dict(
        {
            "name": "smoke",
            "run_profile": "pr_gate",
            "targets": [
                {
                    "id": "local-http",
                    "type": "http",
                    "endpoint": "http://localhost:9999/invoke",
                    "config": {"skip_healthcheck": True},
                }
            ],
            "engines": [
                {"name": "promptfoo", "params": {"command": "promptfoo --version"}},
                {"name": "garak", "params": {"command": "garak --version"}},
            ],
        }
    )

    orchestrator = Orchestrator(artifact_root=str(artifact_root), metadata_db=str(metadata_db))
    result = orchestrator.execute(spec)

    assert result["run_id"].startswith("run-smoke-")
    assert result["status"] == "completed"

    run = orchestrator.get_run(result["run_id"])
    assert run is not None
    assert run["status"] == "completed"

    findings = orchestrator.get_findings(result["run_id"])
    assert isinstance(findings, list)
    assert len(findings) >= 2

    artifacts = orchestrator.list_artifacts(result["run_id"])
    artifact_paths = {item["path"] for item in artifacts}
    assert "run_manifest.json" in artifact_paths
    assert "engine_invocations.json" in artifact_paths
    assert "artifacts_index.json" in artifact_paths
    assert "report.md" in artifact_paths
    assert "report.html" in artifact_paths
    assert "report.csv" in artifact_paths
