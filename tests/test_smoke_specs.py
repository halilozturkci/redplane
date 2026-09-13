"""Smoke RunSpecs are launcher-presence only; real samples do not point at missing scripts."""

from __future__ import annotations

from pathlib import Path

from urt.cli import _template_payload, main
from urt.config import load_run_spec
from urt.engine_pins import pin

REPO = Path(__file__).resolve().parents[1]
SMOKE_SPECS = (
    REPO / "templates" / "run_spec.smoke.yaml",
    REPO / "templates" / "run_spec.sample.yaml",
)
_MISSING_SCRIPTS = (
    "scripts/run_azure_eval.py",
    "scripts/custom_eval.py",
    "tasks/safety_eval.py",
)
_REAL_SPECS = (
    REPO / "templates" / "run_spec.mcs_real.sample.yaml",
    REPO / "templates" / "run_spec.promptfoo_dataset.sample.yaml",
    REPO / "templates" / "run_spec.deepteam_seeded.sample.yaml",
    REPO / "templates" / "run_spec.promptfoo_gateway.sample.yaml",
    REPO / "templates" / "run_spec.eval_after_attack.sample.yaml",
)


def test_smoke_yaml_files_exist_and_declare_smoke_kind() -> None:
    for path in SMOKE_SPECS:
        assert path.is_file(), path
        spec = load_run_spec(path)
        assert spec.metadata.get("spec_kind") == "smoke"
        for evaluator in spec.evaluators:
            assert "output_json" not in evaluator.params
            command = str(evaluator.params.get("command") or "")
            for missing in _MISSING_SCRIPTS:
                assert missing not in command
            assert "script_path" not in evaluator.params or evaluator.params.get("script_path") not in _MISSING_SCRIPTS


def test_smoke_engine_commands_are_launcher_presence() -> None:
    spec = load_run_spec(REPO / "templates" / "run_spec.smoke.yaml")
    by_name = {item.name: item for item in spec.engines}
    assert by_name["promptfoo"].params["command"] == "promptfoo --version"
    assert by_name["garak"].params["command"] == pin("garak").uvx_command
    assert "--help" in by_name["powerpwn"].params["command"] or "--version" in by_name["powerpwn"].params["command"]
    assert "--help" in by_name["deepteam"].params["command"]
    assert "--help" in by_name["inspect"].params["command"]


def test_init_writes_smoke_spec_by_default(tmp_path: Path) -> None:
    output = tmp_path / "run_spec.yaml"
    assert main(["init", "--output", str(output)]) == 0
    spec = load_run_spec(output)
    assert spec.metadata.get("spec_kind") == "smoke"
    assert all("output_json" not in item.params for item in spec.evaluators)


def test_init_smoke_flag_writes_the_same_kind(tmp_path: Path) -> None:
    output = tmp_path / "smoke.yaml"
    assert main(["init", "--smoke", "--output", str(output)]) == 0
    spec = load_run_spec(output)
    assert spec.metadata.get("spec_kind") == "smoke"
    payload = _template_payload()
    assert payload["metadata"]["spec_kind"] == "smoke"


def test_referenced_eval_scripts_are_shipped_or_dropped() -> None:
    sample = (REPO / "templates" / "run_spec.sample.yaml").read_text(encoding="utf-8")
    smoke = (REPO / "templates" / "run_spec.smoke.yaml").read_text(encoding="utf-8")
    init_payload = str(_template_payload())
    for missing in _MISSING_SCRIPTS:
        assert missing not in sample
        assert missing not in smoke
        assert missing not in init_payload
    eval_script = REPO / "scripts" / "eval_engine_findings.py"
    assert eval_script.is_file()
    source = eval_script.read_text(encoding="utf-8")
    for forbidden in ("deepeval", "giskard", "inspect_ai", "azure.ai.evaluation", "import urt"):
        assert forbidden not in source


def test_real_samples_do_not_advertise_missing_eval_scripts() -> None:
    for path in _REAL_SPECS:
        assert path.is_file(), path
        text = path.read_text(encoding="utf-8")
        for missing in _MISSING_SCRIPTS:
            assert missing not in text
        spec = load_run_spec(path)
        assert spec.metadata.get("spec_kind") != "smoke"
