from urt.types import RunSpec, ValidationError


def test_runspec_validates_supported_types():
    spec = RunSpec.from_dict(
        {
            "name": "test-run",
            "run_profile": "nightly",
            "targets": [
                {
                    "id": "t1",
                    "type": "http",
                    "endpoint": "http://localhost:9000/invoke",
                    "config": {"skip_healthcheck": True},
                }
            ],
            "engines": [
                {"name": "promptfoo", "params": {"command": "promptfoo --version"}},
                {"name": "deepteam", "params": {"command": "deepteam --help"}},
            ],
        }
    )
    assert spec.name == "test-run"
    assert spec.targets[0].target_type == "http"
    assert spec.engines[0].name == "promptfoo"
    assert spec.engines[1].name == "deepteam"


def test_runspec_requires_targets():
    try:
        RunSpec.from_dict(
            {
                "name": "bad-run",
                "run_profile": "nightly",
                "targets": [],
                "engines": [{"name": "pyrit", "params": {"config_path": "x"}}],
            }
        )
        assert False, "ValidationError expected"
    except ValidationError as exc:
        assert "At least one target" in str(exc)
