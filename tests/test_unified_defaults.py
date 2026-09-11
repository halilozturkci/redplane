from urt.adapters.engines.pyrit_engine import DEFAULT_CONFIG_PATH, DEFAULT_SCRIPT_PATH
from urt.adapters.targets.copilot import CopilotTargetAdapter
from urt.constants import DEFAULT_ARTIFACT_ROOT, DEFAULT_METADATA_DB
from urt.types import TargetSpec


def test_state_defaults_point_to_urt_state() -> None:
    assert DEFAULT_ARTIFACT_ROOT == ".urt_state/artifacts"
    assert DEFAULT_METADATA_DB == ".urt_state/metadata/urt.sqlite3"


def test_internalized_pyrit_defaults_exist() -> None:
    assert DEFAULT_SCRIPT_PATH.exists()
    assert DEFAULT_CONFIG_PATH.exists()


def test_copilot_sdk_healthcheck_uses_internal_default_module() -> None:
    spec = TargetSpec.from_dict(
        {
            "id": "copilot-sdk",
            "type": "copilot",
            "config": {
                "mode": "sdk",
                "tenant_id": "tenant",
                "app_client_id": "client",
                "environment_id": "env",
                "agent_identifier": "agent",
            },
        }
    )
    adapter = CopilotTargetAdapter(spec)
    ok, detail = adapter.healthcheck()
    assert ok is True, detail
