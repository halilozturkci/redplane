"""Copilot Studio GA extra is optional for core pytest; skip when not synced."""

from __future__ import annotations

import pytest


def test_mcs_integration_modules_import() -> None:
    pytest.importorskip("microsoft_agents.copilotstudio.client")
    pytest.importorskip("microsoft_agents.activity")
    from urt.integrations.mcs_pyrit import copilot_client
    from urt.integrations.mcs_pyrit.targets import mcs_agent_callback

    assert callable(copilot_client.McsCopilotClient)
    assert mcs_agent_callback.ActivityTypes.message == "message"
    assert mcs_agent_callback.ActivityTypes.__module__.startswith("microsoft_agents")
