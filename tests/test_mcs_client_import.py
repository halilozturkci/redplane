"""Copilot Studio GA extra is optional; skip when it is not synced."""

from __future__ import annotations

import pytest


def test_microsoft_agents_copilotstudio_client_imports() -> None:
    pytest.importorskip("microsoft_agents.copilotstudio.client")
    from microsoft_agents.copilotstudio.client import (
        AgentType,
        ConnectionSettings,
        CopilotClient,
        PowerPlatformCloud,
    )

    assert ConnectionSettings is not None
    assert CopilotClient is not None
    assert PowerPlatformCloud is not None
    assert AgentType is not None
