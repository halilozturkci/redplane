"""Runtime extras that unit tests historically never imported."""

from __future__ import annotations


def test_azure_evaluation_identity_openai_and_fastapi_import() -> None:
    import azure.ai.evaluation  # noqa: F401
    import azure.identity  # noqa: F401
    import fastapi  # noqa: F401
    import openai  # noqa: F401
    import yaml  # noqa: F401
