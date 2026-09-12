"""Runtime extras that unit tests historically never imported."""

from __future__ import annotations


def test_azure_evaluation_identity_openai_pyrit_and_fastapi_import() -> None:
    import azure.ai.evaluation  # noqa: F401
    import azure.identity  # noqa: F401
    import fastapi  # noqa: F401
    import openai  # noqa: F401
    import pyrit  # noqa: F401
    import yaml  # noqa: F401

    assert openai.__version__.startswith("3.")
    from importlib.metadata import version

    assert version("pyrit").startswith("1.")
    assert not hasattr(azure.ai.evaluation, "require_redteam_extra")
