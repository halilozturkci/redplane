"""Pinned engine CLI versions for installers, templates, and ``urt init``.

Keep these literals identical in ``scripts/install_engine_tools_uv.sh``,
``scripts/verify_engine_tooling.sh``, ``templates/run_spec.sample.yaml``,
and README examples. Do not enable the inspect-ai ``dev`` extra (it pulls
openai 3). Hold giskard 3.x.
"""

from __future__ import annotations

GARAK = "garak==0.17.0"
POWERPWN = "powerpwn==6.0.0"
DEEPTEAM = "deepteam==1.0.9"
INSPECT_AI = "inspect-ai==0.3.263"
GISKARD = "giskard==2.19.2"

GARAK_PYTHON = "3.12"
POWERPWN_PYTHON = "3.11"
DEEPTEAM_PYTHON = "3.12"
INSPECT_AI_PYTHON = "3.12"
GISKARD_PYTHON = "3.12"

GARAK_VERSION_COMMAND = f"uvx --from {GARAK} garak --version"
POWERPWN_HELP_COMMAND = f"uvx --from {POWERPWN} powerpwn --help"
DEEPTEAM_HELP_COMMAND = f"uvx --from {DEEPTEAM} deepteam --help"
INSPECT_HELP_COMMAND = f"uvx --from {INSPECT_AI} inspect --help"
GISKARD_VERSION_COMMAND = (
    f'uvx --python {GISKARD_PYTHON} --from {GISKARD} python -c "import giskard; print(giskard.__version__)"'
)

INSTALL_TOOLS: tuple[tuple[str, str], ...] = (
    (GARAK, GARAK_PYTHON),
    (POWERPWN, POWERPWN_PYTHON),
    (DEEPTEAM, DEEPTEAM_PYTHON),
    (INSPECT_AI, INSPECT_AI_PYTHON),
)
