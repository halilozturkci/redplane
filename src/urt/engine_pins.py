"""Pinned engine CLI versions for installers, templates, and ``urt init``.

Bash installers keep their own literals (bootstrap cannot import ``urt``).
Tests require those literals to equal this table. Do not enable the
inspect-ai ``dev`` extra (it pulls openai 3). Hold giskard 3.x.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class EnginePin:
    package: str
    version: str
    python: str
    argv: str
    uv_tool: bool = True
    inject_python_flag: bool = False

    @property
    def spec(self) -> str:
        return f"{self.package}=={self.version}"

    @property
    def uvx_command(self) -> str:
        prefix = "uvx"
        if self.inject_python_flag:
            prefix = f"uvx --python {self.python}"
        return f"{prefix} --from {self.spec} {self.argv}"


ENGINE_PINS: tuple[EnginePin, ...] = (
    EnginePin("garak", "0.17.0", "3.12", "garak --version"),
    EnginePin("powerpwn", "6.0.0", "3.11", "powerpwn --help"),
    EnginePin("deepteam", "1.0.9", "3.12", "deepteam --help"),
    EnginePin("inspect-ai", "0.3.263", "3.12", "inspect --help"),
    EnginePin(
        "giskard",
        "2.19.2",
        "3.12",
        'python -c "import giskard; print(giskard.__version__)"',
        uv_tool=False,
        inject_python_flag=True,
    ),
)

PIN_BY_PACKAGE: dict[str, EnginePin] = {item.package: item for item in ENGINE_PINS}


def pin(package: str) -> EnginePin:
    return PIN_BY_PACKAGE[package]
