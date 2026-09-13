"""Pinned engine/evaluator CLI versions for installers, templates, and ``urt init``.

Bash installers keep their own literals (bootstrap cannot import ``urt``).
Tests require those literals to equal this table. Do not enable the
inspect-ai ``dev`` extra (kitchen-sink; optional ``openai>=3.1``).
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
    extras: str = ""
    with_packages: tuple[str, ...] = ()

    @property
    def spec(self) -> str:
        extra = f"[{self.extras}]" if self.extras else ""
        return f"{self.package}{extra}=={self.version}"

    @property
    def quoted_spec(self) -> str:
        if self.extras:
            return f"'{self.spec}'"
        return self.spec

    @property
    def uvx_command(self) -> str:
        parts = ["uvx"]
        if self.inject_python_flag:
            parts.extend(["--python", self.python])
        parts.extend(["--from", self.quoted_spec])
        for extra_pkg in self.with_packages:
            parts.extend(["--with", extra_pkg])
        parts.append(self.argv)
        return " ".join(parts)


ENGINE_PINS: tuple[EnginePin, ...] = (
    EnginePin("garak", "0.17.0", "3.12", "garak --version"),
    EnginePin("powerpwn", "6.0.0", "3.11", "powerpwn --help"),
    EnginePin(
        "deepteam",
        "1.0.9",
        "3.12",
        "deepteam --help",
        with_packages=("sentry-sdk",),
    ),
    EnginePin("inspect-ai", "0.3.263", "3.12", "inspect --help"),
    EnginePin("deepeval", "4.2.2", "3.12", "deepeval --help"),
    EnginePin(
        "giskard",
        "3.0.0",
        "3.12",
        'python -c "from giskard.scan import vulnerability_scan; print(\'giskard-scan-ok\')"',
        uv_tool=False,
        inject_python_flag=True,
        extras="scan",
    ),
)

PIN_BY_PACKAGE: dict[str, EnginePin] = {item.package: item for item in ENGINE_PINS}


def pin(package: str) -> EnginePin:
    return PIN_BY_PACKAGE[package]
