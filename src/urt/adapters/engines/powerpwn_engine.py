"""PowerPwn engine adapter."""

from __future__ import annotations

import shlex
from pathlib import Path

from ..engine_base import EngineContext
from ...types import UnifiedFinding
from ._command import CommandEngineAdapter


class PowerPwnEngineAdapter(CommandEngineAdapter):
    command_name = "powerpwn"

    @property
    def name(self) -> str:
        return "powerpwn"

    def run(self, context: EngineContext):
        mode = str(self.spec.params.get("mode", "recon-only"))
        if mode != "recon-only" and not bool(self.spec.params.get("approved", False)):
            return self._skipped_result(
                context,
                "PowerPwn active mode blocked: set params.approved=true after explicit authorization",
            )

        command = self.spec.params.get("command")
        if not command:
            command = ["powerpwn", "copilot-studio-hunter", "enum"]

        if isinstance(command, str):
            command_list = shlex.split(command)
        else:
            command_list = [str(part) for part in command]

        if not self._command_exists(command_list[0]):
            return self._skipped_result(
                context,
                f"powerpwn command launcher not found in PATH: {command_list[0]}",
            )

        result = self._result_from_command(
            context,
            command_list,
            artifact_name_prefix="powerpwn",
            parse_payload={"mode": mode},
        )

        stdout_text = ""
        stderr_text = ""
        if result.artifacts:
            stdout_artifact = Path(result.artifacts[0])
            if stdout_artifact.exists():
                stdout_text = stdout_artifact.read_text(encoding="utf-8", errors="replace")
                text = stdout_text.lower()
                signals = []
                if "public" in text or "anonymous" in text:
                    signals.append("potential_public_exposure")
                if "hard-coded" in text or "credential" in text or "secret" in text:
                    signals.append("credential_exposure_signal")
                if "http request" in text or "unsafe http" in text:
                    signals.append("unsafe_http_signal")

                for idx, signal in enumerate(signals):
                    result.findings.append(
                        UnifiedFinding(
                            finding_id=f"{context.run_id}:{context.target.target_id}:powerpwn:signal:{idx}",
                            run_id=context.run_id,
                            target_id=context.target.target_id,
                            engine="powerpwn",
                            category="misconfiguration",
                            sub_category=signal,
                            severity="medium",
                            confidence=0.6,
                            attack_vector="recon_signal",
                            attack_complexity=mode,
                            success=True,
                            description=f"PowerPwn output contains signal: {signal}",
                            evidence_refs=[str(stdout_artifact)],
                        )
                    )

        if len(result.artifacts) > 1:
            stderr_artifact = Path(result.artifacts[1])
            if stderr_artifact.exists():
                stderr_text = stderr_artifact.read_text(encoding="utf-8", errors="replace")

        result.findings.extend(
            self._runtime_gap_findings(
                run_id=context.run_id,
                target_id=context.target.target_id,
                mode=mode,
                stdout_text=stdout_text,
                stderr_text=stderr_text,
                evidence_refs=result.artifacts[:2],
            )
        )

        return result

    def _runtime_gap_findings(
        self,
        *,
        run_id: str,
        target_id: str,
        mode: str,
        stdout_text: str,
        stderr_text: str,
        evidence_refs: list[str],
    ) -> list[UnifiedFinding]:
        combined = f"{stdout_text}\n{stderr_text}".lower()
        if not combined.strip():
            return []

        indicators = [
            ("module_missing", "cannot find module", "medium", "PowerPwn runtime dependency/module missing"),
            ("puppeteer_error", "error occurred while running puppeteer", "medium", "PowerPwn Puppeteer runtime error"),
            ("node_runtime_error", "node:internal/modules", "medium", "PowerPwn Node runtime error"),
            ("non_zero_exit", "returned non-zero exit status", "medium", "PowerPwn subprocess non-zero exit"),
            ("no_results", "no results were generated", "low", "PowerPwn produced no recon results"),
        ]

        findings: list[UnifiedFinding] = []
        seen: set[str] = set()
        for sub_category, needle, severity, description in indicators:
            if needle not in combined or sub_category in seen:
                continue
            seen.add(sub_category)
            findings.append(
                UnifiedFinding(
                    finding_id=f"{run_id}:{target_id}:powerpwn:{sub_category}",
                    run_id=run_id,
                    target_id=target_id,
                    engine="powerpwn",
                    category="coverage_gap",
                    sub_category=sub_category,
                    severity=severity,
                    confidence=0.9,
                    attack_vector="engine_runtime",
                    attack_complexity=mode,
                    success=False,
                    description=description,
                    evidence_refs=evidence_refs,
                    metadata={"mode": mode},
                )
            )
        return findings
