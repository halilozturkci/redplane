"""Power CAT Copilot Studio Kit engine adapter."""

from __future__ import annotations

import shlex
from pathlib import Path

from ..engine_base import EngineContext
from ...types import UnifiedFinding
from ._command import CommandEngineAdapter


class PowerCatEngineAdapter(CommandEngineAdapter):
    command_name = "copilot-studio-kit"

    @property
    def name(self) -> str:
        return "powercat"

    def run(self, context: EngineContext):
        command = self.spec.params.get("command")
        if not command:
            command = ["copilot-studio-kit", "agent-review", "run"]

        if isinstance(command, str):
            command_list = shlex.split(command)
        else:
            command_list = [str(part) for part in command]

        launcher = command_list[0]
        if not self._command_exists(launcher):
            # fallback for npm package invocation when native CLI is absent
            if launcher != "copilot-studio-kit":
                return self._skipped_result(
                    context,
                    f"powercat command launcher not found in PATH: {launcher}",
                )
            if not self._command_exists("npx"):
                return self._skipped_result(context, "copilot-studio-kit or npx not found in PATH")
            command_list = ["npx", "@microsoft/copilot-studio-kit-cli", *command_list[1:]]

        result = self._result_from_command(
            context,
            command_list,
            artifact_name_prefix="powercat",
        )

        stdout_text = ""
        stderr_text = ""
        if result.artifacts:
            stdout_artifact = Path(result.artifacts[0])
            if stdout_artifact.exists():
                stdout_text = stdout_artifact.read_text(encoding="utf-8", errors="replace")
                text = stdout_text.lower()
                warnings = []
                if "anti-pattern" in text or "warning" in text:
                    warnings.append("governance_warning")
                if "non-compliant" in text or "compliance" in text:
                    warnings.append("compliance_signal")
                if "failed" in text:
                    warnings.append("quality_gate_failure_signal")

                for idx, warning in enumerate(warnings):
                    result.findings.append(
                        UnifiedFinding(
                            finding_id=f"{context.run_id}:{context.target.target_id}:powercat:signal:{idx}",
                            run_id=context.run_id,
                            target_id=context.target.target_id,
                            engine="powercat",
                            category="policy_violation",
                            sub_category=warning,
                            severity="low",
                            confidence=0.55,
                            attack_vector="governance_scan",
                            attack_complexity="n/a",
                            success=True,
                            description=f"Power CAT output contains signal: {warning}",
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
        stdout_text: str,
        stderr_text: str,
        evidence_refs: list[str],
    ) -> list[UnifiedFinding]:
        combined = f"{stdout_text}\n{stderr_text}".lower()
        if not combined.strip():
            return []

        indicators = [
            ("package_not_found", "npm error code e404", "medium", "Power CAT npm package not found"),
            ("package_not_found", "could not be found", "medium", "Power CAT npm package not found"),
            ("registry_not_found", "not found - get https://registry.npmjs.org", "medium", "Power CAT npm registry lookup failed"),
            ("auth_expired", "access token expired or revoked", "medium", "Power CAT npm auth token expired/revoked"),
            ("permission_denied", "you do not have permission", "medium", "Power CAT package permission denied"),
        ]

        findings: list[UnifiedFinding] = []
        seen: set[str] = set()
        for sub_category, needle, severity, description in indicators:
            if needle not in combined or sub_category in seen:
                continue
            seen.add(sub_category)
            findings.append(
                UnifiedFinding(
                    finding_id=f"{run_id}:{target_id}:powercat:{sub_category}",
                    run_id=run_id,
                    target_id=target_id,
                    engine="powercat",
                    category="coverage_gap",
                    sub_category=sub_category,
                    severity=severity,
                    confidence=0.9,
                    attack_vector="engine_runtime",
                    attack_complexity="n/a",
                    success=False,
                    description=description,
                    evidence_refs=evidence_refs,
                )
            )
        return findings
