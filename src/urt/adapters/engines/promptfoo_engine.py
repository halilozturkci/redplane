"""Promptfoo engine adapter."""

from __future__ import annotations

import csv
import copy
import json
import os
import shlex
from pathlib import Path
from typing import Any

from ..engine_base import EngineContext
from ...runtime import filter_names_by_scenarios, row_matches_scenarios
from ...types import EngineRunResult, UnifiedFinding
from ._command import CommandEngineAdapter

PROJECT_ROOT = Path(__file__).resolve().parents[4]
PROMPTFOO_PRESETS: dict[str, Path] = {
    "copilot_security_starter": PROJECT_ROOT / "examples/promptfoo_presets/copilot_security_starter.jsonl",
    "jailbreakbench": PROJECT_ROOT / "examples/promptfoo_presets/jailbreakbench_starter.jsonl",
    "jailbreakbench_starter": PROJECT_ROOT / "examples/promptfoo_presets/jailbreakbench_starter.jsonl",
    "harmbench": PROJECT_ROOT / "examples/promptfoo_presets/harmbench_starter.jsonl",
    "harmbench_starter": PROJECT_ROOT / "examples/promptfoo_presets/harmbench_starter.jsonl",
    "xstest": PROJECT_ROOT / "examples/promptfoo_presets/xstest_starter.jsonl",
    "xstest_starter": PROJECT_ROOT / "examples/promptfoo_presets/xstest_starter.jsonl",
    "donotanswer": PROJECT_ROOT / "examples/promptfoo_presets/donotanswer_starter.jsonl",
    "donotanswer_starter": PROJECT_ROOT / "examples/promptfoo_presets/donotanswer_starter.jsonl",
    "do_not_answer": PROJECT_ROOT / "examples/promptfoo_presets/donotanswer_starter.jsonl",
    "beavertails": PROJECT_ROOT / "examples/promptfoo_presets/beavertails_starter.jsonl",
    "beavertails_starter": PROJECT_ROOT / "examples/promptfoo_presets/beavertails_starter.jsonl",
    "aegis": PROJECT_ROOT / "examples/promptfoo_presets/aegis_starter.jsonl",
    "aegis_starter": PROJECT_ROOT / "examples/promptfoo_presets/aegis_starter.jsonl",
    "bipia": PROJECT_ROOT / "examples/promptfoo_presets/bipia_indirect_injection_starter.jsonl",
    "bipia_indirect_injection": PROJECT_ROOT / "examples/promptfoo_presets/bipia_indirect_injection_starter.jsonl",
    "bipia_indirect_injection_starter": PROJECT_ROOT / "examples/promptfoo_presets/bipia_indirect_injection_starter.jsonl",
    "cyberseceval": PROJECT_ROOT / "examples/promptfoo_presets/cyberseceval_starter.jsonl",
    "cyberseceval_starter": PROJECT_ROOT / "examples/promptfoo_presets/cyberseceval_starter.jsonl",
    "simplesafetytests": PROJECT_ROOT / "examples/promptfoo_presets/simplesafetytests_starter.jsonl",
    "simplesafetytests_starter": PROJECT_ROOT / "examples/promptfoo_presets/simplesafetytests_starter.jsonl",
    "agentic_tool_abuse": PROJECT_ROOT / "examples/promptfoo_presets/agentic_tool_abuse_starter.jsonl",
    "agentic_tool_abuse_starter": PROJECT_ROOT / "examples/promptfoo_presets/agentic_tool_abuse_starter.jsonl",
}
PROMPTFOO_PRESET_PROFILES: dict[str, list[str]] = {
    "fast": ["copilot_security_starter", "xstest_starter"],
    "smoke": ["copilot_security_starter", "xstest_starter"],
    "balanced": ["copilot_security_starter", "jailbreakbench_starter", "harmbench_starter", "xstest_starter"],
    "agentic": ["copilot_security_starter", "agentic_tool_abuse_starter", "bipia_indirect_injection_starter"],
    "cyber": ["cyberseceval_starter", "xstest_starter"],
}
PROMPT_FIELD_FALLBACKS: tuple[str, ...] = (
    "attack_prompt",
    "prompt",
    "input",
    "text",
    "question",
    "instruction",
    "message",
)


class PromptfooEngineAdapter(CommandEngineAdapter):
    command_name = "promptfoo"

    @property
    def name(self) -> str:
        return "promptfoo"

    def run(self, context: EngineContext) -> EngineRunResult:
        generated_config_artifact: str | None = None
        dataset_meta_artifact: str | None = None

        command, output_json = self._resolve_command_and_output(context)
        if isinstance(command, EngineRunResult):
            return command
        command_list = command

        command_list = self._resolve_promptfoo_launcher(command_list)
        if not self._launcher_exists(command_list[0]):
            return self._skipped_result(
                context,
                (
                    f"promptfoo command launcher not found in PATH: {command_list[0]} "
                    "(hint: run scripts/install_promptfoo_local.sh or set URT_PROMPTFOO_BIN)"
                ),
            )

        prompt_source = self.spec.params.get("prompt_source")
        if prompt_source:
            generated_config_artifact, dataset_meta_artifact = self._build_prompt_source_artifacts(
                context=context,
                prompt_source=prompt_source,
            )

            # Rebuild command against generated config if prompt_source mode is active.
            dataset_config_path = str(Path(generated_config_artifact).resolve())
            output_json = output_json or str(
                context.artifact_store.run_dir(context.run_id) / f"raw/promptfoo/{context.target.target_id}_output.json"
            )
            command_list = self._resolve_promptfoo_launcher(
                self._build_eval_command(config_path=dataset_config_path, output_json=output_json)
            )
            if not self._launcher_exists(command_list[0]):
                return self._skipped_result(
                    context,
                    (
                        f"promptfoo command launcher not found in PATH: {command_list[0]} "
                        "(hint: run scripts/install_promptfoo_local.sh or set URT_PROMPTFOO_BIN)"
                    ),
                )

        env_overrides = self._build_env_overrides(context)
        working_dir = self.spec.params.get("working_dir")
        result = self._result_from_command(
            context,
            command_list,
            artifact_name_prefix="promptfoo",
            env_overrides=env_overrides,
            cwd=working_dir,
        )

        if generated_config_artifact:
            result.artifacts.append(generated_config_artifact)
        if dataset_meta_artifact:
            result.artifacts.append(dataset_meta_artifact)

        if output_json:
            output_path = Path(str(output_json))
            if output_path.exists():
                copied = str(output_path)
                run_root = context.artifact_store.run_dir(context.run_id)
                if run_root not in output_path.parents:
                    copied = self._copy_artifact(
                        context,
                        output_path,
                        f"raw/promptfoo/{context.target.target_id}_output.json",
                    )
                result.artifacts.append(copied)
                result.findings.extend(
                    self._parse_promptfoo_output(
                        run_id=context.run_id,
                        target_id=context.target.target_id,
                        output_path=output_path,
                    )
                )

        return result

    def _resolve_command_and_output(
        self, context: EngineContext
    ) -> tuple[list[str], str | None] | EngineRunResult:
        output_json = self.spec.params.get("output_json")
        command = self.spec.params.get("command")
        if command:
            if isinstance(command, str):
                return shlex.split(command), str(output_json) if output_json else None
            return [str(part) for part in command], str(output_json) if output_json else None

        config_path = self.spec.params.get("config_path")
        if not config_path:
            if self.spec.params.get("prompt_source"):
                # prompt_source mode builds command later after generated config is created.
                return ["promptfoo"], str(output_json) if output_json else None
            return self._skipped_result(
                context,
                "promptfoo requires params.command, params.config_path, or params.prompt_source",
            )

        mode = str(self.spec.params.get("mode", "eval")).strip().lower()
        if mode not in {"eval", "redteam"}:
            mode = "eval"
        if mode == "redteam":
            return ["promptfoo", "redteam", "run", "--config", str(config_path)], str(output_json) if output_json else None

        output_path = str(output_json) if output_json else None
        command_list = self._build_eval_command(config_path=str(config_path), output_json=output_path)
        return command_list, output_path

    def _build_eval_command(self, *, config_path: str, output_json: str | None) -> list[str]:
        command_list = ["promptfoo", "eval", "-c", str(config_path)]
        if output_json:
            command_list.extend(["-o", str(output_json)])

        eval_args = self.spec.params.get("eval_args")
        if isinstance(eval_args, str):
            command_list.extend(shlex.split(eval_args))
            return command_list
        if isinstance(eval_args, list):
            command_list.extend([str(part) for part in eval_args])
            return command_list

        command_list.extend(["--no-progress-bar", "--max-concurrency", "1"])
        return command_list

    def _build_env_overrides(self, context: EngineContext) -> dict[str, str]:
        env: dict[str, str] = {}
        raw_env = self.spec.params.get("env")
        if isinstance(raw_env, dict):
            for key, value in raw_env.items():
                env[str(key)] = str(value)

        if bool(self.spec.params.get("disable_cache", False)):
            env.setdefault("PROMPTFOO_CACHE_ENABLED", "false")
            env.setdefault("PROMPTFOO_CACHE_TYPE", "memory")
            env.setdefault(
                "PROMPTFOO_CONFIG_DIR",
                str(context.artifact_store.run_dir(context.run_id) / "promptfoo_runtime"),
            )

        if bool(self.spec.params.get("disable_wal_mode", False)):
            env.setdefault("PROMPTFOO_DISABLE_WAL_MODE", "true")

        config_dir = self.spec.params.get("config_dir")
        if config_dir:
            env["PROMPTFOO_CONFIG_DIR"] = str(config_dir)

        node_bin_dir = self.spec.params.get("node_bin_dir")
        if node_bin_dir:
            current_path = os.getenv("PATH", "")
            env["PATH"] = f"{node_bin_dir}:{current_path}" if current_path else str(node_bin_dir)

        return env

    def _build_prompt_source_artifacts(
        self,
        *,
        context: EngineContext,
        prompt_source: Any,
    ) -> tuple[str, str]:
        template_path_raw = self.spec.params.get("config_template_path") or self.spec.params.get("config_path")
        if not template_path_raw:
            raise ValueError("promptfoo prompt_source mode requires params.config_template_path or params.config_path")

        template_path = Path(str(template_path_raw)).expanduser()
        if not template_path.is_absolute():
            template_path = template_path.resolve()
        if not template_path.exists():
            raise FileNotFoundError(f"promptfoo template config not found: {template_path}")

        prompts, source_meta = self._resolve_prompt_source(prompt_source)
        if not prompts:
            raise ValueError("promptfoo prompt_source resolved zero prompts")

        var_name = str(self.spec.params.get("dataset_var", "attack_prompt")).strip() or "attack_prompt"

        try:
            import yaml  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("PyYAML is required for prompt_source config generation") from exc

        payload = yaml.safe_load(template_path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"promptfoo template config must be an object: {template_path}")

        template_test: dict[str, Any] = {}
        template_tests = payload.get("tests")
        if isinstance(template_tests, list):
            for item in template_tests:
                if isinstance(item, dict):
                    template_test = copy.deepcopy(item)
                    break

        base_vars: dict[str, Any] = {}
        if isinstance(template_test.get("vars"), dict):
            base_vars = {str(k): v for k, v in template_test["vars"].items() if str(k) != var_name}

        generated_tests: list[dict[str, Any]] = []
        for prompt in prompts:
            test_item = copy.deepcopy(template_test) if template_test else {}
            vars_payload = dict(base_vars)
            vars_payload[var_name] = prompt
            test_item["vars"] = vars_payload
            generated_tests.append(test_item)

        payload["tests"] = generated_tests
        prompts_block = payload.get("prompts")
        if not isinstance(prompts_block, list) or not prompts_block:
            payload["prompts"] = [f"{{{{{var_name}}}}}"]

        config_text = yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)
        generated_config_path = self._write_text_artifact(
            context,
            f"raw/promptfoo/{context.target.target_id}_generated_config.yaml",
            config_text,
        )
        meta_path = self._write_json_artifact(
            context,
            f"raw/promptfoo/{context.target.target_id}_dataset_meta.json",
            {
                "source": source_meta,
                "prompt_count": len(prompts),
                "dataset_var": var_name,
                "template_path": str(template_path),
            },
        )
        return generated_config_path, meta_path

    def _resolve_prompt_source(self, prompt_source: Any) -> tuple[list[str], dict[str, Any]]:
        mode = "file"
        source_path: Path | None = None
        preset_name: str | None = None
        profile_name: str | None = None
        profile_presets: list[str] | None = None
        field_name = str(self.spec.params.get("dataset_field", "attack_prompt"))
        limit = self.spec.params.get("dataset_limit")
        dedupe = bool(self.spec.params.get("dataset_dedupe", True))
        per_preset_limit = self.spec.params.get("dataset_profile_per_preset_limit")

        if isinstance(prompt_source, str):
            value = prompt_source.strip()
            if value.lower().startswith("preset:"):
                mode = "preset"
                preset_name = value.split(":", 1)[1].strip().lower()
            elif value.lower().startswith("profile:"):
                mode = "profile"
                profile_name = value.split(":", 1)[1].strip().lower()
            elif value.lower() in PROMPTFOO_PRESET_PROFILES:
                mode = "profile"
                profile_name = value.lower()
            elif value.lower() in PROMPTFOO_PRESETS:
                mode = "preset"
                preset_name = value.lower()
            else:
                source_path = Path(value).expanduser()
        elif isinstance(prompt_source, dict):
            mode = str(prompt_source.get("mode", "")).strip().lower()
            if not mode:
                if prompt_source.get("profile") or prompt_source.get("presets"):
                    mode = "profile"
                else:
                    mode = "preset" if prompt_source.get("preset") else "file"
            field_name = str(prompt_source.get("field", field_name))
            limit = prompt_source.get("limit", limit)
            dedupe = bool(prompt_source.get("dedupe", dedupe))
            per_preset_limit = prompt_source.get("per_preset_limit", per_preset_limit)
            if mode == "preset":
                preset_name = str(prompt_source.get("preset", "")).strip().lower()
            elif mode == "profile":
                profile_name = str(prompt_source.get("profile", "")).strip().lower() or None
                raw_presets = prompt_source.get("presets")
                if isinstance(raw_presets, list):
                    profile_presets = [
                        str(item).strip().lower()
                        for item in raw_presets
                        if str(item).strip()
                    ]
            else:
                path_value = prompt_source.get("path")
                if path_value:
                    source_path = Path(str(path_value)).expanduser()
        else:
            raise ValueError("prompt_source must be a string path/preset or an object")

        prompts: list[str]
        metadata: dict[str, Any]
        limit_per_preset_value = self._to_positive_int(per_preset_limit)
        scenarios = list(self.spec.enabled_scenarios)
        if mode == "preset":
            if not preset_name:
                raise ValueError("prompt_source preset mode requires a preset name")
            source_path = PROMPTFOO_PRESETS.get(preset_name)
            if not source_path:
                available = ", ".join(sorted(PROMPTFOO_PRESETS))
                raise ValueError(f"unknown prompt_source preset '{preset_name}'. Available: {available}")
            if not source_path.is_absolute():
                source_path = source_path.resolve()
            if not source_path.exists():
                raise FileNotFoundError(f"prompt_source file not found: {source_path}")
            prompts = self._load_prompts_from_file(source_path, field_name=field_name, scenarios=scenarios)
            metadata = {
                "mode": mode,
                "preset": preset_name,
                "path": str(source_path),
                "field": field_name,
                "dedupe": dedupe,
                "enabled_scenarios": scenarios,
            }
        elif mode == "profile":
            presets, resolved_profile = self._resolve_profile_presets(profile_name, profile_presets)
            presets = filter_names_by_scenarios(presets, scenarios)
            prompts = []
            resolved_paths: list[str] = []
            preset_counts: dict[str, int] = {}
            for preset in presets:
                preset_path = PROMPTFOO_PRESETS.get(preset)
                if not preset_path:
                    available = ", ".join(sorted(PROMPTFOO_PRESETS))
                    raise ValueError(f"profile '{resolved_profile}' contains unknown preset '{preset}'. Available: {available}")
                if not preset_path.is_absolute():
                    preset_path = preset_path.resolve()
                if not preset_path.exists():
                    raise FileNotFoundError(f"prompt_source preset file not found: {preset_path}")

                loaded = self._load_prompts_from_file(preset_path, field_name=field_name, scenarios=scenarios)
                if limit_per_preset_value is not None:
                    loaded = loaded[:limit_per_preset_value]
                preset_counts[preset] = len(loaded)
                prompts.extend(loaded)
                resolved_paths.append(str(preset_path))
            metadata = {
                "mode": mode,
                "profile": resolved_profile,
                "presets": presets,
                "paths": resolved_paths,
                "field": field_name,
                "dedupe": dedupe,
                "per_preset_limit": limit_per_preset_value,
                "preset_counts": preset_counts,
                "enabled_scenarios": scenarios,
            }
        else:
            if source_path is None:
                raise ValueError("prompt_source path could not be resolved")
            if not source_path.is_absolute():
                source_path = source_path.resolve()
            if not source_path.exists():
                raise FileNotFoundError(f"prompt_source file not found: {source_path}")
            prompts = self._load_prompts_from_file(source_path, field_name=field_name, scenarios=scenarios)
            metadata = {
                "mode": mode,
                "preset": preset_name,
                "path": str(source_path),
                "field": field_name,
                "dedupe": dedupe,
                "enabled_scenarios": scenarios,
            }

        if dedupe:
            deduped: list[str] = []
            seen: set[str] = set()
            for prompt in prompts:
                if prompt in seen:
                    continue
                seen.add(prompt)
                deduped.append(prompt)
            prompts = deduped

        limit_value = self._to_positive_int(limit)
        if limit_value is not None and limit_value > 0:
            prompts = prompts[:limit_value]

        metadata["limit"] = limit_value
        return prompts, metadata

    def _resolve_profile_presets(
        self,
        profile_name: str | None,
        explicit_presets: list[str] | None,
    ) -> tuple[list[str], str]:
        if explicit_presets:
            deduped = self._dedupe_list(explicit_presets)
            unknown = [preset for preset in deduped if preset not in PROMPTFOO_PRESETS]
            if unknown:
                available = ", ".join(sorted(PROMPTFOO_PRESETS))
                raise ValueError(
                    "prompt_source profile presets contain unknown values: "
                    f"{', '.join(unknown)}. Available: {available}"
                )
            return deduped, profile_name or "custom"

        if not profile_name:
            raise ValueError("prompt_source profile mode requires profile name or presets list")
        mapped = PROMPTFOO_PRESET_PROFILES.get(profile_name)
        if not mapped:
            available = ", ".join(sorted(PROMPTFOO_PRESET_PROFILES))
            raise ValueError(f"unknown prompt_source profile '{profile_name}'. Available: {available}")
        return list(mapped), profile_name

    @staticmethod
    def _dedupe_list(items: list[str]) -> list[str]:
        deduped: list[str] = []
        seen: set[str] = set()
        for item in items:
            if item in seen:
                continue
            seen.add(item)
            deduped.append(item)
        return deduped

    @staticmethod
    def _to_positive_int(value: Any) -> int | None:
        if value is None:
            return None
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return None
        return parsed if parsed > 0 else None

    def _load_prompts_from_file(
        self,
        path: Path,
        *,
        field_name: str,
        scenarios: list[str] | None = None,
    ) -> list[str]:
        suffix = path.suffix.lower()
        if suffix == ".jsonl":
            return self._load_prompts_jsonl(path, field_name=field_name, scenarios=scenarios)
        if suffix == ".json":
            return self._load_prompts_json(path, field_name=field_name, scenarios=scenarios)
        if suffix == ".csv":
            return self._load_prompts_csv(path, field_name=field_name, scenarios=scenarios)
        if suffix in {".txt", ".md"}:
            return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        raise ValueError(f"unsupported prompt_source format: {path.suffix}")

    @staticmethod
    def _load_prompts_jsonl(path: Path, *, field_name: str, scenarios: list[str] | None = None) -> list[str]:
        prompts: list[str] = []
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, str):
                value = payload.strip()
                if value:
                    prompts.append(value)
                continue
            if not isinstance(payload, dict):
                continue
            if not row_matches_scenarios(payload, scenarios):
                continue
            value = PromptfooEngineAdapter._extract_prompt_candidate(payload, field_name=field_name)
            if value:
                prompts.append(value)
        return prompts

    @staticmethod
    def _load_prompts_json(path: Path, *, field_name: str, scenarios: list[str] | None = None) -> list[str]:
        payload = json.loads(path.read_text(encoding="utf-8"))
        prompts: list[str] = []

        if isinstance(payload, dict):
            candidates = payload.get("prompts") or payload.get("attacks") or payload.get("inputs")
            if isinstance(candidates, list):
                payload = candidates

        if isinstance(payload, list):
            for item in payload:
                if isinstance(item, str):
                    value = item.strip()
                    if value:
                        prompts.append(value)
                    continue
                if isinstance(item, dict):
                    if not row_matches_scenarios(item, scenarios):
                        continue
                    value = PromptfooEngineAdapter._extract_prompt_candidate(item, field_name=field_name)
                    if value:
                        prompts.append(value)
        return prompts

    @staticmethod
    def _load_prompts_csv(path: Path, *, field_name: str, scenarios: list[str] | None = None) -> list[str]:
        prompts: list[str] = []
        with path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if not isinstance(row, dict):
                    continue
                if not row_matches_scenarios(row, scenarios):
                    continue
                value = PromptfooEngineAdapter._extract_prompt_candidate(row, field_name=field_name)
                if value:
                    prompts.append(value)
        return prompts

    @staticmethod
    def _extract_prompt_candidate(payload: dict[str, Any], *, field_name: str) -> str | None:
        preferred = payload.get(field_name)
        if isinstance(preferred, str) and preferred.strip():
            return preferred.strip()

        for key in PROMPT_FIELD_FALLBACKS:
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

        for value in payload.values():
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    def _parse_promptfoo_output(self, *, run_id: str, target_id: str, output_path: Path) -> list[UnifiedFinding]:
        try:
            payload = json.loads(output_path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            return [
                UnifiedFinding(
                    finding_id=f"{run_id}:{target_id}:promptfoo:parse_error",
                    run_id=run_id,
                    target_id=target_id,
                    engine="promptfoo",
                    category="execution",
                    sub_category="parse_error",
                    severity="low",
                    confidence=0.95,
                    attack_vector="tool_output",
                    attack_complexity="n/a",
                    success=False,
                    description=f"Unable to parse promptfoo output: {exc}",
                )
            ]

        entries = self._extract_entries(payload)
        if not entries:
            payload_keys = list(payload.keys()) if isinstance(payload, dict) else []
            return [
                UnifiedFinding(
                    finding_id=f"{run_id}:{target_id}:promptfoo:no_results",
                    run_id=run_id,
                    target_id=target_id,
                    engine="promptfoo",
                    category="coverage_gap",
                    sub_category="no_results",
                    severity="low",
                    confidence=0.9,
                    attack_vector="promptfoo_eval",
                    attack_complexity="n/a",
                    success=False,
                    description="Promptfoo output parsed but no evaluation rows were found",
                    metadata={"output_path": str(output_path), "payload_keys": payload_keys},
                )
            ]

        findings: list[UnifiedFinding] = []
        for idx, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue

            grading = entry.get("gradingResult")
            if not isinstance(grading, dict):
                grading = {}

            pass_candidate = self._coerce_bool(grading.get("pass"))
            if pass_candidate is None:
                pass_candidate = self._coerce_bool(entry.get("success"))
            if pass_candidate is None:
                pass_candidate = self._coerce_bool(entry.get("pass"))
            if pass_candidate is None:
                pass_candidate = self._coerce_bool(entry.get("passed"))
            status = str(entry.get("status", "")).strip().lower()
            if pass_candidate is None and status:
                pass_candidate = status in {"pass", "passed", "ok", "success"}
            if pass_candidate is None:
                failure_reason = entry.get("failureReason")
                pass_candidate = failure_reason in (None, 0, "0", "")
            passed = bool(pass_candidate)

            test_case = entry.get("testCase")
            if not isinstance(test_case, dict):
                test_case = {}
            assertions = test_case.get("assert")
            if not isinstance(assertions, list):
                assertions = []

            plugin = "promptfoo_eval"
            for assertion in assertions:
                if isinstance(assertion, dict):
                    plugin = str(assertion.get("type", "promptfoo_eval"))
                    break
            if plugin == "promptfoo_eval":
                plugin = str(entry.get("plugin", entry.get("grader", entry.get("category", plugin))))

            strategy = str(entry.get("strategy", entry.get("attack", entry.get("technique", "promptfoo_eval"))))
            if strategy == "promptfoo_eval":
                prompt = entry.get("prompt")
                if isinstance(prompt, dict):
                    strategy = str(prompt.get("raw", prompt.get("label", strategy)))
                vars_payload = entry.get("vars")
                if isinstance(vars_payload, dict) and vars_payload.get("attack_prompt"):
                    strategy = str(vars_payload.get("attack_prompt"))

            score_raw = entry.get("score", grading.get("score"))
            score = None
            if score_raw is not None:
                try:
                    score = float(score_raw)
                except (TypeError, ValueError):
                    score = None
            reason = grading.get("reason")
            findings.append(
                UnifiedFinding(
                    finding_id=f"{run_id}:{target_id}:promptfoo:test:{idx}",
                    run_id=run_id,
                    target_id=target_id,
                    engine="promptfoo",
                    category="policy_violation",
                    sub_category=plugin,
                    severity="medium" if not passed else "info",
                    confidence=0.8 if score is None else max(0.0, min(1.0, score)),
                    attack_vector=strategy,
                    attack_complexity="unknown",
                    success=not passed,
                    description=str(reason or entry.get("description") or "Promptfoo evaluation result"),
                    metadata={"raw": entry, "score": score},
                )
            )
        return findings

    def _resolve_promptfoo_launcher(self, command_list: list[str]) -> list[str]:
        if not command_list:
            return command_list

        launcher = command_list[0]
        if self._launcher_exists(launcher):
            return command_list

        lower = launcher.lower()
        if lower not in {"promptfoo", "promptfoo.cmd", "promptfoo.exe"}:
            return command_list

        for candidate in self._promptfoo_bin_candidates():
            if candidate.is_file():
                return [str(candidate), *command_list[1:]]
        return command_list

    def _promptfoo_bin_candidates(self) -> list[Path]:
        candidates: list[Path] = []

        env_candidate = os.getenv("URT_PROMPTFOO_BIN")
        if env_candidate:
            candidates.append(Path(env_candidate).expanduser())

        spec_candidate = self.spec.params.get("binary_path")
        if spec_candidate:
            candidates.append(Path(str(spec_candidate)).expanduser())

        candidates.append(Path.home() / ".urt-tools" / "promptfoo" / "node_modules" / ".bin" / "promptfoo")
        candidates.append(Path.cwd() / ".urt-tools" / "promptfoo" / "node_modules" / ".bin" / "promptfoo")

        deduped: list[Path] = []
        seen: set[str] = set()
        for path in candidates:
            key = str(path)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(path)
        return deduped

    def _launcher_exists(self, launcher: str) -> bool:
        path = Path(launcher).expanduser()
        if path.is_file():
            return True
        return self._command_exists(launcher)

    @staticmethod
    def _extract_entries(payload: Any) -> list[Any]:
        if isinstance(payload, list):
            return payload
        if not isinstance(payload, dict):
            return []

        for key in ("results", "evaluations", "tests"):
            value = payload.get(key)
            if isinstance(value, list):
                return value

            if isinstance(value, dict):
                for sub_key in ("results", "evaluations", "rows", "items", "tests"):
                    sub_value = value.get(sub_key)
                    if isinstance(sub_value, list):
                        return sub_value

        return []

    @staticmethod
    def _coerce_bool(value: Any) -> bool | None:
        if isinstance(value, bool):
            return value
        if value is None:
            return None
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"true", "yes", "1", "pass", "passed", "ok", "success"}:
                return True
            if normalized in {"false", "no", "0", "fail", "failed", "error"}:
                return False
            return None
        if isinstance(value, (int, float)):
            return bool(value)
        return None
