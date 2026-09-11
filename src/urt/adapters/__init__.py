"""Adapter factory functions."""

from __future__ import annotations

from .engine_base import EngineAdapter
from .evaluator_base import EvaluatorAdapter
from .target_base import TargetAdapter
from .targets import CopilotTargetAdapter, FoundryTargetAdapter, HttpTargetAdapter
from .engines import (
    DeepTeamEngineAdapter,
    GarakEngineAdapter,
    GiskardEngineAdapter,
    InspectEngineAdapter,
    PowerCatEngineAdapter,
    PowerPwnEngineAdapter,
    PromptfooEngineAdapter,
    PyRITEngineAdapter,
)
from .evaluators import (
    AzureAIEvalEvaluator,
    CustomScriptEvaluator,
    DeepEvalEvaluator,
    GiskardEvalEvaluator,
    InspectEvalEvaluator,
    PromptfooEvalEvaluator,
)
from ..types import EngineSpec, EvaluatorSpec, TargetSpec


TARGET_ADAPTERS: dict[str, type[TargetAdapter]] = {
    "http": HttpTargetAdapter,
    "foundry": FoundryTargetAdapter,
    "copilot": CopilotTargetAdapter,
}

ENGINE_ADAPTERS: dict[str, type[EngineAdapter]] = {
    "pyrit": PyRITEngineAdapter,
    "promptfoo": PromptfooEngineAdapter,
    "garak": GarakEngineAdapter,
    "powerpwn": PowerPwnEngineAdapter,
    "powercat": PowerCatEngineAdapter,
    "deepteam": DeepTeamEngineAdapter,
    "inspect": InspectEngineAdapter,
    "giskard": GiskardEngineAdapter,
}

EVALUATOR_ADAPTERS: dict[str, type[EvaluatorAdapter]] = {
    "deepeval": DeepEvalEvaluator,
    "promptfoo_eval": PromptfooEvalEvaluator,
    "giskard_eval": GiskardEvalEvaluator,
    "inspect_eval": InspectEvalEvaluator,
    "azure_ai_eval": AzureAIEvalEvaluator,
    "custom_script": CustomScriptEvaluator,
}


def create_target_adapter(spec: TargetSpec) -> TargetAdapter:
    adapter_cls = TARGET_ADAPTERS.get(spec.target_type)
    if not adapter_cls:
        raise ValueError(f"Unsupported target adapter: {spec.target_type}")
    return adapter_cls(spec)


def create_engine_adapter(spec: EngineSpec) -> EngineAdapter:
    adapter_cls = ENGINE_ADAPTERS.get(spec.name)
    if not adapter_cls:
        raise ValueError(f"Unsupported engine adapter: {spec.name}")
    return adapter_cls(spec)


def create_evaluator_adapter(spec: EvaluatorSpec) -> EvaluatorAdapter:
    adapter_cls = EVALUATOR_ADAPTERS.get(spec.name)
    if not adapter_cls:
        raise ValueError(f"Unsupported evaluator adapter: {spec.name}")
    return adapter_cls(spec)
