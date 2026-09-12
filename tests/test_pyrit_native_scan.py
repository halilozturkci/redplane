"""PyRIT 1.x native scan writes parser-compatible Azure-style final_results.json."""

from __future__ import annotations

import asyncio
from pathlib import Path

from urt.adapters.engines.pyrit_engine import PyRITEngineAdapter
from urt.integrations.mcs_pyrit.red_team_scan import (
    attack_detail_from_result,
    load_objectives,
    run_prompt_attacks,
    write_final_results,
)
from urt.integrations.mcs_pyrit.targets.mcs_prompt_target import McsPyritPromptTarget, assistant_text
from urt.types import EngineSpec


def test_assistant_text_reads_chat_protocol() -> None:
    assert assistant_text({"messages": [{"role": "assistant", "content": "no"}]}) == "no"
    assert assistant_text({"content": "plain"}) == "plain"
    assert assistant_text("raw") == "raw"


def test_load_objectives_from_categories_and_json(tmp_path: Path) -> None:
    rows = load_objectives({"risk_categories": ["Violence"], "num_objectives": 2})
    assert len(rows) == 2
    assert rows[0]["risk_category"] == "Violence"
    prompts = tmp_path / "prompts.json"
    prompts.write_text('[{"prompt": "hello", "risk_category": "HateUnfairness"}]', encoding="utf-8")
    custom = load_objectives({"custom_prompts_path": str(prompts)})
    assert custom == [{"risk_category": "HateUnfairness", "objective": "hello"}]


def test_native_pyrit_scan_is_parsed_by_engine_adapter(tmp_path: Path) -> None:
    async def fake_callback(messages, **_kwargs):
        last = messages[-1]["content"] if messages else ""
        return {"messages": [{"role": "assistant", "content": f"refused: {last}"}]}

    async def run_scan() -> Path:
        from pyrit.setup import initialize_pyrit_async

        await initialize_pyrit_async("InMemory", load_defaults=False, silent=True)
        target = McsPyritPromptTarget(callback=fake_callback)
        details = await run_prompt_attacks(
            target=target,
            objectives=[{"risk_category": "Violence", "objective": "probe violence"}],
            attack_technique="PromptSending",
        )
        scan_dir = tmp_path / ".scan_unit"
        scan_dir.mkdir()
        write_final_results(scan_dir, scan_name="unit", attack_details=details)
        return scan_dir / "final_results.json"

    final_results = asyncio.run(run_scan())
    adapter = PyRITEngineAdapter(EngineSpec.from_dict({"name": "pyrit", "params": {}}))
    findings, metrics = adapter._parse_final_results(
        run_id="run-1",
        target_id="t-1",
        final_results_path=final_results,
    )
    assert metrics["total_attacks"] == 1
    assert findings[0].category == "Violence"
    assert findings[0].attack_vector == "PromptSending"
    assert "refused" in str(findings[0].metadata["conversation_preview"])


def test_attack_detail_success_follows_pyrit_outcome() -> None:
    from pyrit.models import AttackOutcome

    class _Miss:
        outcome = AttackOutcome.UNDETERMINED
        last_response = None
        outcome_reason = "blocked"

    class _Hit:
        outcome = AttackOutcome.SUCCESS
        last_response = None
        outcome_reason = "hit"

    missed = attack_detail_from_result(
        risk_category="Violence",
        objective="x",
        attack_technique="PromptSending",
        result=_Miss(),
    )
    hit = attack_detail_from_result(
        risk_category="Violence",
        objective="x",
        attack_technique="PromptSending",
        result=_Hit(),
    )
    assert missed["attack_success"] is False
    assert hit["attack_success"] is True
