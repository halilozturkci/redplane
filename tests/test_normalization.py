from urt.normalization import build_scorecard, normalize_findings
from urt.types import UnifiedFinding


def test_normalization_applies_policy_mapping():
    finding = UnifiedFinding(
        finding_id="f1",
        run_id="r1",
        target_id="t1",
        engine="pyrit",
        category="prompt_injection",
        sub_category=None,
        severity="high",
        confidence=0.9,
        attack_vector="jailbreak",
        attack_complexity="difficult",
        success=True,
        description="Prompt injection succeeded",
    )
    normalized = normalize_findings([finding], policy_profiles=["owasp_llm", "mitre_atlas"])
    assert normalized[0].mappings["owasp_llm"]
    assert normalized[0].mappings["mitre_atlas"]


def test_scorecard_computes_asr():
    findings = [
        UnifiedFinding(
            finding_id="f1",
            run_id="r1",
            target_id="t1",
            engine="pyrit",
            category="prompt_injection",
            sub_category=None,
            severity="high",
            confidence=0.9,
            attack_vector="jailbreak",
            attack_complexity="difficult",
            success=True,
            description="x",
        ),
        UnifiedFinding(
            finding_id="f2",
            run_id="r1",
            target_id="t1",
            engine="pyrit",
            category="prompt_injection",
            sub_category=None,
            severity="info",
            confidence=0.9,
            attack_vector="jailbreak",
            attack_complexity="difficult",
            success=False,
            description="y",
        ),
    ]
    score = build_scorecard("r1", findings)
    assert score.total_attacks == 2
    assert score.success_count == 1
    assert score.asr_overall == 0.5
