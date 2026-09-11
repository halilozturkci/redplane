"""Policy and framework mapping utilities."""

from __future__ import annotations

from typing import Iterable


OWASP_LLM_MAP: dict[str, list[str]] = {
    "prompt_injection": ["LLM01:2025 Prompt Injection"],
    "data_exfiltration": ["LLM02:2025 Sensitive Information Disclosure"],
    "supply_chain": ["LLM05:2025 Supply Chain Vulnerabilities"],
    "misconfiguration": ["LLM07:2025 Insecure Plugin Design"],
    "policy_violation": ["LLM06:2025 Excessive Agency"],
    "robustness": ["LLM09:2025 Overreliance"],
    "execution": ["LLM10:2025 Model Theft / Abuse Signals"],
    "violence": ["LLM06:2025 Excessive Agency"],
    "hate_unfairness": ["LLM08:2025 Excessive Prompt Surface"],
    "sexual": ["LLM08:2025 Excessive Prompt Surface"],
    "self_harm": ["LLM06:2025 Excessive Agency"],
}

OWASP_AGENTIC_MAP: dict[str, list[str]] = {
    "prompt_injection": ["A01:2026 Agent Goal/Instruction Manipulation"],
    "data_exfiltration": ["A02:2026 Agent Memory/Data Leakage"],
    "tool_abuse": ["A03:2026 Insecure Tool Use"],
    "misconfiguration": ["A06:2026 Insecure Agent Configuration"],
    "execution": ["A09:2026 Insufficient Monitoring and Controls"],
}

MITRE_ATLAS_MAP: dict[str, list[str]] = {
    "prompt_injection": ["AML.T0051 Prompt Injection"],
    "data_exfiltration": ["AML.T0048 Exfiltration via Model Responses"],
    "tool_abuse": ["AML.T0015 Exploit Public-Facing Application"],
    "misconfiguration": ["AML.T0000 System Weakness / Misconfiguration"],
    "execution": ["AML.T0021 Resource Hijacking"],
}


def map_category(category: str) -> dict[str, list[str]]:
    key = category.strip().lower().replace("-", "_")
    return {
        "owasp_llm": OWASP_LLM_MAP.get(key, []),
        "owasp_agentic": OWASP_AGENTIC_MAP.get(key, []),
        "mitre_atlas": MITRE_ATLAS_MAP.get(key, []),
    }


def merge_mappings(*mapping_dicts: dict[str, list[str]]) -> dict[str, list[str]]:
    merged: dict[str, list[str]] = {}
    for mapping in mapping_dicts:
        for key, values in mapping.items():
            current = merged.setdefault(key, [])
            for value in values:
                if value not in current:
                    current.append(value)
    return merged


def enabled_mapping_keys(policy_profiles: Iterable[str]) -> set[str]:
    return {str(item).strip().lower() for item in policy_profiles}
