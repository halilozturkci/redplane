# Promptfoo Preset Catalog

This catalog documents built-in URT Promptfoo presets, their threat focus, and source provenance.

## Design notes

- Presets are **benchmark-inspired and paraphrased**, not verbatim benchmark copies.
- Each JSONL row carries metadata:
  - `dataset`
  - `benchmark_source`
  - `category`
  - `subcategory`
  - `sample_id`
  - `expected_safe_behavior`
- Recommended baseline execution options for reproducibility:
  - `disable_cache: true`
  - `disable_wal_mode: true`
  - `eval_args: "--no-progress-bar --max-concurrency 1"`

## Presets

| Preset | Rows | Primary focus |
|---|---:|---|
| `copilot_security_starter` | 42 | Agent-specific abuse: prompt leakage, tool abuse, RAG/indirect injection, authz/audit bypass |
| `jailbreakbench_starter` (`jailbreakbench`) | 40 | Jailbreak techniques and refusal bypass patterns |
| `harmbench_starter` (`harmbench`) | 45 | Broad harmful capability requests |
| `xstest_starter` (`xstest`) | 40 | Benign + ambiguous + unsafe mix for over/under-refusal checks |
| `donotanswer_starter` (`donotanswer`, `do_not_answer`) | 35 | Refusal-critical disallowed classes |
| `beavertails_starter` (`beavertails`) | 35 | Fine-grained safety risk taxonomy |
| `aegis_starter` (`aegis`) | 30 | Toxicity + jailbreak + unsafe behavior stress tests |
| `bipia_indirect_injection_starter` (`bipia`, `bipia_indirect_injection`) | 30 | Indirect prompt injection payloads embedded in context |
| `cyberseceval_starter` (`cyberseceval`) | 35 | Cyber dual-use coverage (defensive + offensive misuse) |
| `simplesafetytests_starter` (`simplesafetytests`) | 30 | Compact refusal baseline set |
| `agentic_tool_abuse_starter` (`agentic_tool_abuse`) | 30 | Agentic tool misuse, approval bypass, audit evasion |

## Category framework (recommended for future expansion)

Use this category model when adding new prompts:

1. **Prompt-layer attacks**
   - direct jailbreak
   - role/authority spoofing
   - encoding/obfuscation
   - multi-turn state poisoning
2. **Context-layer attacks**
   - indirect injection in documents/emails/html/json/csv
   - RAG instruction hijack
   - citation poisoning
3. **Agent/tool-layer attacks**
   - unauthorized tool invocation
   - approval bypass
   - privilege escalation
   - audit/log evasion
4. **Data and privacy attacks**
   - system prompt extraction
   - secret/credential exfiltration
   - cross-session or cross-tenant leakage
5. **Safety policy stress tests**
   - harmful content refusal
   - over-refusal on benign prompts
   - boundary/ambiguity handling
6. **Domain-specific stress tests**
   - cybersecurity misuse
   - fraud/social engineering
   - critical infrastructure abuse

## External benchmark and dataset sources

Primary sources used to shape category coverage:

- JailbreakBench (repo + dataset)
  - https://github.com/JailbreakBench/jailbreakbench
  - https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors
- HarmBench
  - https://github.com/centerforaisafety/HarmBench
  - https://arxiv.org/abs/2402.04249
- XSTest
  - https://arxiv.org/abs/2308.01263
- Do-Not-Answer
  - https://github.com/Libr-AI/do-not-answer
  - https://arxiv.org/abs/2308.13387
- BeaverTails
  - https://github.com/PKU-Alignment/beavertails
  - https://arxiv.org/abs/2307.04657
- Aegis 2.0
  - https://huggingface.co/datasets/nvidia/Aegis-AI-Content-Safety-Dataset-2.0
  - https://arxiv.org/abs/2406.08487
- BIPIA (indirect prompt injection benchmark)
  - https://github.com/microsoft/BIPIA
  - https://arxiv.org/abs/2504.11010
- CyberSecEval and Purple Llama
  - https://github.com/meta-llama/PurpleLlama
- SimpleSafetyTests
  - https://huggingface.co/datasets/Bertievidgen/SimpleSafetyTests

Promptfoo plugin references (engine-native support and ideas):

- HarmBench plugin docs: https://www.promptfoo.dev/docs/red-team/plugins/harmbench/
- CyberSecEval plugin docs: https://www.promptfoo.dev/docs/red-team/plugins/cyberseceval/

## Suggested preset bundles

- **Fast smoke (<= 30 prompts):** `copilot_security_starter` + `xstest_starter` (`limit: 15` each)
- **General safety baseline:** `copilot_security_starter` + `jailbreakbench_starter` + `harmbench_starter`
- **Agentic security focus:** `copilot_security_starter` + `agentic_tool_abuse_starter` + `bipia_indirect_injection_starter`
- **Cyber-focused baseline:** `cyberseceval_starter` + `xstest_starter`

Built-in `prompt_source` profile shortcuts:

- `profile:fast`
- `profile:balanced`
- `profile:agentic`
- `profile:cyber`

## Maintenance guidance

- Add prompts in small batches and keep `category`/`subcategory` stable.
- Preserve deterministic `sample_id` formatting (`<dataset>-NNNN`).
- Track major benchmark updates every quarter and refresh paraphrased prompt variants.
