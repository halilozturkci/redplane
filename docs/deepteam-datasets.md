# Unified Dataset Strategy (Local/Manual v1)

This file started as DeepTeam seed guidance. It now captures the broader dataset strategy for the unified red-team platform, while keeping DeepTeam conversion steps.

Goal for v1:
- run locally
- run manually (no scheduler requirement)
- produce auditable outputs for consultants and customers
- keep licensing/provenance clear

## Recommended Dataset Portfolio

Use these first, in this priority order.

1) JailbreakBench (JBB-Behaviors)
- Source: https://github.com/JailbreakBench/jailbreakbench
- Why now: balanced harmful and benign behavior sets, good for jailbreak ASR + false positive calibration.
- Notes: repository README states two datasets (100 harmful + 100 benign behaviors).

2) HarmBench
- Source: https://github.com/centerforaisafety/HarmBench
- Why now: broad harmful behavior coverage, widely referenced for safety red-teaming.
- Notes: Promptfoo HarmBench plugin docs describe coverage across 400 harmful behaviors:
  - https://www.promptfoo.dev/docs/red-team/plugins/harmbench/

3) XSTest
- Source (paper): https://arxiv.org/abs/2308.01263
- Why now: catches exaggerated refusals and overblocking.
- Notes: paper describes 250 safe + 200 unsafe contrast prompts.

4) Lakera Gandalf Ignore Instructions
- Source: https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions
- Why now: direct prompt-injection / instruction-override corpus.
- Notes: small and practical for fast local smoke + regression checks.

5) AILuminate v1.0 DEMO Prompt Set
- Source: https://github.com/mlcommons/ailuminate
- Why now: broad hazard taxonomy and human-authored prompts.
- Notes: repo README describes 1,200 demo prompts (10% sample) and 12 hazard categories.

## Optional Datasets (Phase 1.5)

6) NVIDIA Aegis Safety Dataset
- Source: https://huggingface.co/datasets/nvidia/Aegis-AI-Content-Safety-Dataset-2.0
- Why: moderation-style classification and policy coverage expansion.

7) Anthropic HH-RLHF
- Source: https://huggingface.co/datasets/Anthropic/hh-rlhf
- Why: large conversational set for long-tail robustness checks.
- Caution: curate a subset; full corpus is large/noisy for quick consultant runs.

## Engine Mapping (What to Use Where)

- Promptfoo
  - Prefer built-in dataset plugins when available (`harmbench`, `xstest`, `aegis`, `beavertails`, `cyberseceval`, `donotanswer`):
    - https://www.promptfoo.dev/docs/red-team/plugins/
  - Add custom YAML tests for your Copilot/Foundry business rules and expected assertions.

- DeepTeam
  - Keep dynamic generation enabled first.
  - If simulator returns zero test cases, switch to seeded mode using `DEEPTEAM_SEED_DATASET`.
  - Seed conversion command:
    ```bash
    python examples/deepteam_seeded/prepare_seed_dataset.py \
      --input /path/to/source.(json|jsonl|csv) \
      --output /path/to/deepteam_seed_attacks.json \
      --max-prompts 200
    ```

- PyRIT
  - Use curated prompt corpora (JBB/HarmBench/XSTest subsets) as external prompt sources.
  - Keep attack strategy permutations in PyRIT; keep datasets focused and deduplicated.

- Garak
  - Primary value is probe library itself:
    - https://github.com/NVIDIA/garak
  - Use external datasets mainly for targeted replay/regression sets.

- PowerPwn / Power CAT
  - These are mostly recon/governance/runtime test workflows rather than static prompt-dataset engines:
    - https://github.com/mbrg/power-pwn
    - https://github.com/microsoft/Power-CAT-Copilot-Studio-Kit
  - Feed them scenario test cases and tenant-specific abuse cases, not large benchmark corpora.

## What Not To Prioritize In v1

- Private/paid prompt sets with unclear redistribution terms.
- Very large multimodal datasets unless the target agent is multimodal today.
- Raw internet dumps without license + provenance metadata.

## Minimum Audit Metadata Per Dataset

Store these in your run artifact bundle:
- dataset_id
- source_url
- source_version_or_commit
- license
- import_timestamp_utc
- row_count_loaded
- hash_sha256 (raw file)
- transformation_script_version

This keeps customer audits reproducible even in local SQLite mode.

## Suggested Local Folder Convention

```text
datasets/
  raw/
    jailbreakbench/
    harmbench/
    xstest/
    lakera_gandalf/
    ailuminate_demo/
  curated/
    core_v1/
      prompts.jsonl
      metadata.json
  manifests/
    core_v1.yaml
```

## Practical v1 Starter Pack

If you want one immediate bundle for consultants:
- JBB harmful + benign
- HarmBench subset
- XSTest full
- Gandalf ignore instructions full
- AILuminate demo subset (language/locale filtered)

Target final size:
- 800 to 2,000 prompts total for fast local runs with full audit exports.
