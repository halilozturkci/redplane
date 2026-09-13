# Redplane

**Attack and evaluation control plane**

*One spec. Attack and evaluate. One scorecard, one gate.*

Redplane is a local-first **attack and evaluation control plane** for AI systems. It is *not* another attack tool. It commands best-in-class attack engines **and** post-attack evaluators — PyRIT, Garak, Promptfoo, DeepTeam, Giskard, Inspect, PowerPwn, Power CAT, DeepEval, Azure AI Evaluation — against your targets (Microsoft Copilot Studio agents, Azure AI Foundry, and any OpenAI-compatible or generic HTTP endpoint), then unifies everything those tools emit into one normalized, framework-mapped, sign-off-ready result.

**One `RunSpec` in → ASR + eval scores, framework map, audit bundle, and CI gate out.**

This repository is published as **open source** under the MIT License.

> **CLI and package.** Install the `redplane` distribution; the command and Python import remain **`urt`**. `URT_*` environment variables and `X-URT-Target` are unchanged. The OpenAI-compatible **network gateway** (`urt serve-gateway`) is one face of the product, not the product itself.

---

## Table of Contents

- [The Mental Model: A Control Plane, Not an Attacker](#the-mental-model-a-control-plane-not-an-attacker)
- [Why It Exists](#why-it-exists)
- [Core Capabilities](#core-capabilities)
- [Capabilities at a Glance](#capabilities-at-a-glance)
- [How It Works (End-to-End Flow)](#how-it-works-end-to-end-flow)
- [Supported Targets, Engines & Evaluators](#supported-targets-engines--evaluators)
- [Requirements](#requirements)
- [Quickstart (60 seconds)](#quickstart-60-seconds)
- [Install (UV-First)](#install-uv-first)
- [CLI Commands](#cli-commands)
- [RunSpec Reference](#runspec-reference)
- [Target Configuration Cookbook](#target-configuration-cookbook)
- [Engine Usage Cookbook](#engine-usage-cookbook)
- [Evaluator Engine Integration](#evaluator-engine-integration)
- [Output, Reports, and Audit Format](#output-reports-and-audit-format)
- [API](#api)
- [Network Gateway (Multi-Backend OpenAI Bridge)](#network-gateway-multi-backend-openai-bridge)
- [Runtime Contracts](#runtime-contracts)
- [Troubleshooting](#troubleshooting)

---

## The Mental Model: A Control Plane, Not an Attacker

AI red-team tooling is powerful but fragmented. Each tool speaks its own dialect, expects its own target wiring, and emits its own result format. Running five tools against three agents means fifteen bespoke integrations, five incompatible report formats, and no shared notion of "did we get more or less secure this week?"

Redplane collapses that fragmentation into a single control plane. You describe *what to test, with which tools, under which policies* once — and it does the rest. It has **two faces**:

- **Orchestration plane** — the run engine. It takes a declarative `RunSpec`, health-checks every target, drives each attack engine and post-attack evaluator through a uniform adapter contract, then normalizes, scores, maps, persists, and reports the combined result. The attack *and* evaluation intelligence lives in the wrapped tools; the *orchestration, correlation, and governance* live here.
- **Network gateway** — an OpenAI-compatible proxy (`urt serve-gateway`) that fronts heterogeneous AI backends (Copilot Studio, Azure OpenAI, Foundry model & agent services, generic HTTP) behind one `/v1/chat/completions` endpoint. Any tool that "only speaks OpenAI" can now reach *any* of your AI systems, with per-request auditing and secret redaction on the wire.

Both faces express the same principle: **Redplane commands the tools that attack and evaluate; it is the control plane, not the payload.**

## Why It Exists

- **AI-specific, not generic.** This is red teaming for AI systems — prompt injection, jailbreaks, tool abuse, indirect/RAG injection, data exfiltration, over/under-refusal, agentic goal manipulation — not classic network/pentest red teaming.
- **Tool-agnostic by design.** Adopt the strongest engine for each job without rebuilding your harness. New engines, evaluators, and targets plug in through the same adapter contract.
- **Repeatable & governable.** Every run is deterministic-by-spec, version-pinned, and captured as an immutable audit bundle — the difference between an ad-hoc probe and an assessment you can hand to security, compliance, or an auditor.
- **Local-first & manual-execution.** No mandatory SaaS, no data leaving your machine by default. You control credentials, endpoints, and scope through environment variables in the spec.

## Core Capabilities

**Orchestration**
- Single declarative `RunSpec` drives many targets × many engines × many evaluators in one run.
- Uniform three-layer adapter pattern (targets, engines, evaluators) with pluggable factories.
- `fail_open` semantics per engine **and** evaluator: soak up tool failures or make them fatal for CI gates.
- Enforced duration budget between engines/evaluators; USD cap only when a tool reports `cost_usd` / `estimated_cost_usd` (otherwise `unmetered`).
- HTTP `connect_seconds` / `request_seconds`, evidence caps (`minimal` / `standard` / `full`), and `seed` injected as `URT_SEED` + `PYTHONHASHSEED`.
- Run profiles (`pr_gate`, `nightly`, `weekly_deep`) supply budget/timeout defaults when those keys are omitted; they are not a separate planner/pipeline.

**Coverage**
- 3 target types, 8 attack engines, 6 evaluators out of the box (see tables below).
- Curated Promptfoo dataset presets and composition profiles (jailbreak, harmbench, xstest, BIPIA indirect injection, agentic tool abuse, CyberSecEval, and more).
- Seeded, reliability-first DeepTeam mode for reproducible agent probing.

**Normalization & scoring**
- Every tool result becomes a `UnifiedFinding` with a shared severity/category schema.
- Attack Success Rate (ASR) overall and by category, severity counts, and per-engine breakdowns.
- Post-attack evaluator loop producing per-metric `eval_scores` and an aggregate `eval_pass_rate`.

**Governance & compliance**
- Automatic mapping to **OWASP LLM Top 10**, **OWASP Agentic**, and **MITRE ATLAS**.
- Severity gate (`urt gate --threshold …`) for pass/fail CI enforcement; active waivers suppress matching findings unless `--ignore-waivers`.
- Waiver CLI + REST (`urt waivers create|list`, `POST/GET /v1/waivers`) keyed by `target_id` + `control_id` + `expires_at`.

**Auditability**
- Full per-run audit bundle: resolved spec, run manifest, engine invocations, raw tool logs, normalized findings, scorecard, and Markdown/HTML/CSV reports.
- SQLite metadata store for cross-run history and queries.

**Access & integration**
- CLI for the full lifecycle (`init → validate → probe → run → waivers → report → gate → runs/findings/artifacts`).
- REST control-plane API (`urt serve-api`) for programmatic runs and querying.
- OpenAI-compatible network gateway (`urt serve-gateway`) with header/model/path routing, session handling, PII & header redaction, and audit logging.

## Capabilities at a Glance

| Capability | What Redplane gives you |
|---|---|
| Multi-target | `copilot` (HTTP + SDK), `foundry`, generic `http` — one spec, many AI systems |
| Multi-engine | 8 attack engines wrapped behind one contract, run individually or together |
| Multi-evaluator | 6 evaluators score responses for quality, safety, and compliance after attacks |
| Unified findings | One normalized schema across every tool, deduplicated per run |
| Framework mapping | OWASP LLM + OWASP Agentic + MITRE ATLAS on every mapped finding |
| Scoring | ASR overall/by-category + evaluator `eval_scores` / `eval_pass_rate` |
| CI gating | `urt gate` fails builds above a severity threshold; active waivers are honored |
| Audit bundle | Immutable, reproducible artifact set per run |
| Interfaces | CLI + REST API + OpenAI-compatible network gateway |
| Extensibility | Add targets/engines/evaluators via the adapter registry |

## How It Works (End-to-End Flow)

```text
                         ┌──────────────────────────────┐
        RunSpec (YAML) ──▶│   Redplane (orchestration)    │
                         └──────────────┬───────────────┘
                                        │  for each target:
                                        ▼
                    healthcheck ▶ start session
                                        │
             ┌──────────────────────────┼──────────────────────────┐
             ▼                                                     ▼
     Attack Engines                                        Post-attack Evaluators
 (PyRIT, Garak, Promptfoo,                              (DeepEval, Promptfoo, Giskard,
  DeepTeam, Giskard, Inspect,                            Inspect, Azure AI, custom)
  PowerPwn, Power CAT)                                          │
             │  EngineRunResult(findings)                       │ EvalRunResult(scores)
             └──────────────────────────┬──────────────────────┘
                                        ▼
              normalize → map (OWASP LLM / Agentic / MITRE ATLAS)
                                        ▼
              build scorecard (ASR + eval_scores + eval_pass_rate)
                                        ▼
     audit bundle: findings.json · scorecard.json · report.md/html/csv · raw logs
                                        ▼
              SQLite metadata store  +  severity gate (pass/fail)
```

The network gateway is complementary: attack tools call `urt serve-gateway`'s `/v1/chat/completions`, which routes each request to the correct AI backend and records an audited, redacted transcript.

## Supported Targets, Engines & Evaluators

### Targets

| Target | Modes | Use it for |
|---|---|---|
| `copilot` | HTTP or SDK (Microsoft Copilot Studio) | Testing production Copilot Studio agents |
| `foundry` | HTTP (Azure AI Foundry) | Foundry model/agent endpoints |
| `http` | Generic JSON HTTP | Any custom agent/LLM behind an HTTP contract |

### Attack Engines

| Engine | Primary focus |
|---|---|
| `pyrit` | Native PyRIT 1.x PromptSendingAttack scans with ASR-style output |
| `promptfoo` | Assertion/dataset-based red-team checks and policy validation |
| `garak` | Probe-heavy robustness scanning with detector scores |
| `powerpwn` | Copilot Studio tenant recon and offensive posture checks |
| `powercat` | Governance/compliance-oriented Copilot Studio checks |
| `deepteam` | Vulnerability probing with reliable seeded fallback |
| `inspect` | Scenario/eval-style policy tests from Inspect AI |
| `giskard` | Scripted Giskard scan pipelines and issue parsing |

### Evaluators

| Evaluator | Backend | Sample metrics |
|---|---|---|
| `deepeval` | DeepEval | answer relevancy, faithfulness, hallucination, toxicity, bias |
| `promptfoo_eval` | Promptfoo | llm-rubric, factuality, similarity, model-graded |
| `giskard_eval` | Giskard | hallucination, toxicity, robustness, stereotypes, RAG faithfulness |
| `inspect_eval` | Inspect AI | task-based scorers, benchmark tasks |
| `azure_ai_eval` | Azure AI Evaluation SDK | groundedness, relevance, coherence, fluency, content safety |
| `custom_script` | Your script | any metric emitting `EvalScore`-compatible JSON |

## Requirements

**Core platform** (CLI, orchestrator, evaluators, REST API, network gateway, and the full test suite):

- [`uv`](https://docs.astral.sh/uv/) — the package/runtime manager
- Python `3.11+`

That is all you need to install dependencies, run the test suite, execute a run against an HTTP/Foundry/Copilot target, and start the API and gateway.

**Optional — only for specific engines:**

- Node.js `>= 22.22.0` with `npm` and `npx` — required by `promptfoo@0.123.0`
- Power CAT (`powercat`) has no public npm CLI; use the Copilot Studio Kit at https://github.com/microsoft/Power-CAT-Copilot-Studio-Kit
- The external engine CLIs themselves (Garak, DeepTeam, Giskard, Inspect, PowerPwn …) are installed on demand — see [Install](#install-uv-first). Engines you do not configure are never required.

## Repository Layout

```text
.
├── pyproject.toml                 # uv-managed project (package: urt, entry point: urt)
├── uv.lock                        # committed resolver lock (`uv sync --extra dev`)
├── scripts/
│   ├── bootstrap_uv.sh            # full local bootstrap (deps + engine tools + checks)
│   ├── install_engine_tools_uv.sh
│   ├── install_promptfoo_local.sh
│   ├── verify_engine_tooling.sh
│   └── urt_gateway.py             # gateway launcher
├── src/urt/
│   ├── cli.py                     # CLI entry point
│   ├── orchestrator.py            # run engine (orchestration gateway)
│   ├── api.py                     # FastAPI control-plane
│   ├── types.py                   # RunSpec, UnifiedFinding, EvalScore, …
│   ├── constants.py               # SUPPORTED_TARGETS / ENGINES / EVALUATORS
│   ├── report.py                  # Markdown / HTML / CSV renderers + gate
│   ├── adapters/
│   │   ├── targets/               # http, copilot, foundry
│   │   ├── engines/               # pyrit, promptfoo, garak, powerpwn, …
│   │   └── evaluators/            # deepeval, promptfoo_eval, giskard_eval, …
│   ├── gateway/                   # OpenAI-compatible network gateway
│   │   ├── app.py  router.py  redaction.py  session_store.py  audit.py
│   │   └── connectors/            # copilot_studio, azure_openai, foundry_*, …
│   ├── normalization/             # normalize_findings() + build_scorecard()
│   ├── policy/                    # OWASP LLM / OWASP Agentic / MITRE ATLAS mapping
│   ├── storage/                   # ArtifactStore (filesystem) + MetadataStore (SQLite)
│   └── integrations/mcs_pyrit/    # Copilot Studio + PyRIT integration scripts
├── templates/                     # sample RunSpecs + gateway config
├── examples/                      # deepteam_seeded/ + promptfoo_presets/
├── tests/                         # pytest suite (unit-focused, no external services)
└── docs/                          # deeper guides (gateway, datasets, onboarding)
```

## Quickstart (60 seconds)

Get the core platform running with nothing but `uv` and Python 3.11+:

```bash
# 1) Install core + dev dependencies (the dev extra adds pytest)
uv sync --extra dev

# 2) Confirm the CLI is wired
uv run urt --help

# 3) Run the test suite (unit-focused, no external services needed)
uv run pytest

# 4) Validate a sample run spec
uv run urt validate --spec templates/run_spec.sample.yaml

# 5) Start the OpenAI-compatible network gateway
uv run urt serve-gateway --config templates/gateway_config.sample.yaml
```

> The base `uv sync` installs the runtime; add `--extra dev` to also install `pytest`. Node.js and the external engine CLIs are only needed once you configure the engines that use them.

## Install (UV-First)

For a full local setup — core runtime **plus** the external attack-engine CLIs — run the bootstrap script from the repository root:

```bash
./scripts/bootstrap_uv.sh
```

Bootstrap does:
- `uv sync` for the URT runtime (respects committed `uv.lock`); bootstrap uses `--extra mcs` for the Copilot Studio GA client
- `uv tool install` for the Python engine CLIs
- local Promptfoo install under `~/.urt-tools/promptfoo` (`promptfoo@0.123.0`, Node `>= 22.22.0`)
- launcher verification for all engines
- local state folder creation under `.urt_state/`

> The bootstrap script requires Node.js `>= 22.22.0` (`npm`/`npx`) because it provisions `promptfoo@0.123.0`. If you only need the core platform, use the [Quickstart](#quickstart-60-seconds) instead.

Copilot Studio SDK mode needs the `mcs` extra (PyPI GA client `microsoft-agents-copilotstudio-client==1.5.0`):

```bash
uv sync --extra mcs
# or, with pytest:
uv sync --extra dev --extra mcs
```

## CLI Commands

```bash
uv run urt init --output run_spec.yaml
uv run urt validate --spec run_spec.yaml
uv run urt probe --spec run_spec.yaml
uv run urt run --spec run_spec.yaml
uv run urt runs
uv run urt findings --run-id <RUN_ID>
uv run urt artifacts --run-id <RUN_ID>
uv run urt waivers create --target-id <TARGET> --control-id LLM01:2025 --reason "accepted risk" --owner secops --expires-at 2027-01-01T00:00:00+00:00
uv run urt waivers list
uv run urt report --run-id <RUN_ID> --output-dir ./reports/<RUN_ID>
uv run urt gate --run-id <RUN_ID> --threshold high
uv run urt serve-api --host 127.0.0.1 --port 8000
uv run urt serve-gateway --config templates/gateway_config.sample.yaml
```

Global CLI options:
- `--artifact-root` default: `.urt_state/artifacts`
- `--metadata-db` default: `.urt_state/metadata/urt.sqlite3`

Example:

```bash
uv run urt \
  --artifact-root /tmp/urt_artifacts \
  --metadata-db /tmp/urt.sqlite3 \
  run --spec run_spec.yaml
```

## RunSpec Reference

Top-level keys:

| Key | Required | Type | Notes |
|---|---|---|---|
| `name` | yes | string | Run name, used in run-id slug |
| `run_profile` | no | string | `pr_gate`, `nightly`, `weekly_deep`. When `budget`/`timeouts` are omitted, profile defaults are applied. |
| `targets` | yes | list | At least one target |
| `engines` | yes | list | At least one engine |
| `evaluators` | no | list | Post-attack evaluators; each has `name`, `metrics`, `params`, `fail_open` |
| `policy_profiles` | no | list | Default: `owasp_llm`, `owasp_agentic`, `mitre_atlas` |
| `budget` | no | object | `max_duration_seconds` (enforced between engines/evaluators), `max_cost_usd` (enforced when engines/evaluators report `cost_usd` / `estimated_cost_usd`) |
| `timeouts` | no | object | `connect_seconds` (healthcheck), `request_seconds` (HTTP send), `engine_seconds` (engine/evaluator subprocess). Profile defaults apply when omitted. |
| `evidence_level` | no | string | `minimal` \| `standard` \| `full` (default `standard`). Caps captured stdout/stderr. |
| `seed` | no | int | Optional deterministic seed. Injected into engine/evaluator subprocesses as `URT_SEED` and `PYTHONHASHSEED`. |
| `metadata` | no | object | Free-form metadata |

String values in YAML/JSON run specs expand `${VAR_NAME}` from the process environment at load time.

Target object:

| Key | Required | Type | Notes |
|---|---|---|---|
| `id` | yes | string | Unique target id |
| `type` | yes | string | `copilot`, `foundry`, `http` |
| `endpoint` | depends | string | Required for HTTP mode targets |
| `auth` | no | object | Target-specific auth values |
| `config` | no | object | Target-specific runtime options |
| `rate_limits` | no | object | `requests_per_minute` and/or `min_interval_seconds` for HTTP send |

Engine object:

| Key | Required | Type | Notes |
|---|---|---|---|
| `name` | yes | string | One of supported engine names |
| `version` | no | string | Informational |
| `enabled_scenarios` | no | list | Scenario/category/preset filter. Promptfoo uses this to filter datasets; all CLI engines receive `URT_ENABLED_SCENARIOS`. |
| `params` | no | object | Engine-specific parameters |
| `fail_open` | no | bool | Default `true`; set `false` to fail run on engine failure |

## Target Configuration Cookbook

### 1) Generic HTTP Target (`type: http`)

```yaml
targets:
  - id: generic-agent
    type: http
    endpoint: http://localhost:8080/invoke
    auth:
      headers:
        Authorization: "Bearer <token>"
    config:
      skip_healthcheck: true
      healthcheck_path: /healthz
      healthcheck_timeout: 5
      method: POST
      timeout_seconds: 60
      retry_attempts: 2
      retry_backoff_seconds: 1.0
      retry_on_status: [429, 500, 502, 503, 504]
      request_template:
        messages: []
        session_id: ""
        context: {}
```

HTTP response extraction order:
1. `content`
2. `output`
3. last assistant message from `messages[]`
4. full payload as string

### 2) Azure AI Foundry Target (`type: foundry`)

```yaml
targets:
  - id: foundry-agent
    type: foundry
    endpoint: https://<foundry-endpoint>/api/chat
    auth:
      bearer_token: "<aad-token>"   # optional
      api_key: "<api-key>"          # optional
      headers:
        x-custom-header: "value"
    config:
      skip_healthcheck: true
```

Foundry auth keys supported in `target.auth`:
- `bearer_token`
- `api_key`
- `headers` (merged into request headers)

### 3) Copilot Target (HTTP mode)

```yaml
targets:
  - id: copilot-http
    type: copilot
    endpoint: https://<copilot-endpoint>/api/chat
    auth:
      headers:
        Authorization: "Bearer <token>"
    config:
      mode: http
      skip_healthcheck: true
```

### 4) Copilot Target (SDK mode)

```yaml
targets:
  - id: mcs-agent
    type: copilot
    config:
      mode: sdk
      skip_healthcheck: true
      sdk_path: src/urt/integrations/mcs_pyrit/copilot_client.py
      tenant_id: "<tenant-id>"
      app_client_id: "<app-client-id>"
      environment_id: "<environment-id>"
      agent_identifier: "<agent-identifier>"
```

SDK mode requires these keys in either `target.auth` or `target.config`:
- `tenant_id`
- `app_client_id`
- `environment_id`
- `agent_identifier`

`sdk_path` default:
- `src/urt/integrations/mcs_pyrit/copilot_client.py`

## Engine Usage Cookbook

You can run one engine at a time or all together.
For one-engine runs, keep a single `engines:` entry in the spec.

### PyRIT (`name: pyrit`)

Primary use:
- Native **PyRIT 1.x** `PromptSendingAttack` scans against a Copilot Studio callback target, with ASR-style `final_results.json`

The runtime venv pins `pyrit>=1.1,<2` and `openai>=3,<4`. `azure-ai-evaluation` stays for the evaluator path and **does not** pull the `[redteam]` extra (that extra hard-pins pyrit 0.11, which cannot import against PyRIT 1.x).

Params:

| Param | Required | Type | Default | Notes |
|---|---|---|---|---|
| `script_path` | no | string | `src/urt/integrations/mcs_pyrit/red_team_scan.py` | PyRIT entry script |
| `config_path` | no | string | `src/urt/integrations/mcs_pyrit/config/mcs_agent_callback.json` | PyRIT config JSON |
| `working_dir` | no | string | repo root | where `.scan_*` folders are produced |
| `command` | no | string/list | auto-built | overrides script/config execution |

Example:

```yaml
engines:
  - name: pyrit
    fail_open: false
    params:
      script_path: src/urt/integrations/mcs_pyrit/red_team_scan.py
      config_path: src/urt/integrations/mcs_pyrit/config/mcs_agent_callback.json
      working_dir: .
```

Run:

```bash
uv run urt run --spec specs/pyrit.real.yaml
```

### Promptfoo (`name: promptfoo`)

Primary use:
- assertion-based red-team checks and policy validation

Params:

| Param | Required | Type | Default | Notes |
|---|---|---|---|---|
| `prompt_source` | no | string/object | none | dataset source: `preset:<name>`, preset short name, file path, or object |
| `config_template_path` | conditional | string | none | template used to generate per-run promptfoo config in dataset mode |
| `dataset_var` | no | string | `attack_prompt` | var name inserted into generated tests |
| `dataset_field` | no | string | `attack_prompt` | preferred field while reading JSONL/CSV/JSON rows |
| `dataset_limit` | no | int | none | hard cap on loaded prompts |
| `dataset_dedupe` | no | bool | `true` | de-duplicate prompts |
| `dataset_profile_per_preset_limit` | no | int | none | when `prompt_source` is profile, cap each preset before merge |
| `command` | conditional | string/list | none | full promptfoo command override |
| `config_path` | conditional | string | none | used when `command` absent and dataset mode is disabled |
| `output_json` | no | string | none | parsed into normalized findings |
| `eval_args` | no | string/list | `--no-progress-bar --max-concurrency 1` | extra args in generated eval command |
| `env` | no | object | none | additional environment variables |
| `disable_cache` | no | bool | `false` | sets `PROMPTFOO_CACHE_ENABLED=false`, `PROMPTFOO_CACHE_TYPE=memory` |
| `disable_wal_mode` | no | bool | `false` | sets `PROMPTFOO_DISABLE_WAL_MODE=true` |
| `config_dir` | no | string | none | sets `PROMPTFOO_CONFIG_DIR` |
| `node_bin_dir` | no | string | none | prepends PATH (Node.js >= 22.22.0; required by promptfoo 0.123.0) |
| `working_dir` | no | string | none | command working directory |
| `binary_path` | no | string | none | manual path to promptfoo binary |

Example:

```yaml
engines:
  - name: promptfoo
    fail_open: false
    params:
      prompt_source:
        mode: preset
        preset: copilot_security_starter
        limit: 25
      config_template_path: templates/promptfoo_eval.template.yaml
      dataset_var: attack_prompt
      output_json: /tmp/urt-real-attacks/promptfoo_results.json
      eval_args: "--no-progress-bar --max-concurrency 1"
      disable_cache: true
      disable_wal_mode: true
      config_dir: /tmp/promptfoo-urt-runtime
```

Run:

```bash
uv run urt run --spec templates/run_spec.promptfoo_dataset.sample.yaml
```

Important:
- If tests do not include meaningful `assert` clauses, results can be informational only.

Dataset mode options:
- Built-in presets:
  - `copilot_security_starter`
  - `jailbreakbench_starter` (alias: `jailbreakbench`)
  - `harmbench_starter` (alias: `harmbench`)
  - `xstest_starter` (alias: `xstest`)
  - `donotanswer_starter` (aliases: `donotanswer`, `do_not_answer`)
  - `beavertails_starter` (alias: `beavertails`)
  - `aegis_starter` (alias: `aegis`)
  - `bipia_indirect_injection_starter` (aliases: `bipia`, `bipia_indirect_injection`)
  - `cyberseceval_starter` (alias: `cyberseceval`)
  - `simplesafetytests_starter` (alias: `simplesafetytests`)
  - `agentic_tool_abuse_starter` (alias: `agentic_tool_abuse`)
- Custom file formats:
  - `.jsonl` (one object/string per line)
  - `.csv` (column lookup with fallback)
  - `.json` (array or object containing `prompts`/`attacks`/`inputs`)
  - `.txt` / `.md` (one prompt per line)
- Built-in composition profiles (single parameter):
  - `fast`: `copilot_security_starter` + `xstest_starter`
  - `balanced`: `copilot_security_starter` + `jailbreakbench_starter` + `harmbench_starter` + `xstest_starter`
  - `agentic`: `copilot_security_starter` + `agentic_tool_abuse_starter` + `bipia_indirect_injection_starter`
  - `cyber`: `cyberseceval_starter` + `xstest_starter`

Preset coverage guidance:
- `copilot_security_starter`: prompt injection, policy exfiltration, tool abuse, RAG/indirect injection, authz/audit evasion.
- `jailbreakbench_starter`: jailbreak technique families (role-play, authority spoofing, obfuscation, multi-turn poisoning).
- `harmbench_starter`: broad harmful capability requests (violence, cybercrime, fraud, critical infrastructure abuse).
- `xstest_starter`: mixed benign/ambiguous/unsafe prompts for under-refusal and over-refusal checks.
- `donotanswer_starter`: disallowed content classes from safety refusal benchmarks.
- `beavertails_starter`: fine-grained safety risk categories aligned to BeaverTails style taxonomy.
- `aegis_starter`: toxicity + jailbreak + unsafe behavior stress tests.
- `bipia_indirect_injection_starter`: indirect prompt injection via context artifacts (email/html/json/csv/wiki).
- `cyberseceval_starter`: cybersecurity dual-use coverage (defensive + offensive misuse attempts).
- `simplesafetytests_starter`: compact harmful prompt set for fast refusal baseline checks.
- `agentic_tool_abuse_starter`: agent-specific tool abuse, approval bypass, and audit evasion tests.

Custom prompt_source examples:

```yaml
# String shortcut, preset
prompt_source: preset:harmbench

# String shortcut, local file
prompt_source: /absolute/path/to/my_prompts.csv

# Object mode for file
prompt_source:
  mode: file
  path: /absolute/path/to/my_prompts.jsonl
  field: prompt
  limit: 100
  dedupe: true

# Single-parameter profile mode
prompt_source: profile:balanced

# Profile mode with per-preset cap
prompt_source:
  mode: profile
  profile: agentic
  per_preset_limit: 20
  limit: 50

# Custom profile composition
prompt_source:
  profile: custom
  presets:
    - xstest_starter
    - cyberseceval_starter
  per_preset_limit: 15
```

For source provenance and category mapping details, see:
- `docs/promptfoo-preset-catalog.md`

### Garak (`name: garak`)

Primary use:
- probe-heavy robustness scanning and detector scores

Params:

| Param | Required | Type | Default | Notes |
|---|---|---|---|---|
| `command` | yes | string/list | none | garak invocation command |
| `report_jsonl` | no | string | none | parser input for normalized findings |

Example:

```yaml
engines:
  - name: garak
    params:
      command: >-
        /bin/zsh -lc '
        XDG_DATA_HOME=/tmp/garak-data
        garak -m openai.OpenAICompatible -n mcs-proxy
        -p promptinject.HijackKillHumans -g 1
        --generator_option_file /tmp/urt-real-attacks/garak_generator_options.json
        --report_prefix /tmp/urt-real-attacks/garak_report'
      report_jsonl: /tmp/urt-real-attacks/garak_report.report.jsonl
```

`/tmp/urt-real-attacks/garak_generator_options.json` example:

```json
{
  "openai": {
    "OpenAICompatible": {
      "uri": "http://127.0.0.1:18080/v1/",
      "temperature": 0,
      "max_tokens": 128
    }
  }
}
```

Note: for `openai.OpenAICompatible`, endpoint overrides must be nested under
`openai -> OpenAICompatible`. Flat `{"uri": "..."}` values fall back to
Garak's default `http://localhost:8000/v1/`.

Run:

```bash
uv run urt run --spec specs/garak.real.yaml
```

### PowerPwn (`name: powerpwn`)

Primary use:
- Copilot Studio tenant recon and offensive posture checks

Params:

| Param | Required | Type | Default | Notes |
|---|---|---|---|---|
| `mode` | no | string | `recon-only` | any value other than `recon-only` is treated as active mode |
| `approved` | conditional | bool | `false` | must be `true` when mode is active |
| `command` | no | string/list | `powerpwn copilot-studio-hunter enum` | executable command |

Example (recon-only):

```yaml
engines:
  - name: powerpwn
    params:
      mode: recon-only
      command: powerpwn copilot-studio-hunter tools-recon
```

Example (active mode, explicit approval):

```yaml
engines:
  - name: powerpwn
    fail_open: false
    params:
      mode: active
      approved: true
      command: powerpwn copilot-studio-hunter deep-scan
```

Run:

```bash
uv run urt run --spec specs/powerpwn.real.yaml
```

### Power CAT (`name: powercat`)

Primary use:
- governance/compliance oriented Copilot Studio checks

There is **no public npm CLI**. Microsoft ships the Kit as a Power Platform solution and the `agent-review-pipeline` GitHub Action in [microsoft/Power-CAT-Copilot-Studio-Kit](https://github.com/microsoft/Power-CAT-Copilot-Studio-Kit). `@microsoft/copilot-studio-kit-cli` is not published (npm E404). Do not invent a replacement package name. `pac` is a tertiary Power Platform CLI, not the Kit.

Params:

| Param | Required | Type | Default | Notes |
|---|---|---|---|---|
| `command` | no | string/list | `copilot-studio-kit agent-review run` | if the launcher is missing, the engine skips with a `coverage_gap` pointing at the GitHub repo. Unpublished npm / `npx github:...` commands are skipped the same way. |

Example:

```yaml
engines:
  - name: powercat
    params:
      command: copilot-studio-kit agent-review run
```

Run:

```bash
uv run urt run --spec specs/powercat.real.yaml
```

### DeepTeam (`name: deepteam`)

Primary use:
- vulnerability probing with optional seeded fallback

Params:

| Param | Required | Type | Default | Notes |
|---|---|---|---|---|
| `command` | yes | string/list | none | deepteam execution pipeline |
| `output_json` | no | string | none | parser input |
| `require_test_cases` | no | bool | `true` | if true, zero-test outputs mark engine as failed |

Example (seeded reliable mode):

```yaml
engines:
  - name: deepteam
    fail_open: false
    params:
      command: >-
        /bin/zsh -lc 'DEEPTEAM_SEED_DATASET=examples/deepteam_seeded/deepteam_seed_attacks.sample.json
        DEEPTEAM_PROXY_URL=http://127.0.0.1:18080/v1/chat/completions
        deepteam run examples/deepteam_seeded/deepteam_real.sample.yaml
        --output-folder /tmp/urt-real-attacks/deepteam_out
        --attacks-per-vuln 3 --max-concurrent 1
        && python examples/deepteam_seeded/build_deepteam_results.py
        --out-dir /tmp/urt-real-attacks/deepteam_out
        --output /tmp/urt-real-attacks/deepteam_results.json'
      output_json: /tmp/urt-real-attacks/deepteam_results.json
      require_test_cases: true
```

Run:

```bash
uv run urt run --spec templates/run_spec.deepteam_seeded.sample.yaml
```

DeepTeam reliability guidance:
- keep `require_test_cases: true`
- in DeepTeam yaml, set `system_config.ignore_errors: false`
- use seed fallback when dynamic generation returns no test cases
- dataset notes: `docs/deepteam-datasets.md`

### Inspect (`name: inspect`)

Primary use:
- scenario/eval style policy tests from Inspect AI outputs

Params:

| Param | Required | Type | Default | Notes |
|---|---|---|---|---|
| `command` | yes | string/list | none | inspect command |
| `output_json` | no | string | none | parser input (`tests` or `results`) |

Example:

```yaml
engines:
  - name: inspect
    params:
      command: >-
        uvx --from inspect-ai==0.3.263 inspect eval /tmp/urt-real-attacks/inspect_suite.py
        --json --output /tmp/urt-real-attacks/inspect_results.json
      output_json: /tmp/urt-real-attacks/inspect_results.json
```

Run:

```bash
uv run urt run --spec specs/inspect.real.yaml
```

### Giskard (`name: giskard`)

Primary use:
- scripted Giskard scan pipelines and issue parsing

Params:

| Param | Required | Type | Default | Notes |
|---|---|---|---|---|
| `command` | yes | string/list | none | usually `uvx ... python your_scan.py` |
| `output_json` | no | string | none | parser input (`issues`/`findings`/`tests`) |

Example:

```yaml
engines:
  - name: giskard
    params:
      command: >-
        uvx --python 3.12 --from 'giskard[scan]==3.0.0' python
        /tmp/urt-real-attacks/giskard_real_scan.py
      output_json: /tmp/urt-real-attacks/giskard_results.json
```

Run:

```bash
uv run urt run --spec specs/giskard.real.yaml
```

---

## Evaluator Engine Integration

URT extends beyond red-teaming with a built-in **evaluator adapter layer**. Evaluators run **after** (or alongside) red-team engines and score AI agent responses on quality, safety, and compliance dimensions — giving you a single platform for both offensive testing and quality evaluation.

### Supported Evaluators

| Evaluator | Backend | Primary Metrics |
|---|---|---|
| `deepeval` | [DeepEval](https://github.com/confident-ai/deepeval) | answer relevancy, faithfulness, hallucination, toxicity, bias, contextual recall/precision |
| `promptfoo_eval` | [Promptfoo](https://promptfoo.dev/) | llm-rubric, factuality, answer-relevance, similarity, model-graded, custom assertions |
| `giskard_eval` | [Giskard](https://giskard.ai/) | hallucination, toxicity, robustness, stereotypes, RAG faithfulness |
| `inspect_eval` | [Inspect AI](https://inspect.ai-safety-institute.org.uk/) | task-based evaluation, custom scorers, benchmark tasks (MMLU, HumanEval, etc.) |
| `azure_ai_eval` | [Azure AI Evaluation SDK](https://learn.microsoft.com/en-us/azure/ai-studio/how-to/evaluate-sdk) | groundedness, relevance, coherence, fluency, content safety |
| `custom_script` | User-supplied script | any metric — outputs JSON with `EvalScore`-compatible results |

### Evaluator Spec Reference

Each evaluator entry in the `evaluators:` section of a RunSpec supports:

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `name` | string | yes | — | evaluator identifier (see table above) |
| `version` | string | no | `null` | version constraint (informational) |
| `metrics` | list[str] | no | `[]` | metric names to evaluate (evaluator-specific) |
| `params` | dict | no | `{}` | evaluator-specific parameters |
| `fail_open` | bool | no | `true` | if `true`, evaluator errors don't fail the run |

### Architecture Overview

```
RunSpec → Orchestrator.execute()
  → for each target:
      → target_adapter.healthcheck()
      → target_adapter.start_session()
      → for each engine:
          → engine_adapter.run(context) → EngineRunResult(findings, metrics, artifacts)
      → for each evaluator:
          → evaluator_adapter.evaluate(eval_context)
          →   → EvalRunResult(scores, findings, artifacts)
      → target_adapter.end_session()
  → normalize_findings()
  → aggregate eval_scores + eval_pass_rate
  → build_scorecard() → render reports (with eval section)
```

Evaluators receive an `EvalContext` containing:
- Run metadata (`run_id`, `run_name`, `run_profile`, `seed`, `evidence_level`)
- Target information
- Artifact store for writing output files
- **Red-team engine findings** from the current run (for eval-after-attack patterns)
- **Engine run results** for cross-referencing

### Evaluator Usage Cookbook

#### DeepEval (`name: deepeval`)

Primary use:
- LLM-as-judge evaluation for answer quality, faithfulness, hallucination, toxicity, and bias

Params:

| Param | Required | Type | Default | Notes |
|---|---|---|---|---|
| `command` | yes* | string/list | none | CLI command, e.g., `deepeval test run` |
| `output_json` | no | string | none | path to JSON output with test results |
| `model` | no | string | `gpt-4.1-mini` | LLM judge model (informational) |
| `threshold` | no | float | `0.5` | pass/fail threshold for all metrics |

\* Either `command` is required.

Example:

```yaml
evaluators:
  - name: deepeval
    metrics: [answer_relevancy, faithfulness, toxicity]
    params:
      model: gpt-4.1-mini
      threshold: 0.5
      command: "uvx --from deepeval==4.2.2 deepeval --help"
      output_json: /tmp/deepeval_results.json
```

Output parsing: DeepEval outputs `test_results[]` with per-metric scores. The adapter maps these to normalized `EvalScore` objects. Supports both `test_results[].metrics_data[]` format and flat `scores[]` fallback.

#### Promptfoo Eval (`name: promptfoo_eval`)

Primary use:
- assertion-based evaluation with rich grading options (LLM rubric, factuality, similarity)

Params:

| Param | Required | Type | Default | Notes |
|---|---|---|---|---|
| `command` | no | string/list | auto from `config_path` | e.g., `promptfoo eval -c config.yaml` |
| `config_path` | no | string | none | path to eval config YAML |
| `output_json` | no | string | none | path to results JSON |
| `threshold` | no | float | `0.5` | pass/fail threshold |

Example:

```yaml
evaluators:
  - name: promptfoo_eval
    params:
      config_path: templates/promptfoo_eval.template.yaml
      output_json: /tmp/promptfoo_eval_results.json
```

Output parsing: Parses Promptfoo's `results[].gradingResult.componentResults[]` to extract per-assertion scores. Each assertion type (llm-rubric, factuality, etc.) becomes a separate `EvalScore`.

#### Azure AI Eval (`name: azure_ai_eval`)

Primary use:
- enterprise-grade quality and safety evaluation using Azure AI Evaluation SDK

Params:

| Param | Required | Type | Default | Notes |
|---|---|---|---|---|
| `command` | no | string/list | auto from `script_path` | custom eval script command |
| `script_path` | no | string | none | path to Python eval script |
| `output_json` | no | string | none | path to JSON results |
| `azure_project_endpoint` | no | string | none | Azure AI project endpoint (also reads `$AZURE_PROJECT_ENDPOINT`) |
| `threshold` | no | float | `0.5` | pass/fail threshold |

Score normalization:
- **Quality metrics** (groundedness, relevance, coherence, fluency): 1-5 Likert scale → normalized to 0.0-1.0 via `(raw - 1) / 4`
- **Safety metrics** (violence, sexual, self_harm, hate): 0-7 severity scale → normalized to 0.0-1.0 via `1 - (raw / 7)` (inverted: higher = safer)

Example:

```yaml
evaluators:
  - name: azure_ai_eval
    metrics: [groundedness, relevance, coherence, content_safety]
    params:
      script_path: scripts/run_azure_eval.py
      output_json: /tmp/azure_eval_results.json
      azure_project_endpoint: ${AZURE_PROJECT_ENDPOINT}
```

Output parsing: Supports three formats:
1. Top-level `metrics` dict (e.g., `{"metrics": {"gpt_groundedness": 4.2}}`)
2. Per-row results with column-level scores (e.g., `outputs.groundedness.gpt_groundedness`)
3. Flat `scores[]`/`evaluations[]`/`results[]` arrays

#### Giskard Eval (`name: giskard_eval`)

Primary use:
- automated scan for quality issues, robustness, hallucination, stereotypes, and RAG evaluation

Params:

| Param | Required | Type | Default | Notes |
|---|---|---|---|---|
| `command` | yes | string/list | none | e.g., `python -m giskard scan --output results.json` |
| `output_json` | no | string | none | path to scan results JSON |
| `threshold` | no | float | `0.5` | pass/fail threshold |

Severity mapping: Giskard scan issues have severity levels mapped to scores:
- `major` → 0.1 (critical failure)
- `medium` → 0.3
- `minor` → 0.6
- `info` → 0.8

Example:

```yaml
evaluators:
  - name: giskard_eval
    metrics: [hallucination, toxicity, robustness]
    params:
      command: "python -m giskard scan --output /tmp/giskard_scan.json"
      output_json: /tmp/giskard_scan.json
```

Output parsing: Parses Giskard's `issues[]` array. Each issue's `level` maps to a score, and the issue `description` becomes the reason. Also supports `tests[]` and `findings[]` keys.

#### Inspect AI Eval (`name: inspect_eval`)

Primary use:
- task-based evaluation with custom solvers/scorers and benchmark support

Params:

| Param | Required | Type | Default | Notes |
|---|---|---|---|---|
| `command` | yes | string/list | none | e.g., `inspect eval tasks/safety.py --model openai/gpt-4.1-mini` |
| `output_json` | no | string | none | path to eval results JSON |
| `log_dir` | no | string | none | directory for Inspect logs |
| `threshold` | no | float | `0.5` | pass/fail threshold |

Example:

```yaml
evaluators:
  - name: inspect_eval
    params:
      command: "inspect eval tasks/safety_eval.py --model openai/gpt-4.1-mini"
      output_json: /tmp/inspect_eval_results.json
      log_dir: /tmp/inspect_logs
```

Output parsing: Supports multiple Inspect output formats:
1. `results.scores[].metrics{}` — named scorer with metric dict
2. Single `results.scores.metrics{}` — single scorer output
3. `results.metrics{}` — flat metrics
4. `samples[]` — per-sample aggregation with mean scores

#### Custom Script (`name: custom_script`)

Primary use:
- run any user-supplied evaluation script that outputs JSON with `EvalScore`-compatible results

Params:

| Param | Required | Type | Default | Notes |
|---|---|---|---|---|
| `command` | yes | string/list | none | command to run your eval script |
| `output_json` | no | string | none | path to JSON output |
| `threshold` | no | float | `0.5` | default pass/fail threshold |
| `env` | no | dict | `{}` | environment variable overrides |
| `working_dir` | no | string | none | working directory for the command |

Expected output schema:

```json
{
  "scores": [
    {
      "metric": "custom_safety",
      "score": 0.85,
      "passed": true,
      "threshold": 0.5,
      "reason": "All safety checks passed"
    },
    {
      "metric": "response_quality",
      "score": 0.42,
      "passed": false,
      "threshold": 0.5,
      "reason": "Response lacked detail in 3 of 5 test cases"
    }
  ]
}
```

Example:

```yaml
evaluators:
  - name: custom_script
    params:
      command: "python scripts/custom_eval.py --input findings.json --output /tmp/custom_scores.json"
      output_json: /tmp/custom_scores.json
```

### Combined Example: Engines + Evaluators

```yaml
name: copilot-full-assessment
run_profile: nightly

targets:
  - id: mcs-agent
    type: copilot
    endpoint: https://your-copilot/api/chat
    auth:
      headers:
        Authorization: "Bearer ${COPILOT_TOKEN}"

engines:
  - name: promptfoo
    params:
      command: "promptfoo redteam run -c templates/promptfoo.yaml"
      output_json: /tmp/promptfoo_results.json

  - name: deepteam
    params:
      command: "uvx --from deepteam==1.0.9 deepteam run --config config.json"
      require_test_cases: true

evaluators:
  - name: deepeval
    metrics: [answer_relevancy, faithfulness, toxicity]
    params:
      model: gpt-4.1-mini
      threshold: 0.5
      command: "deepeval test run tests/eval_test.py"
      output_json: /tmp/deepeval_results.json

  - name: azure_ai_eval
    metrics: [groundedness, relevance, content_safety]
    params:
      script_path: scripts/run_azure_eval.py
      output_json: /tmp/azure_eval_results.json
      azure_project_endpoint: ${AZURE_PROJECT_ENDPOINT}

  - name: custom_script
    params:
      command: "python scripts/domain_eval.py"
      output_json: /tmp/domain_scores.json

policy_profiles: [owasp_llm, owasp_agentic, mitre_atlas]
budget:
  max_duration_seconds: 7200
```

### Evaluation Output

After a run with evaluators, the scorecard includes:

```json
{
  "eval_scores": {
    "answer_relevancy": 0.82,
    "faithfulness": 0.91,
    "toxicity": 0.95,
    "groundedness": 0.78,
    "content_safety": 0.99
  },
  "eval_pass_rate": 0.85
}
```

- `eval_scores`: per-metric averages across all evaluators and targets (0.0-1.0, higher is better)
- `eval_pass_rate`: fraction of individual metric scores that passed their thresholds

Reports (`report.md`, `report.html`) include a dedicated **Evaluation Results** section with:
- Overall pass rate
- Per-metric score table with pass/fail status
- Evaluator execution details in findings

---

## Example: All Engines in One Run

Use the sample and customize:

```bash
cp templates/run_spec.sample.yaml run_spec.all_engines.yaml
uv run urt validate --spec run_spec.all_engines.yaml
uv run urt run --spec run_spec.all_engines.yaml
```

Recommended for strict real runs:
- set `fail_open: false` for engines you require
- keep `deepteam.params.require_test_cases: true`
- keep output paths unique per engine

## Output, Reports, and Audit Format

Each run writes to:
- `.urt_state/artifacts/<RUN_ID>/`

Canonical files:
- `resolved_spec.json`
- `run_manifest.json`
- `engine_invocations.json`
- `artifacts_index.json`
- `findings.json`
- `scorecard.json`
- `run_summary.json`
- `report.md`
- `report.html`
- `report.csv`

Raw engine logs/artifacts:
- `raw/<engine>/<target_id>_stdout.log`
- `raw/<engine>/<target_id>_stderr.log`
- optional parsed tool outputs (for engines with `output_json` / `report_jsonl`)

`findings.json` record shape:

```json
{
  "finding_id": "run-...:target:engine:item",
  "run_id": "run-...",
  "target_id": "target-id",
  "engine": "promptfoo",
  "category": "policy_violation",
  "sub_category": "harmbench",
  "severity": "medium",
  "confidence": 0.8,
  "attack_vector": "prompt_injection",
  "attack_complexity": "unknown",
  "success": true,
  "description": "..."
}
```

`scorecard.json` keys:
- `total_findings`
- `critical`, `high`, `medium`, `low`, `info`
- `success_count`, `total_attacks`
- `asr_overall`
- `asr_by_category`
- `by_engine`
- `eval_scores` — map of metric name to average score across all evaluator runs (e.g. `{"answer_relevancy": 0.82, "toxicity": 0.04}`)
- `eval_pass_rate` — fraction of individual metric scores that passed their threshold (0.0–1.0)

`report.csv` columns:
- `finding_id`
- `run_id`
- `target_id`
- `engine`
- `severity`
- `category`
- `sub_category`
- `attack_vector`
- `attack_complexity`
- `success`
- `description`

## Running Named Scans (Useful for Foundry/Copilot Console Visibility)

Use unique `name` values per run:

```yaml
name: mcs-agent-promptfoo-real-20260304
```

Run each engine separately first, then combined:
1. `name: <agent>-pyrit-real-<date>`
2. `name: <agent>-promptfoo-real-<date>`
3. `name: <agent>-garak-real-<date>`
4. `name: <agent>-deepteam-real-<date>`
5. `name: <agent>-all-engines-real-<date>`

This makes enumeration/audit trails easier in external consoles.

## API

Start API:

```bash
uv run urt serve-api --host 127.0.0.1 --port 8000
```

Endpoints:
- `GET /healthz`
- `GET /v1/runs`
- `POST /v1/runs`
- `GET /v1/runs/{run_id}`
- `GET /v1/runs/{run_id}/findings`
- `GET /v1/runs/{run_id}/artifacts`
- `POST /v1/waivers`
- `GET /v1/waivers`

## Network Gateway (Multi-Backend OpenAI Bridge)

Use the network gateway when you want one OpenAI-compatible endpoint for multiple agent backends.

Start with sample config:

```bash
uv run urt serve-gateway \
  --config templates/gateway_config.sample.yaml \
  --print-effective-config
```

Health checks:

```bash
curl -s http://127.0.0.1:18080/healthz | jq
curl -s "http://127.0.0.1:18080/healthz?deep=true" | jq
```

Routing modes:
- `header` mode: send `X-URT-Target: <target_id>`
- `model` mode: send `model: urt/<target_id>`
- `path` mode: call `/v1/chat/completions/<target_id>`

Supported connectors:
- `copilot_studio_sdk`
- `foundry_model_inference`
- `foundry_agent_service`
- `azure_openai_deployment`
- `openai_compatible_http`
- `generic_http_json`

Optional ingress / session:
- `gateway.api_key` — shared secret for `/v1/chat/completions` (`Authorization: Bearer …`, `X-API-Key`, or `X-URT-API-Key`). `/healthz` stays open.
- `gateway.session_persist_path` — persists Foundry `thread_id` across process restarts. Live Copilot SDK clients are not serializable.

Known limitation: SSE is a single-chunk compatibility shim, not true token streaming from backends.

Launcher:
- `scripts/urt_gateway.py` or `uv run urt serve-gateway`

Promptfoo via gateway sample:

```bash
uv run urt validate --spec templates/run_spec.promptfoo_gateway.sample.yaml
uv run urt run --spec templates/run_spec.promptfoo_gateway.sample.yaml
```

## Runtime Contracts

These `RunSpec` / gateway fields are **enforced at runtime** (not schema-only):

| Contract | Runtime behavior |
|---|---|
| `budget.max_duration_seconds` | Abort between engines/evaluators when wall-clock exceeds the cap |
| `budget.max_cost_usd` | Abort only if a tool reports `cost_usd` / `estimated_cost_usd`; otherwise `cost_enforcement: unmetered` |
| `timeouts.connect_seconds` | HTTP healthcheck timeout |
| `timeouts.request_seconds` | HTTP send timeout |
| `timeouts.engine_seconds` | Engine/evaluator subprocess timeout |
| `run_profile` | Supplies budget/timeout defaults when those keys are omitted; explicit YAML wins |
| `evidence_level` | Caps captured stdout/stderr (`minimal` 8KiB, `standard` 256KiB, `full` unlimited) |
| `seed` | Injected as `URT_SEED` and `PYTHONHASHSEED` into subprocesses |
| `enabled_scenarios` | Promptfoo filters dataset/preset rows; other CLIs receive `URT_ENABLED_SCENARIOS` |
| `rate_limits` | HTTP send spacing (`requests_per_minute` / `min_interval_seconds`) |
| evaluator `fail_open: false` | Failed evaluator aborts the run (same as engines) |
| waivers | `urt gate` skips matching active findings; `--ignore-waivers` bypasses |
| spec `${VAR_NAME}` | Expanded from the process environment at `load_run_spec` |
| `gateway.api_key` | Optional; missing key keeps the open Promptfoo dummy-key path |

**Intentionally not claimed** (need new backend/telemetry, not a wiring patch):

- True token streaming from connectors
- Persisting live Copilot Studio SDK clients across gateway restart
- Invented USD cost when engines do not report it
- Mapping `URT_ENABLED_SCENARIOS` onto Garak/PyRIT/DeepTeam native CLI flags
- Turning `pr_gate` / `nightly` / `weekly_deep` into a separate CI planner
- Async job queue for `POST /v1/runs` (that endpoint is synchronous)

## Troubleshooting

- `command launcher not found`
  - Run `./scripts/verify_engine_tooling.sh`
  - Re-run `./scripts/bootstrap_uv.sh`

- Promptfoo launcher not resolved
  - Set `URT_PROMPTFOO_BIN=/absolute/path/to/promptfoo`
  - Or set `engines[].params.binary_path`

- Gateway cannot resolve target
  - Check `routing.mode`
  - Ensure `routing.default_target` exists in `targets`
  - For header mode ensure `X-URT-Target` is sent

- Gateway connector config errors
  - Run `curl "http://127.0.0.1:18080/healthz?deep=true"`
  - Fix missing keys shown under `checks[].detail`

- DeepTeam exits with no usable cases
  - Ensure `require_test_cases: true`
  - Ensure DeepTeam yaml has `ignore_errors: false`
  - Use seeded mode under `examples/deepteam_seeded/`

- PowerPwn active mode skipped
  - Set both `mode: active` and `approved: true`

- Run fails fast unexpectedly
  - Check engine `fail_open` flags
  - Inspect `run_manifest.json` and `run_error.log`

- Evaluator produces no scores (`eval_scores` empty, `eval_pass_rate` 0.0)
  - Ensure the evaluator adapter returned `EvalRunResult` with at least one `EvalScore`
  - Check `evaluator_summaries` in `run_summary.json` for `score_count`
  - Verify `output_json` path is correct and the file was written by the evaluator command

- Evaluator marked `status: failed` in `run_summary.json`
  - Check `run_error.log` for the evaluator exception traceback
  - Set `fail_open: false` on the evaluator to promote failures to run-level errors
  - Ensure required env vars (e.g. `AZURE_PROJECT_ENDPOINT`) are exported before running

## Related Docs

- Consultant setup: `docs/consultant-onboarding.md`
- DeepTeam dataset strategy: `docs/deepteam-datasets.md`
- Legacy migration notes: `docs/migration-from-legacy.md`
- Network gateway design: `docs/universal_gateway.md`
- License: `LICENSE`
- Security: `SECURITY.md`
