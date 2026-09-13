# Consultant Onboarding (Local, Manual Runs)

## Objective

Set up Redplane on a consultant laptop so they can run manual attack-and-evaluation assessments, store full audit artifacts locally, and export reports for customers.

## Prerequisites

- macOS/Linux shell environment
- Python 3.11+
- `uv` installed
- Node.js >= 22.22.0 (`npm`, `npx`) — required by `promptfoo@0.123.0`
- Access credentials for target agents (Copilot Studio or Foundry)

## One-Time Setup

```bash
./scripts/bootstrap_uv.sh
```

## Minimal Operational Checks

```bash
uv run urt --help
uv run urt init --smoke --output /tmp/urt_smoke.yaml
uv run urt validate --spec /tmp/urt_smoke.yaml
```

## Engine Installation Model

- Python engines/evaluators are isolated with `uv tool install`:
  - `garak==0.17.0`
  - `powerpwn==6.0.0` (Python 3.11)
  - `deepteam==1.0.9` (with `sentry-sdk`, required for `--help`)
  - `inspect-ai==0.3.263`
  - `deepeval==4.2.2`
- Promptfoo is installed locally (default: `~/.urt-tools/promptfoo`, package `promptfoo@0.123.0`) and exposed as `promptfoo`
- Copilot Studio SDK: `uv sync --extra mcs` (pins `microsoft-agents-copilotstudio-client==1.5.0` from PyPI)
- Power CAT has no public npm CLI. Canonical source is the Copilot Studio Kit:
  - https://github.com/microsoft/Power-CAT-Copilot-Studio-Kit (Power Platform solution + `agent-review-pipeline` GitHub Action)
  - If your org ships a local `copilot-studio-kit` launcher, point `engines.powercat.params.command` at it
  - Do not invent an npm name and do not treat `powerplatform-review-tool` as Power CAT
- Giskard v3 is invoked with `uvx` (`giskard[scan]==3.0.0`) because the meta-package does not expose a standalone `giskard` binary.

This avoids dependency conflicts across engines (especially `pydantic` version conflicts).
The Copilot Studio GA client is not in the base extra; install it with `uv sync --extra mcs`.

## Recommended Run Flow

1. Prepare a run spec. `templates/run_spec.sample.yaml` / `urt init --smoke` are launcher presence only.
   - For Copilot Studio SDK + native PyRIT, use `templates/run_spec.mcs_real.sample.yaml`.
   - For eval-after-attack (engine findings sidecar + `scripts/eval_engine_findings.py`), use `templates/run_spec.eval_after_attack.sample.yaml`.
   - For DeepTeam seeded fallback mode, use `templates/run_spec.deepteam_seeded.sample.yaml`.
   - For Promptfoo dataset-mode (preset or custom JSONL/CSV), use `templates/run_spec.promptfoo_dataset.sample.yaml`.
2. Add target-specific credentials and safe test scope.
3. Run:

```bash
uv run urt run --spec /path/to/run_spec.yaml
```

4. Export report bundle:

```bash
uv run urt report --run-id <RUN_ID> --output-dir ./reports/<RUN_ID>
```

5. Apply gate:

```bash
uv run urt gate --run-id <RUN_ID> --threshold high
```

## DeepTeam Reliability Guardrails

When running DeepTeam in real attack mode, use these defaults to avoid silent `0 test` outputs:

- In URT engine params, keep `require_test_cases: true` (default).
- In DeepTeam YAML `system_config`, set `ignore_errors: false`.
- Prefer a dedicated simulator/evaluation model pair (do not force both through a strict target proxy).
- If simulator generation is blocked, use `examples/deepteam_seeded/deepteam_seed_attacks.sample.json` as deterministic seed prompts via `DEEPTEAM_SEED_DATASET`.
- To ingest external open-source datasets (`.json/.jsonl/.csv`), use `examples/deepteam_seeded/prepare_seed_dataset.py`.

## Evidence and Audit Artifacts

Each run persists under `.urt_state/artifacts/<RUN_ID>/`:

- `resolved_spec.json`
- `run_manifest.json`
- `engine_invocations.json`
- `artifacts_index.json`
- `findings.json`
- `scorecard.json`
- `report.md`, `report.html`, `report.csv`
- raw stdout/stderr per engine under `raw/<engine>/`

This is the baseline expected evidence pack for customer-facing assessments.

## Promptfoo Dataset Mode (Preset + Custom Files)

URT Promptfoo adapter supports both built-in starter datasets and consultant-provided prompt files with one parameter family:

- `prompt_source`:
  - preset string: `preset:copilot_security_starter`
  - preset short name: `harmbench`, `xstest`, `jailbreakbench`
  - file string: `/abs/path/prompts.jsonl`
  - object form:
    - `mode: preset | file`
    - `preset` or `path`
    - `field`, `limit`, `dedupe`

Supported custom formats: `.jsonl`, `.csv`, `.json`, `.txt`, `.md`.
Generated promptfoo config and dataset metadata are persisted under:
- `raw/promptfoo/<target>_generated_config.yaml`
- `raw/promptfoo/<target>_dataset_meta.json`

Preset catalog and source provenance:
- `docs/promptfoo-preset-catalog.md`
