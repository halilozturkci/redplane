# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

**Redplane** — attack and evaluation control plane for AI agents (Microsoft Copilot Studio, Azure AI Foundry, generic HTTP endpoints). It is not an attack tool: it commands wrapped CLIs, then normalizes, scores, maps, gates, and audits. Product name is **Redplane**; CLI and import package remain `urt`.

## Build & Run

```bash
uv sync                              # install deps
uv sync --extra mcs                  # Copilot Studio GA client (SDK mode)
uv run urt --help                    # CLI entry point
uv run urt run --spec templates/run_spec.mcs_real.sample.yaml  # execute a real run spec
uv run urt run --spec templates/run_spec.smoke.yaml  # launcher presence only
uv run urt view <run_id>             # loopback-only viewer for one run directory
uv run urt serve-gateway --config templates/gateway_config.sample.yaml
```

## Tests

```bash
uv run pytest                        # full suite (unit-focused, no external services)
uv run pytest tests/test_models.py   # single file
uv run pytest -k "test_scorecard"    # by name pattern
```

Tests are in `tests/`. No external services needed — everything is unit-tested with mocks.

## Core Architecture

The platform has a **three-layer adapter pattern**: targets, engines, and evaluators — each with an abstract base, concrete implementations, and a factory in `adapters/__init__.py`.

**Execution flow** (`src/urt/orchestrator.py`):
```
RunSpec → Orchestrator.execute()
  → for each target:
      → healthcheck → start_session
      → for each engine:    → engine_adapter.run(EngineContext) → EngineRunResult
      → for each evaluator: → evaluator_adapter.evaluate(EvalContext) → EvalRunResult
      → end_session
  → normalize_findings → build_scorecard → render reports
```

`execute()` appends a stage event (`stage_events.json`) and rewrites `engine_invocations.json` after every step, so progress is observable while it runs. `POST /v1/runs` is async: `jobs.RunWorker` (one thread per `serve-api` process, in-memory FIFO, SQLite `runs.status` = `queued|running|completed|failed`) calls the **same** `execute(spec, run_id=...)` on the queued row — never a second execution path. `Orchestrator.recover_interrupted_runs()` (called by `create_app`) marks rows whose `worker_id` process is dead as `failed`; it never re-executes. `?wait=true` keeps the synchronous path; `urt run` is unchanged.

**Key modules** (all under `src/urt/`):
- `types.py` — All dataclasses: `RunSpec`, `TargetSpec`, `EngineSpec`, `EvaluatorSpec`, `UnifiedFinding`, `EvalScore`, etc.
- `runtime.py` — BudgetTracker, rate limiter, seed/scenario/evidence helpers (RunSpec contracts)
- `jobs.py` — `RunWorker` background thread for async `POST /v1/runs`, `worker_id` (`host:pid`) liveness helpers
- `constants.py` — `SUPPORTED_TARGETS`, `SUPPORTED_ENGINES`, `SUPPORTED_EVALUATORS`, `RUN_PROFILE_DEFAULTS`, `SEVERITY_ORDER`
- `adapters/__init__.py` — Factory functions: `create_target_adapter()`, `create_engine_adapter()`, `create_evaluator_adapter()` with lookup dicts
- `adapters/engine_base.py` — `EngineAdapter` ABC + `EngineContext` dataclass
- `adapters/evaluator_base.py` — `EvaluatorAdapter` ABC + `EvalContext` dataclass
- `adapters/engines/_command.py` — `CommandEngineAdapter` base for CLI-wrapped tools (most engines subclass this)
- `adapters/evaluators/_command.py` — `CommandEvaluatorAdapter` base for CLI-wrapped evaluators
- `normalization/` — `normalize_findings()` (category aliases → canonical key, framework mappings, `metadata.finding_kind` tag) + `build_scorecard()` (aggregation including eval_scores; ASR counts `attack`-kind findings only) + `kind.py` (`finding_kind()`, `ASR_KINDS`)
- `auth.py` — optional `URT_API_KEY` shared-secret gate for `serve-api` (bearer for `/v1`, `/ui/login` cookie session for pages; `hmac.compare_digest`; no users/roles)
- `specs.py` — spec builder backend: `capabilities()`, templates (`URT_TEMPLATES_DIR`), `validate_spec_payload()` (validate-only, `${VAR}`-only auth rule, redacted resolved spec, env var set/unset booleans), `probe_spec()` (shared with `urt probe`), form ↔ payload for `/ui/specs`
- `matrix.py` — `build_run_matrix()` → `RunMatrix` (targets × runs, per-target scorecard cells; `/v1/matrix`, `/ui/matrix`); `coverage_csv.py` — CSV export of the framework coverage matrix with formula-cell neutralisation (`/v1/runs/{id}/coverage.csv`)
- `diff.py` — cross-run identity key (`category + sub_category + target_id`), `diff_runs()` → `RunDiff`, `TrendPoint` (backs `urt diff`, `/v1/runs/{a}/diff/{b}`, `/v1/targets/{id}/trend`)
- `report.py` — `render_markdown()`, `render_csv()`, `gate_result()`/`GateResult`, `evaluate_gate()` (waiver-aware); `render_html()` is a thin shim over `ui/`
- `ui/` — viewer: `bundle.py` (`load_bundle()` → `RunBundle`: read-time redaction for pre-1.1 bundles, evidence paths, waiver matching, transcripts), `render.py` (Jinja2 templates, `render_run_page(mode="static"|"served")`, hash CSP), `view_server.py` (`urt view`), `templates/`, `static/`
- `artifact_policy.py` — inline-vs-attachment and header rules for serving bundle files (shared by the API and `urt view`)
- `storage/` — `ArtifactStore` (filesystem, writes to `.urt_state/artifacts/<run_id>/`) + `MetadataStore` (SQLite)
- `policy/mapping.py` — Maps findings to OWASP LLM / OWASP Agentic / MITRE ATLAS frameworks; `CATEGORY_ALIASES` / `canonical_category()` fold engine spellings (`hateunfairness`, `jailbreak`, `pii`, …) onto the map keys; `diff.finding_identity()` and `waivers.control_matches()` compare through it so pre-alias bundles and waivers stay comparable
- `policy/waivers.py` — Active waiver matching used by `urt gate`; `preview_matches()` backs the waiver preview (never reimplement `control_matches()` client-side)
- `ui/csrf.py`, `ui/forms.py` — double-submit CSRF and stdlib urlencoded form parsing for the `/ui` waiver forms (the only UI mutation)

**Adapter registries (in `constants.py`):**
- Targets: `http`, `copilot`, `foundry`
- Engines: `pyrit`, `promptfoo`, `garak`, `powerpwn`, `powercat`, `deepteam`, `inspect`, `giskard`
- Evaluators: `deepeval`, `promptfoo_eval`, `giskard_eval`, `inspect_eval`, `azure_ai_eval`, `custom_script`

Adding a new engine/evaluator: create the adapter file, add to `constants.SUPPORTED_*`, add to `adapters/__init__.py` registry dict, add to `adapters/engines/__init__.py` or `adapters/evaluators/__init__.py`.

### Network gateway (`src/urt/gateway/`)

An OpenAI-compatible proxy (`stdlib ThreadingHTTPServer`, not FastAPI) that routes `/v1/chat/completions` to heterogeneous backends (Copilot Studio, Azure OpenAI, Foundry, generic HTTP). Routing modes: header (`X-URT-Target`), model prefix (`urt/<target>`), or path. Optional `gateway.api_key`; Foundry `thread_id` can persist via `session_persist_path`. `GET /v1/sessions` lists session ids + presence flags (no content). SSE is a single-chunk shim. Control-plane API (`urt serve-api`) is FastAPI.

Traces: one redacted JSON per request under `audit.artifact_root/YYYYMMDD/`; `X-URT-Run-Id` (engines get `URT_RUN_ID` in their env) tags the trace with the run. `gateway/traces.py` (`TraceIndex`) is the **read-only** index the orchestrator uses to record `trace_ids` / `gateway_traces` in `run_manifest.json` and that `/v1/traces…` + `/ui/traces` browse (root: `URT_GATEWAY_TRACE_ROOT` / `--gateway-trace-root`). `gateway_client.py` fetches `/v1/sessions` from `URT_GATEWAY_URL` for `/v1/gateway/sessions`.

### CLI Commands

`urt init`, `urt validate`, `urt probe`, `urt run`, `urt report` (`--in-place` re-renders the bundle's own reports), `urt gate` (`--explain`, `--eval-min-pass-rate`), `urt waivers` (`list`, `create`, `revoke` — append-only, no delete), `urt runs`, `urt diff <a> <b>`, `urt findings`, `urt artifacts`, `urt view`, `urt serve-api`, `urt serve-gateway`

### Runtime contracts (do not re-treat as schema-only)

Enforced: duration budget, reported-cost budget, HTTP connect/request timeouts, evidence_level log caps, seed env, Promptfoo `enabled_scenarios`, HTTP `rate_limits`, evaluator `fail_open`, profile timeout/budget defaults, waiver-aware gate, spec `${VAR}` expand.

Not claimed / next-work surface: true token streaming, Copilot SDK session serialize, invented USD cost, native Garak/PyRIT scenario flags, a distributed job queue (async runs are one thread + SQLite; interrupted runs are failed, not resumed), multi-tenant RBAC.

## Gitignore / Excluded Paths

The `.gitignore` excludes these generated/cached paths — do not commit them:
- `.venv/` — virtual environments (recreated via `uv sync`)
- `.scan_*/` — URT scan result directories (runtime output)
- `.urt_state/` — URT artifact store and SQLite metadata (runtime output)
- `.pytest_cache/`, `.mypy_cache/`, `.ruff_cache/`, `.deepeval/` — tool caches
- `__pycache__/`, `*.pyc`, `*.pyo` — Python bytecode
- `.token_cache.json`, `.token_cache_dataverse.json`, `token_cache.bin`, `.env` — credentials/secrets
- `*:Zone.Identifier` — Windows NTFS alternate data stream markers
- `.DS_Store` — macOS Finder metadata

`uv.lock` **is committed**. Regenerate it with `uv lock` after `pyproject.toml` changes; CI runs `uv lock --check` then `uv sync --extra dev --frozen`.

## Key Conventions

- **Python >= 3.11** required. Uses `uv` as package manager (not pip/poetry).
- Promptfoo is pinned to `0.123.0` and requires **Node.js >= 22.22.0**.
- Runtime pins `openai>=3,<4` and `pyrit>=1.1,<2`. `azure-ai-evaluation` is installed **without** the `[redteam]` extra (that extra hard-pins pyrit 0.11).
- Source layout: `src/urt/` with `pyproject.toml` at repo root.
- All dataclasses use `slots=True` and `from_dict()`/`to_dict()` pattern.
- Engines/evaluators wrap external CLI tools via subprocess — they never import the tool's Python package directly.
- `fail_open: true` (default) means adapter errors don't fail the run; `false` makes them fatal.
- Artifacts are written to `.urt_state/artifacts/<run_id>/` with a standard audit bundle (see `AUDIT_BUNDLE_FILES` in constants).
- Environment variables in YAML configs are expanded via `os.path.expandvars()` — use `${VAR_NAME}` syntax.

## Agent skills

Project skills live in `.agents/skills/` (Cursor/Claude resolve the same tree via
`.cursor/skills` and `.claude/skills`). Inventory: `docs/agents/imported-skills.md`.
Read a skill's `SKILL.md` before using it.

### Issue tracker

Tickets and specs live in GitHub Issues on this repo. See
`docs/agents/issue-tracker.md`.

### Triage labels

Canonical role strings map 1:1 onto GitHub labels. See
`docs/agents/triage-labels.md`.

### Domain docs

Single-context: `CLAUDE.md` / `AGENTS.md`, optional root `CONTEXT.md` +
`docs/adr/`. See `docs/agents/domain.md`.
