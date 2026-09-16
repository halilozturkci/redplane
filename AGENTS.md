# Redplane — Repository Guidelines

## Project Structure & Module Organization
- Core code lives in `src/urt/` with a `src` layout. Product name is **Redplane**; CLI/import remain `urt`.
- Key modules:
  - `cli.py`, `orchestrator.py`, `types.py`, `constants.py`, `runtime.py`
 - `gateway/` for the OpenAI-compatible gateway server and routing
 - `ui/` for the bundle reader, Jinja2 templates, the self-contained `report.html` viewer and the `urt view` server
 - `normalization/`, `policy/` (including waivers), `storage/` for findings mapping and persistence
- Tests are in `tests/` (unit-focused, no external services required).
- Operational scripts are in `scripts/` (`bootstrap_uv.sh`, tooling installers, gateway launcher).
- Specs and examples live in `templates/`, `examples/`, and supporting docs in `docs/`.
- `uv.lock` is committed. Promptfoo is `promptfoo@0.123.0` and requires Node.js `>= 22.22.0` (`scripts/toolchain_pins.env`).

## Build, Test, and Development Commands
- `./scripts/bootstrap_uv.sh` — full local bootstrap (deps, engine tools, promptfoo, checks).
- `uv sync` — install/update Python dependencies into the project environment.
- `uv sync --extra mcs` — add the Copilot Studio GA client (`microsoft-agents-copilotstudio-client==1.5.0`). Full bootstrap already passes this extra.
- `uv run urt --help` — verify CLI wiring and available subcommands.
- `uv run urt validate --spec templates/run_spec.smoke.yaml` — validate the smoke run spec
- `uv run urt validate --spec templates/run_spec.mcs_real.sample.yaml` — validate a real MCS spec
- `uv run urt run --spec templates/run_spec.mcs_real.sample.yaml` — execute a real red-team run
- `uv run urt view <run_id>` — serve one run directory (viewer + bundle files) on loopback.
- `uv run urt serve-gateway --config templates/gateway_config.sample.yaml` — start gateway.
- `uv run pytest` — run the full test suite.
- CI on pull requests and `main`: Node floor check, `uv lock --check`, `uv sync --extra dev --frozen`, pytest, `uv run urt --help`.
- `uv run pytest tests/test_models.py -k runspec` — run focused tests during iteration.

## Coding Style & Naming Conventions
- Target Python `>=3.11`; follow PEP 8 with 4-space indentation.
- Prefer explicit type hints and small, composable functions.
- Naming:
  - modules/functions/variables: `snake_case`
  - classes/dataclasses: `PascalCase`
  - constants: `UPPER_SNAKE_CASE`
- Keep adapter implementations aligned with the existing target/engine/evaluator pattern in `src/urt/adapters/`.

## Testing Guidelines
- Framework: `pytest` (configured in `pyproject.toml` with `testpaths = ["tests"]`).
- Test files: `tests/test_*.py`; test functions: `test_*`.
- Add or update tests for every behavior change, especially parser, gateway routing, and normalization logic.
- Run targeted tests first, then `uv run pytest` before opening a PR.

## Commit & Pull Request Guidelines
- Commit style in history is short, imperative, and often colon-scoped (e.g., `Restructure repo: ...`, `Add ...`).
- Keep commits focused by concern (feature, fix, refactor, docs).
- PRs should include:
  - clear summary and rationale
  - linked issue/task (if available)
  - test evidence (`uv run pytest` output or targeted test commands)
  - sample artifact/report paths when output formats or run behavior change

## Security & Configuration Tips
- Never commit secrets or local runtime state (`.env`, token caches, `.urt_state/`, tool caches).
- Use environment variables in specs (`${VAR_NAME}`) for credentials and endpoints.

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
