# Redplane — Repository Guidelines

## Project Structure & Module Organization
- Core code lives in `src/urt/` with a `src` layout. Product name is **Redplane**; CLI/import remain `urt`.
- Key modules:
  - `cli.py`, `orchestrator.py`, `types.py`, `constants.py`, `runtime.py`
  - `gateway/` for the OpenAI-compatible gateway server and routing
  - `normalization/`, `policy/` (including waivers), `storage/` for findings mapping and persistence
- Tests are in `tests/` (unit-focused, no external services required).
- Operational scripts are in `scripts/` (`bootstrap_uv.sh`, tooling installers, gateway launcher).
- Specs and examples live in `templates/`, `examples/`, and supporting docs in `docs/`.

## Build, Test, and Development Commands
- `./scripts/bootstrap_uv.sh` — full local bootstrap (deps, engine tools, promptfoo, checks).
- `uv sync` — install/update Python dependencies into the project environment.
- `uv run urt --help` — verify CLI wiring and available subcommands.
- `uv run urt validate --spec templates/run_spec.sample.yaml` — validate a run spec.
- `uv run urt run --spec templates/run_spec.sample.yaml` — execute a red-team run.
- `uv run urt serve-gateway --config templates/gateway_config.sample.yaml` — start gateway.
- `uv run pytest` — run the full test suite.
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
