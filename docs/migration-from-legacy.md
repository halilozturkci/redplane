# Migration From Legacy Layout

This document maps the previous two-directory setup into this Redplane repository (CLI/package: `urt`).

## Legacy Sources (unchanged)

- `red-team/universal-red-team-platform`
- `red-team/red-teaming-copilot-studio-agent-modular`

Both legacy directories remain in place for backward compatibility and reference if you still have the old tree.

## New Unified Location

- this repository root (`src/urt/`)

## File Mapping

- Legacy `red_team_scan.py` now lives at:
  - `src/urt/integrations/mcs_pyrit/red_team_scan.py`
- Legacy `targets/mcs_agent_callback.py` now lives at:
  - `src/urt/integrations/mcs_pyrit/targets/mcs_agent_callback.py`
- Legacy `src/CopilotStudioClient.py` now lives at:
  - `src/urt/integrations/mcs_pyrit/copilot_client.py`
- Legacy scan config now lives at:
  - `src/urt/integrations/mcs_pyrit/config/mcs_agent_callback.json`

## Runtime State and Audit Outputs

URT now writes local runtime state under:

- `.urt_state/artifacts/<RUN_ID>/`
- `.urt_state/metadata/urt.sqlite3`
- `.urt_state/logs/`

Canonical audit bundle files are unchanged (`resolved_spec.json`, `run_manifest.json`, `engine_invocations.json`, `artifacts_index.json`, `findings.json`, `scorecard.json`, `run_summary.json`, and report outputs).

## Updated Defaults

- PyRIT default script path:
  - `src/urt/integrations/mcs_pyrit/red_team_scan.py`
- PyRIT default config path:
  - `src/urt/integrations/mcs_pyrit/config/mcs_agent_callback.json`
- Copilot SDK default path:
  - `src/urt/integrations/mcs_pyrit/copilot_client.py`

