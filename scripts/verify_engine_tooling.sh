#!/usr/bin/env bash
set -euo pipefail

MISSING=0
for cmd in uv npx garak powerpwn deepteam inspect; do
  if command -v "${cmd}" >/dev/null 2>&1; then
    echo "OK: ${cmd}"
  else
    echo "MISSING: ${cmd}"
    MISSING=1
  fi
done

if ! uv run python -c "import microsoft_agents.copilotstudio.client" >/dev/null 2>&1; then
  echo "MISSING: microsoft_agents.copilotstudio.client (run: uv sync --extra mcs)"
  MISSING=1
fi

if [[ "${MISSING}" -ne 0 ]]; then
  echo "One or more required commands are missing."
  exit 1
fi

PROMPTFOO_BIN_DEFAULT="${HOME}/.urt-tools/promptfoo/node_modules/.bin/promptfoo"
PROMPTFOO_BIN="${PROMPTFOO_BIN:-}"
if [[ -n "${PROMPTFOO_BIN}" ]]; then
  :
elif command -v promptfoo >/dev/null 2>&1; then
  PROMPTFOO_BIN="$(command -v promptfoo)"
elif [[ -x "${PROMPTFOO_BIN_DEFAULT}" ]]; then
  PROMPTFOO_BIN="${PROMPTFOO_BIN_DEFAULT}"
else
  echo "MISSING: promptfoo (run scripts/install_promptfoo_local.sh)"
  exit 1
fi
echo "OK: promptfoo (${PROMPTFOO_BIN})"

echo "Checking URT entrypoint"
uv run urt --help >/dev/null

echo "Running engine smoke commands"
# uv tool pins must match src/urt/engine_pins.py:
# garak==0.17.0 powerpwn==6.0.0 deepteam==1.0.9 inspect-ai==0.3.263
garak --version >/dev/null
powerpwn --help >/dev/null
deepteam --help >/dev/null
inspect --help >/dev/null
uvx --python 3.12 --from giskard==2.19.2 python -c "import giskard; print(giskard.__version__)" >/dev/null
"${PROMPTFOO_BIN}" --version >/dev/null

POWERCAT_KIT="https://github.com/microsoft/Power-CAT-Copilot-Studio-Kit"
if command -v copilot-studio-kit >/dev/null 2>&1; then
  echo "Power CAT CLI check: OK (copilot-studio-kit)"
elif command -v pac >/dev/null 2>&1 && pac help >/dev/null 2>&1; then
  echo "Power CAT check: WARN (no copilot-studio-kit; pac is a tertiary Power Platform CLI, not the Kit). Canonical: ${POWERCAT_KIT}"
else
  echo "Power CAT check: WARN (no public npm CLI; Kit is a Power Platform solution + GitHub Action at ${POWERCAT_KIT})"
fi

if ! uv run python -c "import microsoft_agents.copilotstudio.client" >/dev/null 2>&1; then
  echo "MISSING: microsoft_agents.copilotstudio.client (run: uv sync --extra mcs)"
  exit 1
fi
echo "OK: microsoft_agents.copilotstudio.client"

echo "All engine launchers are operational."
