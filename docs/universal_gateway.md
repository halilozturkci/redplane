# Redplane network gateway — technical design

## Objective

Provide a single OpenAI-compatible entrypoint (`/v1/chat/completions`) that can route red-team traffic to multiple backend agent platforms while preserving a unified audit format for all engines.

## Scope

- Single gateway endpoint for Promptfoo and other OpenAI-compatible attack tools.
- Multi-backend routing with 6 connectors:
  - `copilot_studio_sdk`
  - `foundry_model_inference`
  - `foundry_agent_service`
- `azure_openai_deployment`
- `openai_compatible_http`
- `generic_http_json`
- Per-request audit artifacts with redaction.

## Non-Goals

- Centralized secrets manager (future phase).
- Multi-tenant RBAC (future phase). Optional shared-secret `gateway.api_key` is supported; it is not tenant RBAC.
- True token streaming from backends (SSE remains a single-chunk compatibility shim).
- Persisting live Copilot SDK client objects across process restart (Foundry `thread_id` can persist).
- Long-term artifact storage backends (future phase).

## High-Level Architecture

1. `Gateway HTTP Server`
   - Exposes `/healthz` and `/v1/chat/completions`.
   - Normalizes OpenAI request/response format.

2. `Router`
   - Resolves target from one of:
     - Header mode: `X-URT-Target`
     - Model mode: `model: urt/<target_id>`
     - Path mode: `/v1/chat/completions/<target_id>`
   - Falls back to `routing.default_target` or single-target config.

3. `Connector Layer`
   - One connector implementation per backend platform.
   - Converts canonical chat request to provider-specific API calls.
   - Returns normalized `ChatResult`.

4. `Audit Store`
   - Writes per-request trace JSON under `.urt_state/gateway/YYYYMMDD`.
   - Applies header/body redaction and payload truncation.

## File Layout

- `src/urt/gateway/app.py`: HTTP app + request lifecycle + audit writing.
- `src/urt/gateway/config.py`: schema + loader for gateway config.
- `src/urt/gateway/router.py`: route resolution model.
- `src/urt/gateway/contracts.py`: shared request/response/error contracts.
- `src/urt/gateway/redaction.py`: secret masking helpers.
- `src/urt/gateway/audit.py`: trace artifact writer.
- `src/urt/gateway/connectors/*`: backend connector implementations.
- `scripts/urt_gateway.py`: standalone launcher.
- `templates/gateway_config.sample.yaml`: 6-backend config example.
- `templates/run_spec.promptfoo_gateway.sample.yaml`: URT run example via gateway.

## Configuration Model

Top-level sections:

- `gateway`:
  - `host`, `port`, `request_timeout_seconds`, `log_level`, `session_ttl_seconds`
  - `api_key` (optional shared secret for `/v1/chat/completions`; `/healthz` stays open)
  - `session_persist_path` (optional JSON file for Foundry thread ids)
- `routing`:
  - `mode`: `header|model|path`
  - `header_name`
  - `model_prefix`
  - `default_target`
  - `path_prefix`
- `audit`:
  - `artifact_root`
  - `capture_bodies`
  - `max_body_bytes`
  - `redact_headers`
- `targets`:
  - map of `<target_id>` -> connector + endpoint + auth + config

Env vars inside YAML are expanded via `${VAR}` syntax.

## Request Lifecycle

1. Parse JSON request and validate `messages`.
2. Resolve target using router.
3. Instantiate connector for resolved target.
4. Execute connector call.
5. Normalize backend response into OpenAI chat completion schema.
6. Write trace artifact (`trace_id`, target, latency, request, response, errors).
7. Return JSON response to client.

## Error Model

- Routing errors -> HTTP 404 (`routing_error`).
- Validation errors -> HTTP 400 (`invalid_request`).
- Connector HTTP failures -> mapped status (`http_error`).
- Connector runtime failures -> HTTP 502 (`request_failed`).
- Gateway internal errors -> HTTP 500 (`gateway_internal_error`).

## Audit Model

Each request produces one trace artifact containing:

- `trace_id`, timestamp, route source, target id, connector name.
- `run_id` when the caller sent `X-URT-Run-Id` (or `context.run_id`). Redplane puts
  `URT_RUN_ID` in every engine's environment; a tool that forwards it as that header
  (the shipped `templates/promptfoo_eval.template.yaml` does) gets its traces linked to
  the run exactly. Untagged traces are linked only by the run's time window.
- Request path/headers/body (redacted and optionally truncated).
- Response body + status.
- Error payload when present.

Redaction applies to standard sensitive keys and configured header list. The
`metadata.audit_path` returned to the client is **relative to `audit.artifact_root`**
(`YYYYMMDD/trace-….json`), never the server's filesystem layout.

The control plane reads this tree read-only: `Orchestrator` records the linked
`trace_ids` (and how each matched) in `run_manifest.json` at the end of a run;
`urt serve-api` browses it under `GET /v1/traces…` and `/ui/traces` with the gateway
down. Point `URT_GATEWAY_TRACE_ROOT` / `--gateway-trace-root` at `audit.artifact_root`
when it is not the default `.urt_state/gateway`.

## Sessions endpoint

`GET /v1/sessions` (same `gateway.api_key` gate as chat completions) lists the live
and persisted sessions: `session_id`, `source` (`live` | `persisted`), `last_used_utc`,
`idle_seconds`, `thread_id_present`, `live_client_present`. Never the Foundry
`thread_id` value, the Copilot client or any message content. `urt serve-api` proxies
it as `GET /v1/gateway/sessions` when `URT_GATEWAY_URL` (+ `URT_GATEWAY_API_KEY`) is set.

## Implementation Phases

1. Core + Router + Audit + `copilot_studio_sdk`.
2. HTTP-family connectors:
   - `openai_compatible_http`
   - `generic_http_json`
3. Azure connectors:
   - `foundry_model_inference`
   - `azure_openai_deployment`
4. Stateful connector:
   - `foundry_agent_service` (threads/runs/messages flow)
5. CLI + templates + docs + backward compatibility wrapper.
6. Full automated test suite and smoke verification.

## Validation Checklist

- `uv run urt serve-gateway --config templates/gateway_config.sample.yaml --print-effective-config`
- `curl http://127.0.0.1:18080/healthz`
- Promptfoo one-shot through gateway:
  - `uv run urt run --spec templates/run_spec.promptfoo_gateway.sample.yaml`
- `uv run python -m pytest -q`
