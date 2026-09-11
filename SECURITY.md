# Security Policy

Redplane is an open-source attack-and-evaluation control plane. Treat credentials, token caches, and target endpoints as secrets.

## Reporting a vulnerability

Please report security issues privately via GitHub Security Advisories on this repository. Do not file a public issue for leaked credentials, live tokens, or exploitable bugs.

## Secrets that must never be committed

- `.env` and copies of `templates/.env.mcs.template` with real values
- MSAL / Copilot Studio token caches (`token_cache.bin`, `TOKEN_CACHE_PATH`)
- Azure / Entra client secrets, API keys, and gateway `api_key` values

The Copilot Studio client writes its cache to `~/.urt_state/msal_token_cache.bin` by default (override with `TOKEN_CACHE_PATH`). That path is gitignored.

If a token cache or secret was ever committed to git history, revoke the Entra refresh tokens, rotate the app registration credentials, and publish a rewritten history that does not contain the blob.
