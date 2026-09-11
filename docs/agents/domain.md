# Domain Docs

How the engineering skills should consume Redplane domain documentation.

## Before exploring, read these

- **`CLAUDE.md`** and **`AGENTS.md`** at the repo root (product + contributor
  contracts)
- **`CONTEXT.md`** at the repo root, if it exists
- **`docs/adr/`** — ADRs that touch the area you are about to change

If `CONTEXT.md` or `docs/adr/` do not exist, **proceed silently**. The
`/domain-modeling` skill creates them lazily when terms or decisions actually
get resolved.

## File structure

This repo is **single-context**:

```
/
├── CLAUDE.md
├── AGENTS.md
├── CONTEXT.md          # optional; created by /domain-modeling
└── docs/adr/           # optional
```

## Vocabulary

Prefer the terms already used in `CLAUDE.md` / `AGENTS.md` (RunSpec, target,
engine, evaluator, gateway, UnifiedFinding, scorecard, gate). Do not invent
synonyms for those concepts.
