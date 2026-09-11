# Imported skill inventory

Copied from `halilozturkci/cyberroundtable.ai` `.agents/skills/` (47 skills, 94
files) plus `skills-lock.json`.

Layout:

- Canonical: `.agents/skills/<name>/SKILL.md`
- Cursor: `.cursor/skills` → `.agents/skills`
- Claude Code: `.claude/skills` → `.agents/skills`

## Matt Pocock pack (`skills-lock.json`)

ask-matt, caveman, code-review, codebase-design, diagnose, diagnosing-bugs,
domain-modeling, grill-me, grill-with-docs, grilling, handoff, implement,
improve-codebase-architecture, prototype, research, resolving-merge-conflicts,
setup-matt-pocock-skills, tdd, teach, to-issues, to-prd, to-spec, to-tickets,
triage, wayfinder, write-a-skill, writing-great-skills, zoom-out

## Additional repo skills (not in the lockfile)

claude-agentic-coding-best-practices, cursor-agentic-coding-best-practices,
design-an-interface, edit-article, git-guardrails-claude-code,
hardened-slice-workflow, migrate-to-shoehorn, obsidian-vault, qa, review,
request-refactor-plan, scaffold-exercises, setup-pre-commit,
thermo-nuclear-code-quality-review, tracer-bullet-slice-workflow, ubiquitous-language,
writing-beats, writing-fragments, writing-shape

Some workflow skills still mention Linear/`HAL-*` from the source repo. In
Redplane, follow `docs/agents/issue-tracker.md` (GitHub Issues) unless the user
explicitly names a Linear ticket.
