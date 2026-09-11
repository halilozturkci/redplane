# Issue tracker: GitHub

Tickets, specs, and triage for **this** repository live in **GitHub Issues** on
`halilozturkci/redplane`. Use the `gh` CLI (or the GitHub MCP) for create / read
/ update / comment / label operations.

This file is the Redplane wiring for the imported engineering skills. It is not
the Cyber Roundtable Linear board. Skills that still mention Linear/`HAL-*`
inside their own `SKILL.md` should follow **this** file when working in Redplane.

## Workspace

- **Remote:** `https://github.com/halilozturkci/redplane`
- **Issues:** `gh issue list` / `gh issue view` / `gh issue create`
- **PRs:** code-review surface only (`gh pr …`)

## Conventions

- **Create an issue:** `gh issue create --title "…" --body "…"` with labels as
  needed.
- **Read an issue:** `gh issue view <N>`
- **List issues:** `gh issue list --label ready-for-agent` (or other filters)
- **Comment:** `gh issue comment <N> --body "…"`
- **Labels:** `gh issue edit <N> --add-label …` / `--remove-label …`
- **Close:** `gh issue close <N>`

## Pull requests as a triage surface

**PRs as a request surface: no.** Incoming work requests and agent-ready tickets
live in GitHub Issues. PRs are the merge / review surface.

## When a skill says "publish to the issue tracker"

Create a GitHub issue on this repo. Apply the `ready-for-agent` triage label
unless the skill instructs otherwise.

## When a skill says "fetch the relevant ticket"

`gh issue view <N>` (and comments if the thread matters).
