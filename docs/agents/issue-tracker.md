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

## Wayfinding operations

Skills that say "fetch / publish / list tickets" use GitHub Issues on this repo, not Linear.

| Skill phrase | GitHub |
| ------------ | ------ |
| Fetch the relevant ticket | `gh issue view <N>` (include comments if the thread matters) |
| Publish to the issue tracker | `gh issue create --title "…" --body "…"` then `gh issue edit <N> --add-label ready-for-agent` |
| List AFK-ready work | `gh issue list --label ready-for-agent` |
| List items waiting on a human | `gh issue list --label ready-for-human` |
| List untriaged | `gh issue list --label needs-triage` |
| Apply a triage role | `gh issue edit <N> --add-label <role>` using the labels in `docs/agents/triage-labels.md` |
| Comment on a ticket | `gh issue comment <N> --body "…"` |
| Close after merge | `gh issue close <N>` (PRs close issues with `Closes #N`; PRs are not the request surface) |

Title prefix: use a program/step prefix (`RP-1: …`) so issues stay grabable without Linear ids.

Do not open Linear/`HAL-*` tickets for Redplane work.

## Pull requests as a triage surface

**PRs as a request surface: no.** Incoming work requests and agent-ready tickets
live in GitHub Issues. PRs are the merge / review surface.

## When a skill says "publish to the issue tracker"

Create a GitHub issue on this repo. Apply the `ready-for-agent` triage label
unless the skill instructs otherwise.

## When a skill says "fetch the relevant ticket"

`gh issue view <N>` (and comments if the thread matters).
