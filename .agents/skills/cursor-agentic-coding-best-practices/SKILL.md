---
name: cursor-agentic-coding-best-practices
description: >-
  Cursor agentic coding best practices for one Linear implementation ticket:
  claim In Progress, worktree or local branch, implement, full suite/Simulator,
  code-review, Bugbot, thermo-nuclear-code-quality-review, Codex CLI review,
  one PR, then the Linear evidence package and worktree removal. Use when
  implementing a CDCM/HAL/COST/GDE ticket, taking the next implementation
  ticket, running the tracer-bullet loop, or invoking
  /cursor-agentic-coding-best-practices.
disable-model-invocation: true
---

# Cursor Agentic Coding Best Practices

One **implementation** ticket → one branch → one PR. Quality bar matches this
repo's slice discipline (Linear claim, worktree, full gates, review loop,
board update).

This skill is a **repo skill**: it lives under `.agents/skills/` and ships with
the git tree. After clone/pull on any machine, agents can invoke it the same
way as sibling skills (`tdd`, `prototype`, `grilling`, `code-review`, …).

The Claude Code twin is `claude-agentic-coding-best-practices`. Shared
discipline lives in both; harness-specific review binaries stay here
(Bugbot, Cursor-native tools). Do not copy Claude's "call the Cursor CLI as
a third reviewer" pass into this skill — you are already that reviewer.

Canonical order board: **HAL-468** (`CDCM-0: Implementation order board`).
If that ticket is missing, recreate it under the program parent before coding.
Program-specific order maps (example: COST on [HAL-531](https://linear.app/halilozturkci/issue/HAL-531)
→ Implementation order) override HAL-468 row-picking when the user names that
program.

## Non-negotiables

- Never implement two tickets in one PR.
- Never start a ticket whose Linear `blockedBy` edges are still open.
- Never commit/push on `main` / `production`. Prefer a dedicated worktree.
- Do not mark the ticket **Done** at PR open — set **In Review**, attach PR,
  update HAL-468. **Done** only after merge + post-merge cleanup.
- Secrets, Apple keys, API tokens: never paste into Linear, commits, or PRs.
- **A reviewer that can write is not a reviewer, it is a second author.**
  Bugbot, `/code-review`, thermo, and Codex are read-only review passes.
  Fix findings yourself in this session; do not hand the branch to a reviewer
  that can edit.
- After the PR is open and the Codex CLI review cycle for that PR is finished
  (ran via CLI, findings read, fixed or recorded), **remove the session
  worktree** so the primary checkout stays lean. The remote branch stays for
  the PR; branch deletion is post-merge only.
- Every open PR must leave a complete **Evidence package** on Linear (implementation
  ticket + HAL-468): related tickets, PR URL, branch, commit SHAs, files touched,
  reviews, worktree status. Chat alone is not the record.

## Workflow checklist

Copy and track:

```
Cursor agentic coding:
- [ ] 1. Resolve order board + pick ticket
- [ ] 2. Claim on Linear (In Progress, assignee me)
- [ ] 3. Branch / worktree
- [ ] 4. Implement against ticket AC
- [ ] 5. Verify (full suite + Simulator when UI/native)
- [ ] 6. /code-review (Standards vs Spec) → fix clear findings
- [ ] 7. Bugbot review → fix clear findings
- [ ] 8. thermo-nuclear-code-quality-review → fix clear findings
- [ ] 9. Codex CLI review (ticket-aware) → fix or record
- [ ] 10. Commit + push + open PR
- [ ] 11. Linear Evidence package (ticket + HAL-468) with PR/commits/related
- [ ] 12. Remove session worktree (PR open + Codex cycle done)
```

### 1. Resolve order board + pick ticket

1. `get_issue` **HAL-468** (includeRelations if useful).
2. If the user named a ticket (`HAL-463`, `CDCM-F01`, `COST-4`, …), use that only if
   blockers are clear.
3. Else pick the first board row that is **Next/Queued**, unblocked, and not
   already In Progress by another session. For a named program, prefer that
   program's Implementation order section when one exists (COST: HAL-531).
4. `get_issue <id> includeRelations=true`. Refuse to start if any `blockedBy`
   issue is not `Done`.
5. Ops exception: **HAL-462 O01** may run in parallel with engineering and does
   not block F01.

### 2. Claim on Linear

Before editing code:

```
save_issue:
  id: HAL-XXX
  state: In Progress
  assignee: me
```

Comment once: claimed for implementation; branch name you will use.

Update HAL-468 status cell for that row to `In Progress`. For a named program
board (COST on HAL-531), also log the claim there.

### 3. Branch / worktree

**Where worktrees live depends on the machine, and the difference is not
cosmetic:**

| Machine | Location | Why |
| --- | --- | --- |
| Server (`/var/www/cyberroundtable.ai`) | `/mnt/data/crt-worktrees/<topic>` | `/` is 48 GB and has hit 97%; `/mnt/data` is a separate 100 GB volume. The primary checkout must stay on `main` because the deploy runner, the DR-panel worker and the cron jobs `cd` into it and execute whatever branch is checked out. |
| Local Mac checkout | `.claude/worktrees/<topic>` | `.claude/` is gitignored, so worktrees never pollute `git status`. Nothing executes the primary checkout automatically here. |
| Cursor Cloud Agent VM | Local branch in that checkout | The VM is already an isolated checkout. A nested worktree is optional, not required. |

```bash
git fetch origin main
git worktree add <worktree-path> -b cursor/hal-XXX-short-slug origin/main
ln -sfn "$(git rev-parse --show-toplevel)/node_modules"             <worktree-path>/node_modules
ln -sfn "$(git rev-parse --show-toplevel)/apps/engine/node_modules" <worktree-path>/apps/engine/node_modules
```

Both symlinks are required — the engine is its own npm project, and without its
link the engine typecheck fails with phantom module errors that look like code
faults but are environmental.

- **Never `npm ci` inside a worktree.** It deletes and repopulates the shared
  trees out from under running engine workers.
- **Symlink, never bind-mount.** `git worktree remove` walks a bind mount and
  deletes *through* it into the real `node_modules`. A symlink is immune. If you
  inherit a worktree with bind mounts (`findmnt | grep node_modules`), unmount
  before removing anything.
- Build with `npm run build` (the repo pins `--webpack`); a bare `next build`
  selects Turbopack, which panics on the symlinked tree.

**Local branch OK** when already inside a dedicated worktree for this ticket,
the environment cannot add worktrees, or this is a Cloud Agent checkout —
still leave `main` clean:

```bash
git fetch origin main
git checkout -b cursor/hal-XXX-short-slug origin/main
```

Branch naming: `cursor/hal-<n>-<short-slug>` (match ticket intent). Cloud Agent
runs that must follow the environment branch template still use the
`cursor/<descriptive-name>-<run-suffix>` form the harness requires.

### 4. Implement

- Treat the Linear description as the spec (Outcome, AC, Boundaries, Dependencies).
- Follow CLAUDE.md / AGENTS.md: design system for UI, migration rules for SQL,
  commit message convention (program prefix or `fix:` / `docs:` —
  one ticket per commit/PR).
- Any task where "how should it look / read / behave" is open must go through
  `/prototype` **before** production UI. Mechanical edits do not.
- Do not smuggle out-of-scope work into a foundation or tracer slice.
- Use `/tdd` at real seams when the ticket has testable contracts.
- Run `npm run check:precommit` as you go when web/server code is touched.

### 5. Verify

**The full suite is two systems.** `npm test` runs the node test-runner
(`tests/*.test.mjs` source-contract assertions) *and* vitest. Running only
vitest gives a false green — refactors routinely break the markup assertions in
the node suite.

```bash
npm test                 # both systems
npm run check:precommit  # lint + typecheck + engine typecheck + migration safety + secret scan
```

When the change touches `apps/ios` or native UX, also run:

```bash
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
xcodebuild -project apps/ios/CyberRoundtable.xcodeproj \
  -scheme CyberRoundtable \
  -destination 'platform=iOS Simulator,id=<booted-udid>' \
  -derivedDataPath .build/DerivedData \
  CODE_SIGNING_ALLOWED=NO test
```

Install + launch on a booted Simulator and smoke the ticket's visible path
(screenshot if UI). Click-drag to scroll (trackpad wheel may miss ZStack tabs).
Do not ask the human to check what you can verify headlessly, and never claim a
Simulator pass you did not run.

Server-only tickets: contract/unit tests + no false Simulator claim.

### 6. `/code-review` — Standards vs Spec

Run the repo `code-review` skill on the branch diff since `origin/main` (or the
merge-base). It launches two parallel sub-agents:

- **Standards** — does the code follow this repo's documented standards?
- **Spec** — does the code do what the originating ticket asked for?

Fix clear, in-scope findings. Do not expand scope to polish.

### 7. Bugbot

Read and follow `~/.cursor/skills-cursor/review-bugbot/SKILL.md`.

- Launch exactly one `bugbot` subagent (`Diff: branch changes` unless told otherwise).
- Fix clear, valid findings that are in scope. Do not expand scope to polish.

### 8. thermo-nuclear-code-quality-review

Read and follow the `thermo-nuclear-code-quality-review` skill (maintainability,
structure, file-size growth, spaghetti, abstractions, codebase health). It ships
in this repo at `.agents/skills/thermo-nuclear-code-quality-review/`. It is
deliberately harsh about abstraction quality and asks for *ambitious*
restructuring rather than local tidying.

- Run that skill on the branch diff (not the full `thermos` double-pass unless
  the user explicitly asks for security thermo-nuclear-review too).
- Fix clear medium/high findings in scope; record accepted residual risk in the
  PR if intentionally deferred.

### 9. Codex CLI review (before PR)

With all review fixes committed (or at least staged intent clear), run Codex
against the ticket via CLI — **background OK**. Prefer stdin prompt form when
the installed `codex review` rejects combining `--base` with an inline prompt:

```bash
codex review --base main
# or, when custom instructions are required and supported:
# printf '%s\n' 'Ticket: HAL-XXX — …' | codex review --base main -
```

If Codex demands `OPENAI_API_KEY`, check `command -v codex` and
`codex --version` before suspecting the login — a stale binary shadowing the
standalone one is the likelier cause. This repo's engine login is
`npm run codex-login -- --device-code` in `apps/engine` (device-code only when
the user explicitly asks; never log into a CLI on the user's behalf).

If `codex review` is unavailable, fall back to:

```bash
codex exec "Review git diff vs origin/main for HAL-XXX …"
```

**Read the Codex output**, incorporate high-signal suggestions (or explain skip
in the PR body), then continue. Do not open the PR until this read/fix-or-record
step is done unless the user explicitly waives Codex.

### 10. Commit + PR

- Commit with repo convention; body lists concrete changes + UI review flag if UI.
- Push branch; open **one** PR targeting `main`.
- PR title includes ticket id: `CDCM-F01: … (HAL-463)` or `HAL-463: …`.
- PR body must include:
  - Summary (what landed)
  - Related Linear tickets (implementation + parent + blocks/blockedBy that matter)
  - Test plan (Simulator/device when UI)
  - Review notes (code-review / Bugbot / thermo-nuclear-code-quality-review / Codex)
    with what was fixed or intentionally deferred
  - Commit SHA(s) or rely on GitHub commits tab, but Linear must list them too

### 11. Linear Evidence package (mandatory in the flow)

Do **not** stop at “PR opened.” Record the full trail so another machine/agent
can continue without chat history.

On the **implementation** ticket:

```
save_issue:
  id: HAL-XXX
  state: In Review
  links: [{ url: "<pr-url>", title: "PR #N — HAL-XXX" }]
```

Post (or update) one **Evidence package** comment using this template:

```markdown
## Evidence package — HAL-XXX / PR #N

### Tickets
- Implementation: HAL-XXX — <title> — <url>
- Parent / program: HAL-… (if any)
- Blocks: …
- Blocked by (must be Done when started): …
- Related: HAL-468 (order board), …

### GitHub
- PR: https://github.com/…/pull/N
- Branch: `cursor/hal-XXX-…`
- Base: `main`
- Head commit(s):
  - `<full-or-short-sha>` — `<commit subject>`
- Key paths: `path/a`, `path/b`, …

### Reviews
- /code-review (Standards vs Spec): <findings; fixed … / deferred …>
- Bugbot: <none | N findings; fixed … / deferred …>
- thermo-nuclear-code-quality-review: <…>
- Codex CLI: <command used>; <P0/P1/P2 summary; fixed … / recorded …>

### Verification
- `npm test` (node suite + vitest): <result>
- `npm run check:precommit`: <result>
- Simulator / UI: <what you drove, or n/a>
- UI visual review needed: yes/no

### Worktree
- Path used: `<path or "local branch in Cloud Agent checkout">`
- Removed after PR+Codex: yes/no (if no, why)
```

On **HAL-468**:

- Set that row Status → `In Review`.
- Append work log line **with commit SHA**:
  `YYYY-MM-DD — HAL-XXX — PR #N — branch — sha <short> — In Review`
- If the PR is non-product (skill/docs chore supporting the loop), still log it
  and label it as non-tracer so the board stays honest.
- Attach/link the PR on HAL-468 when it is board-relevant (skill pack, order
  tooling); always attach on the implementation ticket.

### 12. Remove the session worktree (mandatory after PR + Codex)

Best time: **immediately after** steps 9–11 succeed — PR is open on GitHub,
Codex CLI review was run and its findings were read (and fixed or recorded),
and no further edits are planned in this worktree until review comments arrive.

```bash
# From the primary checkout (not inside the worktree):
findmnt | grep node_modules            # bind mounts must be unmounted first
git -C <worktree-path> status --porcelain
# disposable noise (the node_modules symlinks) — just delete the links:
rm -f <worktree-path>/node_modules <worktree-path>/apps/engine/node_modules
# real uncommitted work — archive then remove:
# git -C <worktree-path> diff HEAD --binary > /tmp/hal-XXX.patch

git worktree remove <worktree-path>
git worktree prune
```

Rules:

- Removing the worktree does **not** delete the remote PR branch.
- Do **not** `git branch -d` / `git push --delete` here — that stays **post-merge**.
- Do **not** remove a worktree belonging to another running session.
- If review comments need more commits later, add a fresh worktree on the same
  branch: `git worktree add <worktree-path> cursor/hal-XXX-short-slug`
- Cloud Agent local-branch sessions have no worktree to remove — say so in the
  Evidence package.

After merge (when asked to finish):

- Ticket → **Done**
- HAL-468 log → `Merged`
- Post-merge: `main` pull, delete local + origin feature branch, and if a
  worktree was re-created for review fixes, `git worktree remove` + `prune`.

## Review chain at a glance

| # | Pass | Runs where | Catches |
| --- | --- | --- | --- |
| 6 | `/code-review` | Cursor sub-agents | Repo standards + spec drift |
| 7 | Bugbot | Cursor Bugbot subagent | Product defects on the branch diff |
| 8 | thermo-nuclear-code-quality-review | Cursor / repo skill | Abstraction quality, file growth, spaghetti |
| 9 | Codex CLI | Codex, diff-native | Correctness against the base branch |

Four passes is the ceiling, not a target. If two consecutive passes return to the
same root cause, the design is wrong, not the code: make the design decision or
move it to its own ticket rather than patching again.

Do **not** add a fifth pass that shells out to `cursor-agent` / `agent` against
this same checkout. That is the Claude twin's cross-harness review. Here it
would be a second author with the same tools.

## Decision: worktree vs local

| Situation | Choice |
| --- | --- |
| Primary tree on `main` / shared live dir | **Worktree** (`/mnt/data/crt-worktrees/` on the server) |
| Already in a dedicated worktree for this HAL | Stay local to that worktree |
| Worktree add fails (permissions / nested) | Local feature branch; say so in the PR |
| Cloud agent with its own checkout | Local branch in that checkout |

## Out of scope for this skill

- Opening research/grilling tickets (use wayfinder / grilling).
- Multi-ticket mega-PRs.
- Marking Done without merge.
- Weakening CAPTCHA, signing, or privacy boundaries to make a demo pass.
- Logging into any CLI on the user's behalf unless they explicitly asked.

## Related skills (repo `.agents/skills/`)

Sibling project skills (same pack, also git-tracked):

- `tdd` — contract-first tests
- `prototype` — throwaway design/interaction check before production UI
- `code-review` — required Standards vs Spec pass (this flow)
- `grilling` / `grill-with-docs` / `domain-modeling` — product/language locks
- `diagnose` / `diagnosing-bugs` — hard bug loops
- `to-prd` / `to-issues` / `wayfinder` — planning and ticketization
- `handoff` — compact session handoff for another agent
- `resolving-merge-conflicts` — merge/rebase conflicts
- `claude-agentic-coding-best-practices` — Claude Code twin

External / user Cursor skills this flow also uses:

- `review-bugbot` — Bugbot subagent (`~/.cursor/skills-cursor/`)
- `thermo-nuclear-code-quality-review` — required code-quality pass (this flow)
- `thermo-nuclear-review` / `thermos` — only if the user also asks for security thermo

Also: `docs/agents/issue-tracker.md` — Linear MCP conventions and the mandatory
title-prefix rule.
