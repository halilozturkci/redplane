---
name: claude-agentic-coding-best-practices
description: >-
  Claude Code agentic coding loop for one Linear implementation ticket:
  claim In Progress, worktree or local branch, implement, tests/Simulator,
  code-review, thermo-nuclear-code-quality-review, Cursor Agent review,
  Codex CLI review, one PR, then the Linear evidence package and worktree
  removal. Use when implementing a CDCM/HAL/GDE ticket, taking the next
  implementation ticket, running the tracer-bullet loop, or invoking
  /claude-agentic-coding-best-practices.
disable-model-invocation: true
---

# Claude Agentic Coding Best Practices

One **implementation** ticket → one branch → one PR. Same discipline as the
Cursor sibling skill (`cursor-agentic-coding-best-practices`), rewritten for
**Claude Code**: the review chain, the tool names, and the binaries are the ones
that actually exist in this harness, and every command below was executed on a
real machine before being written down.

This is a **repo skill**: it lives under `.agents/skills/` and ships with the git
tree. `.claude/` is **gitignored** in this repo — that is why repo skills live
under `.agents/`, not `.claude/skills/`. To make this skill invocable inside
Claude Code, link it into the personal pack (the `remotion-best-practices`
precedent):

```bash
ln -sfn /var/www/cyberroundtable.ai/.agents/skills/claude-agentic-coding-best-practices \
        ~/.claude/skills/claude-agentic-coding-best-practices
```

Canonical order board: **HAL-468** (`CDCM-0: Implementation order board`).
If that ticket is missing, recreate it under the program parent before coding.

## Non-negotiables

- Never implement two tickets in one PR.
- Never start a ticket whose Linear `blockedBy` edges are still open.
- Never commit/push on `main` / `production`. Prefer a dedicated worktree.
- Do not mark the ticket **Done** at PR open — set **In Review**, attach the PR,
  update HAL-468. **Done** only after merge + post-merge cleanup.
- Secrets, API tokens, Apple keys: never paste into Linear, commits, or PRs.
- **A reviewer that can write is not a reviewer, it is a second author.** Every
  review pass is read-only by *enforced permission*, never by prompt wording.
- After the PR is open and the Codex cycle for that PR is finished, **remove the
  session worktree**. The remote branch stays for the PR; branch deletion is
  post-merge only.
- Every open PR leaves a complete **Evidence package** on Linear (implementation
  ticket + HAL-468). Chat alone is not the record.

## Workflow checklist

Copy and track:

```
Claude agentic coding:
- [ ] 1. Resolve order board + pick ticket
- [ ] 2. Claim on Linear (In Progress, assignee me)
- [ ] 3. Branch / worktree
- [ ] 4. Implement against ticket AC
- [ ] 5. Verify (full suite + Simulator when UI/native)
- [ ] 6. /code-review (Standards vs Spec) → fix clear findings
- [ ] 7. thermo-nuclear-code-quality-review → fix clear findings
- [ ] 8. Cursor Agent review (enforced read-only) → fix or record
- [ ] 9. Codex CLI review (ticket-aware) → fix or record
- [ ] 10. Commit + push + open PR
- [ ] 11. Linear evidence package (ticket + HAL-468)
- [ ] 12. Remove session worktree
```

### 1. Resolve order board + pick ticket

1. `get_issue` **HAL-468** (`includeRelations: true` if useful).
2. If the user named a ticket, use it — but only if its blockers are clear.
3. Otherwise take the first board row that is Next/Queued, unblocked, and not
   already In Progress in another session.
4. `get_issue <id> includeRelations=true`. Refuse to start while any `blockedBy`
   issue is not Done.
5. Ops exception: **HAL-462 O01** may run in parallel with engineering.

### 2. Claim on Linear

Before editing code:

```
save_issue:
  id: HAL-XXX
  state: In Progress
  assignee: me
```

Comment once with the branch name you will use, and set that row on HAL-468 to
`In Progress`.

### 3. Branch / worktree

**Where worktrees live depends on the machine, and the difference is not
cosmetic:**

| Machine | Location | Why |
| --- | --- | --- |
| Server (`/var/www/cyberroundtable.ai`) | `/mnt/data/crt-worktrees/<topic>` | `/` is 48 GB and has hit 97%; `/mnt/data` is a separate 100 GB volume. The primary checkout must stay on `main` because the deploy runner, the DR-panel worker and the cron jobs `cd` into it and execute whatever branch is checked out. |
| Local Mac checkout | `.claude/worktrees/<topic>` | `.claude/` is gitignored, so worktrees never pollute `git status`. Nothing executes the primary checkout automatically here. |

```bash
git fetch origin main
git worktree add <worktree-path> -b claude/hal-XXX-short-slug origin/main
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

Branch naming: `claude/hal-<n>-<short-slug>`. A local branch is acceptable only
when you are already inside a dedicated worktree for this ticket, or worktree
creation is impossible — say so in the PR.

### 4. Implement

- Treat the Linear description as the spec (Outcome, AC, Boundaries, Dependencies).
- Follow `CLAUDE.md` / `AGENTS.md`: design system for UI, migration rules for
  SQL, commit convention (program prefix, one ticket per commit/PR).
- Any task where "how should it look / read / behave" is open must go through
  `/prototype` **before** production UI. Mechanical edits do not.
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

For UI or native work, drive the simulator with the Claude Code simulator tool
(`mcp__Claude_Code_iOS_Simulator__control`): `attach` first so the human can
watch, then `launch`, then `screenshot` / `tap` to walk the ticket's visible
path yourself. Do not ask the human to check what you can verify headlessly, and
never claim a Simulator pass you did not run.

Server-only tickets: contract/unit tests, and no Simulator claim at all.

### 6. `/code-review` — Standards vs Spec

**Bugbot does not exist in Claude Code.** It is a Cursor subagent (and Cursor's
real review product is a Cloud Agents feature, not the CLI); the Cursor sibling
skill's step 6 has no equivalent binary here. The native replacement is the
repo's `code-review` skill, which runs two parallel sub-agents over the diff
since a fixed point:

- **Standards** — does the code follow this repo's documented standards?
- **Spec** — does the code do what the originating ticket asked for?

Fix clear, in-scope findings. Do not expand scope to polish.

### 7. thermo-nuclear-code-quality-review

Run the `thermo-nuclear-code-quality-review` skill on the branch diff. It ships
in this repo at `.agents/skills/thermo-nuclear-code-quality-review/`. It is
deliberately harsh about abstraction quality, file-size growth and spaghetti
conditions, and asks for *ambitious* restructuring rather than local tidying.

Do not run the security double-pass (`thermos` / `thermo-nuclear-review`) unless
the user asks for it.

Fix clear medium/high findings in scope; record accepted residual risk in the PR
when you defer something on purpose.

### 8. Cursor Agent review — before Codex

A third reviewer, from a different model family, with no memory of how the code
was written. Run it after the two Claude passes and before Codex.

#### 8.1 Prove you have the right binary

`agent` has been ambiguous on this machine before: until 2026-08-14 it resolved
to **grok** (`~/.grok/bin/agent`, a different product with different flags),
because `~/.grok/bin` precedes `~/.local/bin` on PATH. That alias was removed,
but the class of bug returns whenever a new CLI claims the name.

```bash
agent --version     # expect 2026.MM.DD-<hash>. "grok x.y.z" means the wrong binary.
```

If it is wrong, call the real one by the name nothing competes for:
`cursor-agent` — the same executable under an unambiguous alias.

#### 8.2 Prove it is authenticated — with a real round-trip

**`agent status` is not a reliable probe.** It prints `✓ Login successful!` from
local credential state even when every real request fails with
`Authentication required`. Probe with an actual call, and judge the **JSON
envelope**, not the exit code:

```bash
agent -p "Reply with exactly: PONG" --mode ask --trust --output-format json \
  > /tmp/agent-probe.json 2>/tmp/agent-probe.err
jq -e '.type == "result" and .is_error == false' /tmp/agent-probe.json >/dev/null \
  || { echo "cursor-agent probe failed:"; cat /tmp/agent-probe.err; }
```

If it fails on auth, **stop and ask the human to run `agent login`** (interactive
browser OAuth — an agent must never perform a login on the user's behalf) or to
export `CURSOR_API_KEY`. Over SSH, `NO_OPEN_BROWSER=1` prints the URL instead of
opening a browser; in a container, `AGENT_CLI_CREDENTIAL_STORE=file` avoids the
macOS keychain.

Three gotchas, all observed rather than assumed:

- **`--output-format text` can return completely empty with exit 0.** The same
  prompt under `--output-format json` returned a valid envelope. Use `json` and
  parse it; `text` has a documented-and-observed silent-failure mode.
- **Exit codes are not trustworthy on their own.** Gate on
  `.type == "result" and .is_error == false` — the docs guarantee no well-formed
  JSON object is emitted on failure, which makes the envelope the stronger
  signal.
- **Never pipe the probe into `head`/`grep` and then read `$?`** — a pipeline
  reports the last command's status and silently converts failure into success.
  Redirect to a file, or read `${PIPESTATUS[0]}`.

#### 8.3 Fresh worktrees need `--trust`

A newly created worktree is an untrusted workspace, and headless runs refuse to
start there:

```
⚠ Workspace Trust Required … Pass --trust, --yolo, or -f if you trust this directory
```

Pass **`--trust`** — it grants workspace trust and nothing else. Do **not** reach
for `--yolo` / `-f`: those mean "force allow commands unless explicitly denied",
which is an approval policy, not a trust grant, and it is the opposite of what a
review needs.

#### 8.4 Make it read-only by permission, not by prompt

**`--mode plan` and `--mode ask` are not security boundaries.** Cursor's own docs
describe them as behavioural modes and then recommend a *prompt* ("do not write
any code") to keep the agent from editing — which is exactly the admission that
the mode enforces nothing at the tool layer. Enforcement lives in the
permissions config, where **deny beats allow beats `--force`**.

This skill ships `review-permissions.template.json`: `Read(**)` plus read-only
git and shell commands allowed, `Write(**)` and every mutating or exfiltrating
shell command denied, secrets unreadable.

**Copy it into a throwaway config directory — never point `CURSOR_CONFIG_DIR` at
a tracked path.** The CLI treats that directory as its config home and **writes
its whole session state back into `cli-config.json` on exit, including
`authInfo` with the account email, user id and auth id.** Pointing it at a repo
directory stages credentials for commit. (This was caught in testing, not in
theory.)

```bash
SKILL_DIR="$(git rev-parse --show-toplevel)/.agents/skills/claude-agentic-coding-best-practices"
REVIEW_CFG="$(mktemp -d)"
cp "$SKILL_DIR/review-permissions.template.json" "$REVIEW_CFG/cli-config.json"
# … run the review (below) …
rm -rf "$REVIEW_CFG"        # takes the credential writeback with it
```

Verified adversarially: told to create a file, the agent tried the built-in
writer, then a shell write, then the filesystem MCP — all three were refused and
no file appeared.

#### 8.5 Run the review

There is **no `review` subcommand** — unlike Codex, the Cursor CLI reviews only
what you prompt. Pass the prompt as an **argument**; stdin is not a prompt
channel (piped stdin only makes the CLI infer print mode).

```bash
perl -e 'alarm shift; exec @ARGV' 900 \
  env CURSOR_CONFIG_DIR="$REVIEW_CFG" agent -p "$(cat <<'PROMPT'
Review the current branch's changes against origin/main for a single ticket.
Ticket: HAL-XXX — <one-line outcome>.
Start by running: git diff origin/main...HEAD
Report only defects you can anchor to a specific file and line: correctness bugs,
missed edge cases, contract/test drift, security issues, and places the change
does not match the ticket's stated outcome.
Rank by severity. If you find nothing at a severity, say so explicitly.
Do not restyle and do not propose refactors.
PROMPT
)" --model cursor-grok-4.6-high-fast --trust --output-format json \
  > /tmp/hal-XXX-cursor-review.json 2>/tmp/hal-XXX-cursor-review.err

jq -r 'select(.type=="result") | .result' /tmp/hal-XXX-cursor-review.json
```

The timeout wrapper is not optional: the CLI has a multi-release history of
headless hangs and documents no run timeout of its own. **Do not write
`timeout 900 …`** — stock macOS ships neither `timeout` nor `gtimeout` (both are
coreutils), so that line dies with `command not found` before the review starts.
The `perl -e 'alarm shift; exec @ARGV'` form above needs nothing that is not
already on a Mac (`/usr/bin/perl`) and exits 142 when it fires.

The whole invocation above — throwaway config, model slug, trust flag, JSON
envelope — was run end to end against a real 20-file diff before being written
down: the agent executed `git diff origin/main...HEAD --stat` under the
read-only permission set (so the `Shell(git:diff*)` allow rule does what it
claims), returned a valid envelope, and the disposable config dir was confirmed
afterwards to have captured `authInfo` — which is exactly why it is disposable.

**Model selection — effort and speed live in the slug, not in flags.** There is
no `--effort` or `--fast` option, and the bracket syntax printed by `--help`
(`model[effort=high,fast=false]`) **does not work** — Cursor staff confirmed it
was published by mistake and never implemented. Verified here: the bracket form
exits 1 with `Cannot use this model`, while the flat slug succeeds.

```bash
agent models | grep -i grok     # slug on the left, display name on the right
```

The ladder is `low → medium → high → xhigh` (some families add `max`), with an
optional `-fast` suffix, and `high` is the implicit default that display names
omit. "Cursor Grok 4.6 High Fast" is therefore **`cursor-grok-4.6-high-fast`**.

Two more flags to get right:

- **`--auto-review` is not a code review.** It is a server-side *tool-approval*
  classifier that auto-runs calls it judges safe — and Cursor's own docs state it
  is not a security boundary. Do not reach for it because of the name.
- **Never pass `-w` / `--worktree`.** That makes the agent its own checkout under
  `~/.cursor/worktrees/`, which both defeats the point of reviewing *your* branch
  and lands outside this repo's worktree discipline.

One cross-tool effect worth knowing: the Cursor CLI loads `.cursor/rules`,
`AGENTS.md` **and `CLAUDE.md`** from the project root as rules automatically. The
reviewer therefore already knows this repo's conventions — no flag needed, and no
need to restate them in the prompt.

**Read the output and act on it.** Fix what is real; for anything skipped, write
one line in the PR body saying why. A review you ran but ignored is worse than
one you never ran, because the evidence package will claim coverage.

### 9. Codex CLI review

With the earlier fixes committed (or the intent clear), run Codex against the
ticket. Background is fine.

```bash
codex review --base main
```

The old dual-binary trap is gone: `/opt/homebrew/bin/codex` and the nvm copy no
longer exist, and bare `codex` resolves to `~/.local/bin/codex` (0.147.x). If
Codex ever demands `OPENAI_API_KEY` again, check `command -v codex` and
`codex --version` before suspecting the login — a stale binary shadowing the
standalone one is the likelier cause.

If `codex review` rejects combining `--base` with an inline prompt, pass the
prompt on stdin; if the subcommand is unavailable at all, fall back to:

```bash
codex exec "Review git diff vs origin/main for HAL-XXX — …"
```

Read the output, incorporate the high-signal findings, and explain any skip in
the PR body. Do not open the PR before this step unless the user waives it.

### 10. Commit + PR

- Commit with the repo convention; the body lists concrete changes and flags UI
  changes explicitly so reviewers know visual review is required.
- Push the branch; open **one** PR targeting `main`.
- PR title carries the ticket id: `GDE-1: … (HAL-494)`.
- PR body: summary, related Linear tickets, test plan, and a review-notes block
  naming each of the four passes with what was fixed or deliberately deferred.

### 11. Linear evidence package

Do not stop at "PR opened". On the implementation ticket:

```
save_issue:
  id: HAL-XXX
  state: In Review
  links: [{ url: "<pr-url>", title: "PR #N — HAL-XXX" }]
```

Then post (or update) one comment:

```markdown
## Evidence package — HAL-XXX / PR #N

### Tickets
- Implementation: HAL-XXX — <title> — <url>
- Parent / program: …
- Blocks / Blocked by: …
- Related: HAL-468 (order board)

### GitHub
- PR: https://github.com/…/pull/N
- Branch: `claude/hal-XXX-…`  Base: `main`
- Head commit(s): `<sha>` — `<subject>`
- Key paths: …

### Reviews
- /code-review (Standards vs Spec): <findings; fixed … / deferred …>
- thermo-nuclear-code-quality-review: <…>
- Cursor Agent (`--model <slug>`, enforced read-only config): <…>
- Codex CLI (`codex review --base main`): <…>

### Verification
- `npm test` (node suite + vitest): <result>
- `npm run check:precommit`: <result>
- Simulator / UI: <what you drove, or n/a>
- UI visual review needed: yes/no

### Worktree
- Path used: `<path>`
- Removed after PR + Codex: yes/no (if no, why)
```

On **HAL-468**: set the row to `In Review` and append
`YYYY-MM-DD — HAL-XXX — PR #N — branch — sha <short> — In Review`.

### 12. Remove the session worktree

Best time: immediately after steps 9–11 succeed and no further edits are planned
in this worktree until review comments arrive.

```bash
# From the primary checkout, never from inside the worktree:
findmnt | grep node_modules            # bind mounts must be unmounted first
git -C <worktree-path> status --porcelain
# disposable noise (the node_modules symlinks) — just delete the links:
rm -f <worktree-path>/node_modules <worktree-path>/apps/engine/node_modules
# real uncommitted work — archive before removing:
# git -C <worktree-path> diff HEAD --binary > <somewhere-safe>.patch

git worktree remove <worktree-path>
git worktree prune
```

- Removing the worktree does **not** delete the remote PR branch.
- Do **not** `git branch -d` / `git push origin --delete` here — post-merge only.
- Never remove a worktree whose branch is unmerged, or one belonging to another
  running session.
- If review comments need more commits, add a fresh worktree on the same branch.

After merge: ticket → **Done**, HAL-468 row → `Merged`, pull `main`, delete the
local and origin feature branches, and remove any worktree re-created for review
fixes.

## Review chain at a glance

| # | Pass | Runs where | Catches |
| --- | --- | --- | --- |
| 6 | `/code-review` | Claude Code sub-agents | Repo standards + spec drift |
| 7 | thermo-nuclear-code-quality-review | Claude Code | Abstraction quality, file growth, spaghetti |
| 8 | Cursor Agent | Cursor CLI, different model family | Defects the Claude passes are blind to |
| 9 | Codex CLI | Codex, diff-native | Correctness against the base branch |

Four passes is the ceiling, not a target. If two consecutive passes return to the
same root cause, the design is wrong, not the code — make the design decision or
move it to its own ticket rather than patching again.

## Out of scope

- Opening research/grilling tickets (use `/wayfinder`, `/grilling`).
- Multi-ticket mega-PRs.
- Marking a ticket Done without a merge.
- Weakening CAPTCHA, signing, or privacy boundaries to make a demo pass.
- Logging into any CLI on the user's behalf.

## Related skills

In this repo (`.agents/skills/`): `tdd`, `prototype`, `code-review`,
`thermo-nuclear-code-quality-review`, `grilling`, `domain-modeling`,
`diagnose` / `diagnosing-bugs`, `to-prd`, `to-issues`, `wayfinder`, `handoff`,
`resolving-merge-conflicts`, and the Cursor twin
`cursor-agentic-coding-best-practices`.

Also: `docs/agents/issue-tracker.md` — Linear MCP conventions and the mandatory
title-prefix rule.
