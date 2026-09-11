---
name: tracer-bullet-slice-workflow
description: >-
  Executes one tracer-bullet vertical slice with phased
  plan-develop-test-verify-rebibe-commit discipline. Use when the user starts or
  continues a slice implementation, says "slice workflow" or "rebibe", or invokes
  this skill with a slice identifier or issue path.
argument-hint: "Slice id or issue path (e.g. SLICE-45H2, docs/issues/SLICE-45h2-....md)"
---

# Tracer-Bullet Slice Workflow

Apply this workflow for the **active slice** the user gave as an argument. If no slice was passed, ask once for a slice id or issue file path before intake.

## Slice input (required)

Treat the user's argument (or explicit message) as **`$SLICE_INPUT`**. Resolve it to:

| Field | How to resolve |
|-------|----------------|
| **`$SLICE_ISSUE_PATH`** | If input is a `.md` path, use it. Else search the repo's issue directory (commonly `docs/issues/`, or `issues/`) for a file matching the id (case-insensitive; e.g. `SLICE-45H2`, `slice-45h2`, slug fragment). |
| **`$SLICE_ID`** | Title/id from the issue file (e.g. `SLICE-45`, `SLICE-45H2`) — not guessed from the filename alone. |
| **`$SLICE_TYPE`** | `Type:` field in the issue (e.g. `AFK` / `HITL`). |
| **`$PARENT_ISSUE`** | `Parent` field or `## Parent` section / parent issue link in the slice file, if any. |
| **`$ISSUE_PACK_INDEX`** | Nearest index, milestone, or master list linked from the slice (e.g. a pack `00-index.md`, `MILESTONES.md`, or `README.md`) — only if one exists. |

Do not assume a fixed issue directory or numeric series; only paths and rules **linked from `$SLICE_ISSUE_PATH`**.

If resolution is ambiguous, list candidates and ask the user to pick one.

## 0. Slice intake

1. Read **`$SLICE_ISSUE_PATH`**, **`$PARENT_ISSUE`**, linked ADRs, PRD links, migration ledger links, and CONTEXT.md glossary terms referenced in the issue.
2. Read the repo's own rules before writing code: `CLAUDE.md` / `CONTRIBUTING` for the **commit convention**, the **pre-commit gate**, and the **migration-pipeline rules** (file naming, required headers, ledger). Where these conflict with this skill's defaults, the repo's rules win.
3. Build a **task list** from acceptance criteria and test-plan items in **`$SLICE_ISSUE_PATH`**.
4. Split tasks into **phases** (2–4 typical). Phase names come from the issue structure, not a global template.
5. Post the task list at slice start; label it with **`$SLICE_ID`**. Update checkboxes only when items are truly done.

## 1. Per-task loop (within a phase)

For **each** task in the phase:

| Step | Action |
|------|--------|
| **Plan** | State files to touch, invariants from the issue + ADRs, and how acceptance maps to code. |
| **Develop** | Minimal correct diff; match project conventions. |
| **Test** | Run tests named in the issue test plan; scope to changed packages when possible. |
| **Verify** | Fix failures; re-run until green; confirm no scope creep vs **Implementation notes** / **Out of scope** in the issue. |

Do not start the next task in the phase until the current task verifies.

## 2. Phase closeout (mandatory)

Before committing a phase:

1. **Rebibe** — Re-read every file changed in the phase; trace **`$SLICE_ISSUE_PATH`** acceptance criteria → code; hunt for gaps, typos, missing exports, wrong optional/required fields, and behavioral leaks outside slice scope.
2. Run phase-level tests again (per issue test plan), plus the repo's pre-commit gate if one exists (e.g. `npm run check:precommit` — lint, typecheck, migration safety, secret scan). Do not skip mandated hooks (e.g. `--no-verify`) unless the user explicitly authorizes it.
3. **Commit** — Follow the repo's commit convention exactly (the one read in §0.2): required subject format, commit cadence (per phase vs. one-per-slice), body structure, and any mandated trailer (e.g. a `Co-Authored-By:` footer). Do **not** impose a generic convention over the repo's own. Skip committing only if the user forbids it.
4. Update **`$SLICE_ISSUE_PATH`** status / checkboxes only when the phase satisfies those items.

## 3. Slice closeout

After all phases for **`$SLICE_ID`**:

1. Full-slice **rebibe** (all files + tests touched for this slice).
2. Run the slice test plan end-to-end.
3. **Prerequisite rebibe** — If the issue **Blocked by** field, parent issue, or the user names prior slices that must stay correct, re-verify those slices (read their issue files + relevant code/tests) before marking **`$SLICE_ID`** done.
4. Note blockers for the **next** slice (from **Blocks** / dependency map) in a short handoff bullet list.

## 4. UI manual validation (when applicable)

If **`$SLICE_ISSUE_PATH`** or **`$ISSUE_PACK_INDEX`** requires admin/operator-visible evidence (e.g. an admin console or management panel):

- What to open (prefer paths stated in the issue or pack index).
- Feature flags / tenant / DB prerequisites from the issue.
- Exact pages or flows to verify.
- Expected good state vs regressions.

**Do not** claim UI verification unless the user requested browser automation and you ran it. Ask the user to confirm.

## 5. Out of scope guardrails

Derive guardrails from **`$SLICE_ISSUE_PATH`** and linked ADRs — especially **Implementation notes**, negative acceptance criteria, and **Type: HITL** requirements. Examples (only when the issue says so):

- Contract-only slice → no runtime behavior beyond validation/types.
- HITL / migration slice → no shared-DB writes without runbook + ledger sign-off recorded in the issue.
- Flag-gated behavior → default off; legacy path unchanged when flag off.

Do not import guardrails from other slices unless **`$SLICE_INPUT`** or the user explicitly combined slices.

## 6. Commit message

The repo's mandated commit format is the source of truth (read `CLAUDE.md` / `CONTRIBUTING` before the first commit — see §0.2). If the repo requires a slice-prefixed subject (e.g. `SLICE-XX: <imperative title>`), use that — do **not** substitute a generic `type(scope):` line. Where the repo leaves scope free, infer it from the packages touched in the slice; if the issue names a scope, prefer that. Always include any mandated body structure and trailers (co-author footer, migration-ledger references).

## 7. Reporting template

After each phase, report:

```
Slice: $SLICE_ID
Phase N: <name>
- Tasks completed: …
- Tests run: …
- Rebibe findings fixed: … (or none)
- Commit: <hash/message> | skipped (user request)
- Manual UI validation: none | <checklist for user>
- Prerequisite rebibe: none | <slices verified>
- Next phase: …
```

## 8. Session handoff

When pausing mid-slice or finishing **`$SLICE_ID`**, use the **handoff** skill. Reference **`$SLICE_ISSUE_PATH`**, ADRs, and commits by path — do not duplicate issue bodies.
