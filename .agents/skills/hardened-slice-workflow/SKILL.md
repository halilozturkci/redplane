---
name: hardened-slice-workflow
description: Executes issue or slice implementation with tracer-bullet phasing, mandatory tests, review gates, thermo-nuclear quality gates, issue closeout, and commit discipline. Use when starting or continuing an issue/slice and the user asks for tracer bullet, sub-phases, review before commit, thermo review, no remaining findings, strict closeout, or hardened issue execution.
argument-hint: "Slice id or issue path (e.g. SLICE-105A, docs/issues/SLICE-105A-....md)"
---

# Hardened Slice Workflow

Use this as an orchestration skill. It does not replace the underlying skills;
it forces their order and stop conditions for issue/slice implementation.

## Required Skills

Before changing code, load and follow these skills when available:

- `tracer-bullet-slice-workflow` for issue intake, sub-phase planning, tests,
  rebibe, issue checklist updates, and commit conventions.
- `review` for spec and standards review of each sub-phase and the final slice.
- `thermo-nuclear-code-quality-review` for strict maintainability review of
  touched code before each commit and at slice closeout.

If one is unavailable, state the missing skill once and run an equivalent manual
gate with the same intent. Do not ask the user for permission to run these gates
unless a tool, production write, or external account action truly requires it.

## Intake

1. Resolve the active issue/slice from the user's request.
2. Read the issue body, parent issue, linked ADR/PRD/context docs, migration
   notes, and repo instructions such as `CLAUDE.md`, `AGENTS.md`, or
   `CONTRIBUTING`.
3. Build a checklist from acceptance criteria and test-plan items.
4. Split the work into 2-4 vertical sub-phases. Each sub-phase must produce a
   verifiable behavior or contract, not a horizontal implementation layer.
5. Tell the user the sub-phase list before edits. Keep updates short.

## Sub-Phase Loop

For each sub-phase:

1. **Plan**: name files likely to change, invariants to preserve, and tests to
   run for that sub-phase.
2. **Develop**: make the smallest correct change. Keep scope inside the issue.
3. **Test**: run targeted tests for that sub-phase. Fix failures before moving
   on.
4. **Rebibe**: re-read every changed file and trace issue acceptance criteria
   to code. Fix gaps, typos, export mistakes, cutoff leaks, and scope creep.
5. **Review gate**: use the `review` skill against the current diff or the
   sub-phase commit range. Fix all actionable spec/standards findings.
6. **Thermo gate**: use `thermo-nuclear-code-quality-review` on touched areas.
   Fix all actionable maintainability, abstraction, giant-file, and
   condition-sprawl findings.
7. **Retest**: rerun the sub-phase tests after review fixes.
8. **Commit checkpoint**: commit the sub-phase only if repo rules allow phase
   commits. If repo rules require a single slice commit, keep the sub-phase
   verified but defer the commit to slice closeout.

Do not start the next sub-phase while tests or actionable findings remain.
Classify unresolved items only when they are explicitly out of scope, blocked by
missing external state, or contradicted by the issue/repo rules.

## Slice Closeout

After all sub-phases:

1. Run the full issue test plan and the repo precommit gate.
2. Re-run `review` for the full slice diff/range.
3. Re-run `thermo-nuclear-code-quality-review` for the full slice diff/range.
4. Fix every actionable finding, then rerun affected tests and gates.
5. Update the issue checklist only for criteria that are truly satisfied.
6. Close the issue when the issue tracker supports it. For a file-based markdown
   tracker (e.g. `docs/issues/SLICE-*.md`), mark the slice's acceptance
   checkboxes complete and report any remaining human action (such as staging
   visual review on HITL slices).
7. Commit with the repo's required message format. Include tests, migration
   safety, UI review notes, and co-author/footer requirements from repo rules.

## Reporting

Report after each sub-phase:

- Sub-phase name and status.
- Tests run.
- Review findings fixed, or `none`.
- Thermo findings fixed, or `none`.
- Commit hash, or why commit was deferred by repo rules.
- Next sub-phase.

Final report must include the final commit hash, test commands, any skipped
manual validation, and the next issue/slice if known.
