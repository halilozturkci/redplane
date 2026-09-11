# Triage Labels

The imported skills speak in five canonical triage roles. Map them 1:1 onto
GitHub labels in `halilozturkci/redplane`.

| Role in mattpocock/skills | Label in this tracker | Meaning |
| ------------------------- | --------------------- | ------- |
| `needs-triage`            | `needs-triage`        | Maintainer needs to evaluate this issue |
| `needs-info`              | `needs-info`          | Waiting on reporter for more information |
| `ready-for-agent`         | `ready-for-agent`     | Fully specified, ready for an AFK agent |
| `ready-for-human`         | `ready-for-human`     | Requires human implementation |
| `wontfix`                 | `wontfix`             | Will not be actioned |

When a skill mentions a role (for example "apply the AFK-ready triage label"),
use the corresponding label string from this table.

If a label does not exist yet, create it on first use (`gh label create`).
