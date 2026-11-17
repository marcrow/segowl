# Wire Automations into the analysis pipeline

Status: ready-for-agent
Blocked by: 02
Spec: ../spec.md
Type: task

## What

- Insert Automation evaluation after Scan parse, before verdict computation in the analysis pipeline.
- Derived tags visible in inventory tables, report, per-source, per-target, exports.
- Exclusion toggle in all views: hidden by default, "Show exclusions" button reveals excluded observations greyed out. Toggle state persists per session (not per Mission).
- Exclusions propagate to: matrix cells, Findings, Pivot Machines, Scan Diff, CSV/exports.

## Acceptance

- with an exclusion active, the matrix cell changes (e.g. REACHABLE → BLOCKED if the closed port was the only evidence)
- toggle on: excluded rows visible but greyed; toggle off: rows hidden, counts updated
- Findings list excludes flows masked by an exclusion Automation
- export CSV reflects the exclusion state
