# Target filter in Mission.targets()

Status: ready-for-agent
Blocked by: 01
Spec: ../spec.md
Type: task

## What

- `Mission.targets(src, zones=None, tags=None, combine='or')` → filtered IP list.
- `zones`: list of Zone names; `tags`: list of Machine Tags; `combine`: 'and' or 'or'.
- When both are set and combine='and': only Machines in a listed Zone AND having a listed tag.
- When combine='or': Machines in a listed Zone OR having a listed tag.
- `None` for a parameter means no filter on that axis (default: everything minus Self).
- UI: checkboxes + toggle, preview count. Applied to single script and zip export.

## Acceptance

- generate a script with zone=iLO: only iLO targets in the target file
- generate a zip with tag=windows, combine=and, zone=Admin: only windows Machines in Admin
- default (no filter): same as before (all minus Self)
