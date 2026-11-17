# Per-profile targeting: persistence and backend

Status: ready-for-agent
Blocked by: 01
Spec: ../spec.md
Type: task

## What

- `scan_profiles.csv` gains 3 optional columns: `zones`, `tags`, `combine`. Empty = whole inventory (backward-compatible).
- `Mission.targets(src, zones=None, tags=None, combine='or')` → filtered IP list.
- `zones`: list of Zone names; `tags`: list of Machine Tags; `combine`: 'and' or 'or'.
- When both are set and combine='and': only Machines in a listed Zone AND having a listed tag.
- When combine='or': Machines in a listed Zone OR having a listed tag.
- `None` for a parameter means no filter on that axis (default: everything minus Self).
- Tags include derived tags (from Automations).
- Targeting UI in the profile editor (step 1), saved with the profile via the existing save flow.
- Applied to single script download and zip export.

## Acceptance

- create a profile "iLO sweep" with zone=iLO: only iLO targets in the generated script
- create a profile with tag=windows, combine=and, zone=Admin: only windows Machines in Admin
- default (no targeting): same as before (all minus Self)
- switch profile: targeting loads from the saved profile
- reload page: targeting persists (file-based)
- two browsers see the same targeting after save
