# Automation engine: tag and exclude actions

Status: ready-for-agent
Blocked by: 01
Spec: ../spec.md
Type: task

## What

- Load `automations.ini` via `configparser`. Validate each section (required keys, action type, tag charset).
- Run tag Automations first: for each observation, if condition matches, add derived tag to the Machine.
- Run exclusion Automations: for each observation, if condition matches, mark it excluded.
- Recompute verdicts after exclusions. EXCLUDED verdict when all observations removed.
- ALIVE preserved when host answered discovery and all ports excluded.
- Warning counter: how many Findings / Pivot Machines an `state = open` exclusion masks.
- Write back `automations.ini` (add/remove/edit Automations from the app).

## Acceptance

- tag Automation: port 3389 open → Machine gets `windows` derived tag (read-only, not in CSV)
- exclude Automation: state = closed and zone = Admin → those observations removed, verdicts recompute
- EXCLUDED verdict when all ports excluded on a pair
- ALIVE when host answers ping but all ports excluded
- warning count on open-state exclusion
