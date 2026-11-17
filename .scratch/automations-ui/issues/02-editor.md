# Automations editor page

Status: ready-for-agent
Blocked by: 01
Spec: ../spec.md
Type: task

## What

- Automations page in the app navigation (between Kits and Report, or as a tab within a relevant section — per prototype verdict).
- List view: label, action badge (tag/exclude), condition text, match count.
- Add/Edit: hybrid editor as validated in prototype. CRUD via app API (`/api/automations`).
- Autocomplete: Zones, Machines, Tags from inventory; common ports from Port Labels.
- Test button: evaluate condition against current observations, display match count and affected Machines.
- Warning banner when an exclusion matches `state = open` observations, showing Finding/Pivot Machine impact.
- Delete with confirmation modal (not native confirm — no alert/confirm policy).

## Acceptance

- create, edit, delete an Automation from the UI; `automations.ini` reflects the changes
- autocomplete suggests Zone names from the current inventory
- test shows realistic match counts
- warning appears when excluding open ports
