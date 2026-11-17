# Tags in the data model

Status: ready-for-agent
Blocked by: 01
Spec: ../spec.md
Type: task

## What

- `inventory.py`: parse a `tags` column (`;`-separated in the CSV cell) into `Host.tags: list[str]`. Validate charset `[a-z0-9_-]`, max 32 chars per tag.
- Tags are per Machine: when saving, all Interfaces of a Machine get the same tag list.
- `extra_columns()` returns `tags` among free columns; report tables and exports show tags.
- Round-trip: load → save preserves tags and all other free columns.

## Acceptance

- `pytest`: load an inventory with tags, check `Host.tags`; save and reload, nothing lost
- an inventory without a tags column still loads fine
