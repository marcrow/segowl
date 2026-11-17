# Tags in the inventory editor

Status: ready-for-agent
Blocked by: 01, 02
Spec: ../spec.md
Type: task

## What

- Tags field in the inventory editor: comma-separated input per row, autocomplete on all tags in the Mission.
- When the user edits tags on one Interface, all Interfaces of the same Machine update.
- Bulk edit: select rows → apply/remove a tag (toolbar button or context menu, as validated in prototype).

## Acceptance

- add/remove tags on a Machine, save, reload: tags persist
- autocomplete suggests existing Mission tags
- bulk tag on 5 rows at once works
