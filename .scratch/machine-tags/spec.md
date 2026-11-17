# Machine Tags: label Machines for grouping and targeting

Status: ready-for-agent

Vocabulary: `GLOSSARY.md` (Machine Tag, Machine, Interface, Auditor Kit).

## Goal

Let the auditor label Machines with free-form tags (e.g. windows, admin, vmware) in the inventory, so they can target scans and write Automation conditions against groups of Machines instead of listing IPs by hand.

Non-goals: derived tags (Automations, see `automations/`), tag-based Flow Policy, tag hierarchy.

## Constraints

- Tags are stored as a `;`-delimited list in a `tags` column of `inventory.csv` (the fifth column, or a named free column via header).
- Tags are per Machine: every Interface of a Machine shares its tags. The inventory stores tags on each row; the editor keeps them in sync across rows of the same Machine.
- Tag charset: `[a-z0-9_-]`, lowercase only, max 32 chars. Validated on save.
- The `tags` column is optional: an inventory without it works as before.
- `extra` dict in `Host` gains a reserved key `tags` → `list[str]`.

## Stages

### Stage 1: data model and persistence
- `inventory.py`: parse the `tags` column into `Host.tags: list[str]`, write it back.
- `csvfile.py` or inventory helpers: round-trip tags through load/save without losing other free columns.
- Tags visible in all tables that show Machine info (report, per-source, per-target).

### Stage 2: inventory editor
- A `tags` field in the inventory editor row (comma-separated input, autocomplete on existing tags in the Mission).
- Bulk edit: select multiple rows, apply/remove a tag.

## Kit integration

Port Groups, Scan Profiles, Port Labels are already in the Kit. Machine Tags are NOT in the Kit (they are client data: specific to an inventory). Automations that compute derived tags are in the Kit (see `automations/spec.md`).
