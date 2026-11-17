# Scan targeting: scope script generation to Zones and Machine Tags

Status: ready-for-agent

Vocabulary: `GLOSSARY.md` (Scan Profile, Machine Tag, Zone, Source). Depends on: `machine-tags/` (tags in inventory).

## Goal

Let the auditor generate scan scripts targeting a subset of the inventory instead of everything, using Zones and Machine Tags as filters. Each Scan Profile carries its own targeting: "Console scan" targets `tag=console`, "iLO sweep" targets `zone=iLO`, "Full TCP" targets everything.

Non-goals: target selection from scan results (that's Automations + tags).

## Constraints

- Targeting is **per Scan Profile**, persisted in a separate `scan_targeting.csv` (columns: `profile`, `zones`, `tags`, `combine`). Empty = whole inventory (backward-compatible default). Stored separately to preserve kit portability (zones are client data).
- Filter expression: flat list of criteria (Zone and/or Machine Tag), with a global AND/OR toggle.
  - AND: `zone = iLO AND tag = windows` → intersection (Machines in iLO that are tagged windows).
  - OR: `zone = iLO OR tag = admin` → union.
- The filter is part of the profile editor (step 1), shown as a distinct "Targeting" section below Ports/Options.
- Applies to single-script generation and to the zip export (all Sources × one profile).
- `Mission.targets(src)` gains optional filter parameters; the scan script chain already consumes targets as a list.
- Persistence is file-based (CSV), so both users/browsers see the same targeting.

## Stages

### Stage 1: prototype
- Mockup of the targeting section inside the profile editor: Zone checkboxes, Tag checkboxes (manual + derived), AND/OR toggle, live count of matching Machines/Interfaces.

### Stage 2: implementation
- `scan_profiles.csv`: 3 new optional columns (`zones`, `tags`, `combine`).
- `Mission.targets(src, zones, tags, combine)` with filter.
- Targeting section in the profile editor UI, saved with the profile.
- Zip export respects the profile's targeting.
- Preview count: "N Machines, M Interfaces" matching the current targeting.
