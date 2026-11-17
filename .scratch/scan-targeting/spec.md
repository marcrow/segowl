# Scan targeting: scope script generation to Zones and Machine Tags

Status: ready-for-agent

Vocabulary: `GLOSSARY.md` (Scan Profile, Machine Tag, Zone, Source). Depends on: `machine-tags/` (tags in inventory).

## Goal

Let the auditor generate scan scripts targeting a subset of the inventory instead of everything, using Zones and Machine Tags as filters. Covers the use case of follow-up scans (e.g. "scan only windows machines in the iLO zone").

Non-goals: persistent target sets (the filter is chosen at generation time), target selection from scan results (that's Automations + tags).

## Constraints

- Target filter is applied at script generation time, in the web UI.
- Filter expression: flat list of criteria (Zone and/or Machine Tag), with a global AND/OR toggle.
  - AND: `zone = iLO AND tag = windows` → intersection (Machines in iLO that are tagged windows).
  - OR: `zone = iLO OR tag = admin` → union.
- The same filter applies to single-script generation and to the zip export (all Sources × one profile).
- `Mission.targets(src)` gains optional filter parameters; the scan script chain already consumes targets as a list.

## Stages

### Stage 1: prototype
- Mockup of the target filter UI in the script generation flow: Zone checkboxes, Tag checkboxes, AND/OR toggle, preview of matching Machines count.

### Stage 2: implementation
- `Mission.targets(src, zones, tags, combine)` with filter.
- UI integrated into the script generation page (between profile selection and the generate button).
- Zip export respects the filter.
- Preview count: "N Machines, M Interfaces" matching the current filter.
