# Report exclusions: Automation section and toggle in the HTML report

Status: ready-for-agent

Vocabulary: `GLOSSARY.md` (Automation, EXCLUDED). Depends on: `automations/` (engine and integration).

## Goal

In the exported standalone HTML report, excluded observations are hidden and a dedicated section lists the active exclusion Automations with their match counts, so the report reader knows what was filtered and why.

Non-goals: interactive Automation editing in the report, tag Automations in the report section.

## Constraints

- Excluded observations are hidden from all report views (matrix, tables, findings, diagrams).
- A "Show exclusions" toggle in the report reveals excluded observations greyed out (same as in the live app).
- A dedicated "Exclusion Automations" section in the report lists each active exclusion Automation: label, condition (in natural language), number of matched observations, and the list of affected Zones.
- Tag Automations are NOT listed in this section (they are an auditor working tool, not an audit result).
- The report is standalone (offline, no CDN).

## Stages

### Stage 1: exclusion section
- Render the Automation list section in the report HTML: label, condition, match count, affected Zones.
- Excluded observations removed from all rendered views.
- EXCLUDED verdict displayed with its own color and tooltip.

### Stage 2: toggle
- JS toggle in the report to show/hide excluded observations (greyed out when shown).
- Toggle state persists in `localStorage` (with try/catch as usual).
