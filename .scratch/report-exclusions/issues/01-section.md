# Exclusion Automations section in the report

Status: ready-for-agent
Blocked by: –
Spec: ../spec.md
Type: task

## What

- New section in the report HTML: "Exclusion Automations". Lists each active exclusion with label, condition (human-readable), observation count, affected Zones.
- Excluded observations removed from: matrix cells, per-source tables, per-target tables, Findings, Pivot Machines, diagrams, exports.
- EXCLUDED verdict: own CSS class, color, and tooltip ("Every port observation was removed by Automations").
- `html.escape` on all Automation labels and conditions rendered in the report.

## Acceptance

- report with an active exclusion: the section appears, counts are correct
- matrix cell reflects the post-exclusion verdict
- Findings list does not include flows masked by exclusions
