# Exclusion toggle in the report

Status: done
Blocked by: 01
Spec: ../spec.md
Type: task

## What

- JS button "Show exclusions" / "Hide exclusions" in the report toolbar.
- When shown: excluded observations appear greyed out (opacity + strikethrough or muted color) in all tables.
- Matrix cells: excluded-only cells show the EXCLUDED badge greyed when toggle is on.
- Toggle state persists in `localStorage` (try/catch, default: hidden).
- Same toggle works in the live app views.

## Acceptance

- toggle on: excluded rows visible but visually distinct; toggle off: rows hidden
- works in standalone report.html (offline, no server)
- localStorage failure: defaults to hidden, no error
