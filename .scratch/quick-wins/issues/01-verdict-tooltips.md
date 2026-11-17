# Verdict tooltips on detail view badges

Status: done
Blocked by: –
Spec: ../spec.md
Type: task

## What

Add `title` attribute to the `_vb()` verdict badge in `render/html.py` with a one-line glossary definition per verdict. Five-line dict, one-line template change.

## Acceptance

- hover over a verdict badge in per-source or per-target detail: tooltip shows the definition
- UNSEEN, BLOCKED and ALIVE tooltips help a first-time reader

## Answer

`VERDICT_TIP` dict added to `render/html.py`; `_vb()` now emits a `title` attribute on every verdict badge. All three call sites (per-source, per-target, all-targets via `_flow_row`) go through `_vb`, so one change covers everything.
