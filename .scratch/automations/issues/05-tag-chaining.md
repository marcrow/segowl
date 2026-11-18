# Machine-level conditions: `has()` and tag chaining

Status: resolved
Blocked by: —
Spec: ../spec.md
Type: task

## Problem

The condition engine evaluates per-observation (one port at a time). There is no
way to express "machine has port A in state X **and** port B in state Y" because
one observation cannot match two different ports.

User examples:

1. **Tag machines with 445 open AND 139 open** (→ tag `windows`).
2. **Exclude observations on machines that have 17988 closed AND 17990 filtered**
   (iLO firewall noise: the closed on 17988 is a reset from the firewall, not a
   real service; the proof is that 17990 is filtered, not closed).

## Solution: `has()` + tag chaining

### `has()` — machine-level predicate

`has(inner)` is true for all observations of a Machine when any observation
matches `inner`. Mixes with per-observation terms.

Example 1 — one automation:
```
has(port = 445 and state = open) and has(port = 139 and state = open)  → tag windows
```

Example 2 — one automation:
```
has(port = 17988 and state = closed) and has(port = 17990 and state = filtered) and (port = 17988 or port = 17990)  → exclude
```

The port filter limits which observations get excluded; without it, all
observations of matching machines would be excluded (tags/has() are
per-machine, present on every observation).

### Tag chaining

Derived tags propagate after each tag Automation, so subsequent Automations
(tag or exclude) see them. Order in `automations.ini` = execution order.
Useful when `has()` is not needed or for building tag hierarchies.

## Resolved questions

**Q1 (exclude scope):** the user wants to exclude primarily 17988 (firewall
artifact) and 17990 along with it. The port filter in the condition controls
scope — no engine change needed.

**Q2 (cross-source):** tags aggregate per Machine across all Sources. Confirmed
by user.

**Q3 (grouped ports):** accepted limitation. If nmap groups a port into "N
closed ports", `port = X` misses it (`port=0` sentinel). In practice, nmap
lists individually the ports from the requested set.

## What changed

- `segowl/automations.py`: `_HasNode`, `_BoundPred`, parser `has()` support,
  `run_automations()` chaining + bind
- `segowl/app.py`: `test_automation` binds has-nodes, `automation_context`
  includes derived tag names in autocomplete
- `segowl/assets/automations.html`: syntax highlighting and autocomplete for `has(`
- `tests/test_automations.py`: `test_has_parses`, `test_has_tag_automation`,
  `test_has_exclude`, `test_tag_chaining`, `test_derived_tag_in_exclude`
- `.scratch/automations/spec.md`: rules 6 (chaining) and 7 (has)
- `docs/guide/automations.md`: `has()` section, iLO example, updated tips
- `GLOSSARY.md`: Automation entry updated
