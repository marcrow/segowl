# Automations: condition → action engine for post-scan processing

Status: ready-for-agent

Vocabulary: `GLOSSARY.md` (Automation, Machine Tag, Exclusion, EXCLUDED verdict, Auditor Kit).

## Goal

Let the auditor create persistent condition → action entries that run automatically after each Scan import. Two action types: **tag** (compute a derived Machine Tag from Scan results) and **exclude** (remove matching port observations from the analysis, to suppress firewall noise or acknowledged flows).

Non-goals: automating Scan launches, modifying the inventory file, complex scripting.

## Constraints

- Stored in `automations.ini` (stdlib `configparser`), one section per Automation.
- Security: the condition parser is a whitelist — only known fields, only known operators (`=`, `!=`, `and`, `or`, parentheses). No `eval`, no string interpolation. Field names and operators are validated. Values are validated against inventory data where applicable. Max condition length: 500 chars. Max nesting depth: 4. Names with spaces must be quoted (`zone = "Server Room"`).
- Tag charset: `[a-z0-9_-]`, same as manual Machine Tags.
- Zero runtime dependency: parser is a hand-written recursive descent (~100 lines).

## File format

```ini
[web-servers]
action = tag
tag = web_server
condition = port = 80 or port = 443

[firewall-noise-admin]
action = exclude
condition = state = closed and zone = Admin

[windows-machines]
action = tag
tag = windows
condition = port = 3389 and state = open
```

## Condition language

### Fields

| Field      | Type   | Values / source                       |
|------------|--------|---------------------------------------|
| `port`     | int    | 1–65535                               |
| `state`    | enum   | open, closed, filtered, unfiltered    |
| `protocol` | enum   | tcp, udp                              |
| `zone`     | string | Zone names from inventory             |
| `machine`  | string | Machine names from inventory          |
| `tag`      | string | Machine Tags (manual or derived)      |

Extensible: `service` will be added when the scan-services feature lands.

### Operators

`=`, `!=`, `and`, `or`, parentheses for grouping. Parentheses preferred over brackets (AZERTY keyboard).

### Examples

```
state = closed and zone = Admin
(port = 80 or port = 443) and state = open
port = 22 and state = closed and machine = "FW-01"
state = closed and port = 161 and protocol = udp
```

## Evaluation model

1. A condition is tested against one **observation**: a (Source, Interface, protocol, port, state) tuple from a Scan.
2. Tag Automations run first on raw observations. If any observation of a Machine matches, the Machine gets the derived tag. So `port = 80 or port = 443` means "Machine has an open/closed/filtered port 80 OR port 443" (the OR is across observations, not within one).
3. Exclusion Automations run after tag Automations. An excluded observation is removed from the analysis.
4. Verdicts are recomputed after exclusions. If all observations of a Source → Interface pair are excluded, the verdict is EXCLUDED. If a host answered discovery and all its ports are excluded, the verdict is ALIVE (discovery is not a port observation).
5. Exclusions on `state = open` are allowed but trigger a warning: "this Automation masks N Findings and M Pivot Machines".
6. Tag Automations are **chained**: a derived tag from one Automation is visible to subsequent Automations (order in `automations.ini` matters). Derived tags are also visible to exclusion Automations.
7. `has(…)` is a machine-level predicate: true for all observations of a Machine when any of its observations matches the inner condition. Enables multi-port AND conditions (e.g. `has(port = 445 and state = open) and has(port = 139 and state = open)`).
7. Exclusions propagate everywhere: matrix, per-source, per-target, Findings, Diff, exports.

## Execution

- Automations run automatically whenever the analysis is computed (lazy regeneration on file change, same as the report).
- "Re-apply all" button in the UI forces a full recomputation (useful after adding an Automation to an existing Mission).
- Derived tags are computed in memory, never written to `inventory.csv`.

## Kit integration

An Automation is portable when its condition uses only `port`, `state`, `protocol` and `tag` (no `zone`, `machine`). The Kit's `automations.ini` holds only portable Automations. At Kit activation in a Mission, portable Automations are copied into the Mission's `automations.ini` (the auditor picks which ones).

## Stages

### Stage 1: parser and engine
- Condition parser (recursive descent, whitelist, injection-safe).
- Evaluation against observations.
- Tag and exclude actions.
- `automations.ini` read/write via `configparser`.
- Verdict recomputation after exclusions, EXCLUDED verdict.
- Warning on `state = open` exclusions.
- Tests on the parser (edge cases, injection attempts, valid conditions).

### Stage 2: integration
- Wire into the analysis pipeline (after Scan parse, before verdict computation).
- Derived tags available in all views, report tables, exports.
- Exclusion toggle in all views (hidden by default, "Show exclusions" reveals them greyed out).

### Stage 3: Kit integration
- Portable Automation detection.
- Kit export/import of `automations.ini`.
- Activation picker in the Mission.
