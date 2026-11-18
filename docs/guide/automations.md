# Automations

Condition → action entries that run after each Scan import. Two actions: **Tag** derives a Machine Tag from
results, **Exclude** removes matching observations from the analysis.

**Automations** sits between Scans and Flow Policy in the menu: the results feed the Automations, and the
Automations clean the data before the Policy judges it.

## Why Automations

### Progressive scanning with Tags

A broad first Scan rarely tells the auditor which ports deserve a closer look on which Machines. Automations
close the gap: they read the Scan results, tag Machines by what was observed, and the second Scan targets only
the tagged Machines with the right ports.

**Example: identify Windows Machines and scan deeper.**

| Step | What you do |
|---|---|
| 1. Broad sweep | Run a first profile across the whole inventory (e.g. top 1000 TCP with `-Pn`). |
| 2. Tag | Create a tag Automation: `(port = 3389 or port = 445 or port = 5985) and state = open` → tag `probably-windows`. |
| 3. Target | Create a "Windows deep" Scan Profile, targeting `tag = probably-windows`, with Windows-specific ports (WinRM, MSSQL, RPC ranges, SMB…). |
| 4. Second scan | Download the scripts: only the tagged Machines are in the target list. |

The same approach works for any family:

- `(port = 80 or port = 443 or port = 8080 or port = 8443) and state = open` → tag `web-server`, then
  scan all web ports and scripts.
- `(port = 623 or port = 17990) and state = open` → tag `oob`, then target the oob Zone with iLO/iDRAC
  ports.
- `state = open or state = closed` → tag `responded`: under `-Pn`, Machines that answered on at least one
  port, then target `responded` for a deeper pass rather than the whole range again.

!!! tip "OR between ports, AND with `has()`"
    A condition is tested against one port observation at a time. `port = 445 and port = 3389` is always
    false (one observation cannot be two ports). To tag Machines that have **either** port, use OR:
    `(port = 445 or port = 3389) and state = open`.

    To tag Machines that have **both** ports open, use `has()`:

    ```
    has(port = 445 and state = open) and has(port = 139 and state = open)
    ```

    `has(…)` means "the Machine has at least one observation that matches". It can be combined with
    per-observation terms: `has(…) and port = 80` matches port 80 observations only on Machines
    where the `has()` part is true.

### Suppress firewall noise with Exclude

Closed ports in an administration Zone that the client acknowledges? An entire Zone that is out of scope for
the audit? Exclude them: the matrix, the Findings and the verdicts update, and the noise no longer hides the
real Findings.

```
state = closed and zone = Admin        → exclude: closed ports in the Admin Zone
port = 161 and protocol = udp          → exclude: SNMP noise everywhere
```

**Example: suppress iLO firewall noise.**

A firewall sends a TCP reset on port 17988 (iLO HTTP) but filters 17990 (iLO HTTPS). The pattern
17988 closed + 17990 filtered is noise — `closed` on 17988 alone is not meaningful. One exclude
Automation handles it:

```
has(port = 17988 and state = closed) and has(port = 17990 and state = filtered) and (port = 17988 or port = 17990)
```

The two `has()` clauses select Machines with the iLO noise pattern. The `port = …` filter limits the
exclusion to 17988 and 17990 — other ports on the same Machine are not affected. A Machine that has only
17988 closed (without 17990 filtered) is not excluded.

!!! warning "Excluding open ports"
    Excluding `state = open` observations is allowed but SegOWL warns you: it hides Findings and Pivot
    Machines. The toggle **Show exclusions** (in the report) reveals what was masked, greyed out.

## Writing a condition

**Automations › New Automation**: name it, pick the action (tag or exclude), write the condition. Two modes:
**text** (type the expression, with syntax highlighting and autocomplete) and **visual** (clause builder for
simple conditions). **Test** shows how many observations match before you save.

### Fields

| Field | Values |
|---|---|
| `port` | 1–65535 |
| `state` | open, closed, filtered, unfiltered |
| `protocol` | tcp, udp |
| `zone` | Zone names from the inventory |
| `machine` | Machine names from the inventory |
| `tag` | Machine Tags (manual or derived from earlier tag Automations) |

### Operators

`=`, `!=`, `and`, `or`, parentheses. Names with spaces must be quoted: `zone = "Server Room"`.

### `has()` — machine-level condition

`has(…)` is true for a Machine when **any** of its observations matches the inner condition. Use it to
express AND between different ports:

```
has(port = 445 and state = open) and has(port = 3389 and state = open)
```

`has()` mixes with per-observation terms. Without `has()`, each comparison tests a single observation.

### Examples

```
(port = 3389 or port = 445 or port = 5985) and state = open
(port = 80 or port = 443) and state = open
state = closed and zone = Admin
port = 161 and protocol = udp
machine = "FW-01" and state = filtered
has(port = 445 and state = open) and has(port = 139 and state = open)
```

!!! tip "Add `state = open` for tagging"
    Without a state filter, `port = 3389` also matches filtered and closed observations, which under `-Pn`
    means every Machine that was tested. Write `(port = 3389 or port = 445) and state = open` to tag only
    Machines that actually serve those ports.

## How it runs

1. **Tag** Automations run first, in order. Each one sees the derived tags of the previous ones (**chaining**).
   Any matching observation gives the Machine the derived tag.
2. **Exclude** Automations run second. They see all derived tags. Matched observations are removed from the
   analysis.
3. Verdicts are recomputed: a Source → Interface pair with all observations excluded becomes EXCLUDED; a host
   that answered discovery with all ports excluded becomes ALIVE.

Automations run automatically on every file change (lazy regeneration, like the report). **Re-apply all**
forces a full recomputation.

## The file

`automations.ini` in the Mission folder, one section per Automation:

```ini
[web-servers]
action = tag
tag = web-server
condition = port = 80 or port = 443

[firewall-noise-admin]
action = exclude
condition = state = closed and zone = Admin
```

Editable by hand or in the app: they stay in sync.

## In the Auditor Kit

An Automation is **portable** when its condition uses only `port`, `state`, `protocol` and `tag` — never a
Zone or Machine name (those are client data). Portable Automations travel in the Kit and are proposed at
activation. See [Auditor Kit](auditor-kit.md#kits).
