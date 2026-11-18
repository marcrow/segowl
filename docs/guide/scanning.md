# Scanning from each Source

A **Source** is the IP you scan from. Every Source runs the same profile against the inventory minus its own
Machine (**Self**), optionally filtered by [scan targeting](#scan-targeting).

![Several Sources fanning out over the whole inventory](../img/tutorial/several-sources.svg)

## Build the scan

**Scans › Build the scan**: pick a Scan Profile of your kit, adjust it for this Mission, and the exact nmap
command is shown live.

![The scan builder](../img/scans.png)

- **Ports**: tick Port Groups, add nmap top ports, or search ports by product, tag or vendor (`veeam`, `oob`,
  `ldap`, `udp:161`…) in the Port Labels and the IANA registry.
- **Options**: each nmap option explained (SYN or connect, `-Pn`, timing, retries, rates, `-sV`, NSE scripts).
- **Commands for Source**: targets come from the inventory, minus the Source's Machine. With targeting, only
  the matching subset.

Then download **one script per Source** and run it there.

## Scan targeting

A Scan Profile can target a subset of the inventory instead of everything, using **Zones** and **Machine
Tags** as filters. The targeting section sits below Ports and Options in the profile editor.

- **Zone checkboxes**: tick the Zones to include.
- **Tag checkboxes**: tick the Machine Tags (manual or derived) to include.
- **AND / OR toggle**: AND = Machines in a ticked Zone **and** carrying a ticked tag. OR = Machines in a
  ticked Zone **or** carrying a ticked tag. Default: AND.
- Untouched (all Zones checked, no tags): the whole inventory, same as before.

The filter applies to the scripts and to the zip export. Each profile carries its own targeting
(`scan_targeting.csv` in the Mission folder), so "Broad TCP" can target everything while "Windows deep"
targets only `tag = probably-windows`. Targeting is per Mission (Zones and tags are client data): it does
not travel in a Kit.

### Use cases

**Zone-specific profile**: an "iLO sweep" profile targeting only the iLO Zone with iLO-specific ports (623,
17990), while "Broad TCP" keeps the whole inventory.

**Tag-driven second pass**: after a first sweep, an Automation tags Machines from results (e.g.
`probably-windows`), and a "Windows deep" profile targets `tag = probably-windows` with Windows ports. See
[Automations: progressive scanning](automations.md#progressive-scanning-with-tags).

**Manual tag**: tag admin jump hosts `admin` by hand in the inventory, then create an "Admin deep" profile
targeting `tag = admin` with admin-specific ports and scripts.

## Run on site, drop the results

Results go in `scans/<source_ip>/`, any file name. In the app, drop the `.xml` / `.gnmap` / `.nmap` on the
Source's row: the views regenerate. By hand:

```bash
mkdir -p mission/scans/$SRC_IP && cd mission/scans/$SRC_IP
nmap -Pn -p- -oA broad <targets>          # through proxychains/SOCKS if pivoting
nmap -Pn -p 8443,9200 -oA follow-up <ip>  # any later follow-up, any parameters
```

A Source may have **any number of Scans**: they combine into its **Source View**. The most permissive state of
a port wins (an open port seen once proves the flow passed), and disagreements stay visible
([ADR 0001](../adr/0001-source-view-most-permissive-wins.md)).

## Good scans make good views

!!! tip "Keep the XML"
    XML is the reference format, the only one telling which ports were tested (**Coverage**): "tested and
    not seen" versus "never tested". For one scan written in several formats (`-oA`), xml > gnmap > nmap.

!!! warning "Avoid `--open`"
    Closed ports are what reveals a flow that crosses the segmentation (REACHABLE). `--open` throws them away.

!!! tip "Prefer `-Pn`"
    `-Pn` is auto-detected from the nmap header (or forced with `--pn`). Blocked targets then show as
    `filtered`, so BLOCKED, instead of being absent. Without it, hosts dropping ping are never port-scanned.

- `--top-ports N` works: nmap writes the expanded port list in the XML.
- The Interfaces of the Source's own Machine are always removed from its results: a machine scanning itself
  shows many "open" ports that would skew the matrix.

## Take a Scan out

Move its file into a sub-folder of the Source's folder, e.g. `scans/<source_ip>/excluded/`: it is no longer
read, only listed as excluded. Useful for a Scan that conflicts with the others (see the Conflicts table of the
Scans tab). In the app, scan names in the report are clickable: they open the raw scan file
(`.nmap` preferred, then `.gnmap`, then `.xml`) as plain text. The standalone `report.html` has no server, so scan names stay plain text there.

A Source folder that is not an inventory IP is **ignored** and listed in the terminal and the Anomalies tab.
The legacy layout `scans/<source_ip>.xml` is still accepted.
