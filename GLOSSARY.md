# Segmentation testing

Measures, from network scans launched inside the perimeter, which flows are actually allowed between segments, so the auditor can judge whether the intended segmentation holds.

## Language

### Perimeter

**Mission**:
One segmentation audit for a client: its inventory, its Scans, its optional Flow Policy and its Port Groups. The unit that is archived, copied and compared.
_Avoid_: engagement, project, audit

**Zone**:
Network segment declared by the auditor in the inventory, representing a segmentation intent, not an observed VLAN or subnet. An administration tier (T0, T1…) or an environment (admin, iLO, monitoring) is expressed as a Zone.
_Avoid_: VLAN, subnet, segment, tier, environment

**Machine**:
What the inventory names: Interfaces with the same name are one Machine, whatever reality is. The auditor merges or splits Machines by renaming an Interface in the inventory; a name found elsewhere (DNS, a Scan) only proposes. An inventory filled with DNS names does not prove that two different names are two different devices: one device may carry one name per network.
_Avoid_: host, server, asset

**Interface**:
One IP of a Machine, attached to exactly one Zone. A Machine whose Interfaces sit in several Zones spans those Zones.
_Avoid_: alias, leg, secondary IP

**Flow Policy**:
The optional, auditor-supplied statement of which flows between Zones (and, by exception, Machines) are allowed or denied, possibly restricted to ports. Often absent: building it is time-consuming, and the tool must stay useful without it.
_Avoid_: rule, expected matrix, zone policy

**Undeclared Flow**:
Observed flow about which the Flow Policy says nothing. Shown apart, never a Finding.

### Scan

**Source**:
The IP the auditor scans from. It is declared before its first Scan, so a Source without a Scan is a gap in the Mission, unlike an Interface that was never meant to be scanned from. In practice it stands for its Machine, since system routing picks the outgoing Interface.
_Avoid_: pivot, origin, source host

**Scan Profile**:
Named, reusable recipe for a Scan: which ports (Port Groups, explicit ports, top-ports) and which nmap options. Carries no target: targets always come from the inventory, so a Scan Profile holds no client data. Exported as one ready-to-run command per Source, so every Source is scanned the same way.
_Avoid_: template, preset, scan config

**Port Label**:
Human description of a port (product, technology, vendor, whether it is cleartext) with descriptive tags (admin, backup, oob, risky…), used to find ports when building Port Groups and Scan Profiles. Purely descriptive: unlike a Port Group, it filters nothing and the Flow Policy cannot reference it.
_Avoid_: service, port category

**Machine Tag**:
Free-form label on a Machine, assigned by the auditor in the inventory (e.g. windows, admin, vmware). Used to group Machines for scan targeting and to express Automation conditions. A tag is manual when the auditor typed it, and derived when an Automation computed it from Scan results; derived tags are read-only and never written to the inventory file.
_Avoid_: label (overloaded with Port Label), category

**Auditor Kit**:
Named set of Port Groups, Scan Profiles, Port Labels and portable Automations that an auditor carries from Mission to Mission. Never contains client data (no inventory, no Flow Policy, no Scan, no IP). An Automation is portable when its condition references only ports, states, protocols and Machine Tags, never Zones or Machine names.
_Avoid_: library, settings, config

**Scan**:
One nmap run from a Source, against a set of targets and a set of ports. A Source may have several Scans (e.g. a broad sweep then a targeted follow-up with extra ports); they are combined into its Source View.
_Avoid_: campaign, run, job

**Coverage**:
What was actually tested from a Source towards an Interface: which ports, by which Scans. Distinguishes "tested and not seen" from "never tested".
_Avoid_: scope

**Source View**:
Everything a Source sees, combining all its Scans. When Scans disagree on a port, the most permissive state wins (an open port observed once proves the flow passed), and the disagreement stays visible to the auditor.

**Self**:
All the Interfaces of the Machine carrying the Source. They are excluded from its own Scans.

**Scan Diff**:
Comparison of what two Scans, or two Source Views, observed, either over time (same Source, before/after) or across Sources (what one sees that the other does not). A difference on a port only one side tested is not comparable.
_Avoid_: delta, comparison

### Verdict

Verdict of a Source → Interface pair, from most permissive to most closed:

**OPEN**:
At least one open port: a service is reachable.

**REACHABLE**:
No open port but at least one closed port (RST received), or unfiltered in an ACK Scan (-sA). An RST proves that a TCP stack answered at L4, but nmap cannot distinguish an RST from the target host from an RST sent by an inline firewall in REJECT mode; the auditor decides whether the flow genuinely crossed the segmentation.

**ALIVE**:
The Interface answers host discovery (ping, ARP) but no port gets through, whether filtered or not tested. A lead: scan its ports deeper, or conclude none is open. Counts as passing in the zone matrix (`~`), never as BLOCKED. Does not exist in a -Pn Scan.
_Avoid_: host up, joinable, ICMP reachable (nmap discovery also uses ARP and TCP probes)

**BLOCKED**:
The Interface did not answer host discovery, or, in -Pn, only filtered ports. In -Pn, this does not distinguish filtering from a powered-off or nonexistent Interface.

**UNSEEN**:
The Interface is absent from the Scan output.

**EXCLUDED**:
Every port observation of this Source → Interface pair was removed by Automations. Distinct from UNSEEN (never scanned) and BLOCKED (scanned, nothing answered): EXCLUDED means data existed but the auditor discarded all of it. Only appears when the auditor's own Automations removed every observation; when non-excluded ports remain, the verdict is recomputed from them normally (a host answering discovery with all ports excluded is ALIVE, not EXCLUDED).

### Automation

**Automation**:
A named, persistent condition → action entry stored in `automations.ini`. The condition is a boolean expression over observation fields (port, state, protocol, Zone, Machine, Machine Tag). Two action types: **tag** (compute a derived Machine Tag) and **exclude** (remove matching port observations from the analysis). Tag Automations run first, in order, and are **chained**: each one sees the derived tags of the ones above it. Exclusion Automations run second and see all derived tags. An Automation whose condition references only ports, states, protocols and Machine Tags (no Zone or Machine name) is portable and may live in the Auditor Kit.
_Avoid_: rule (see Flow Policy), filter

### Result

**Finding**:
Observed flow that the Flow Policy explicitly denies. Without a Flow Policy there are no Findings: the auditor reads the views.
_Avoid_: vulnerability, violation

**Pivot Machine**:
A Machine spanning at least two Zones that a Source reaches with an OPEN verdict: whoever holds it rebounds from the Source's Zone into the Machine's other Zones. Only the Machines the inventory declares are found: a device known under two names is missed, so the list is never exhaustive.
_Avoid_: bastion, jump host, bridge

**Port Group**:
Named set of ports (e.g. admin, db, web) used to filter and highlight flows, and to express the Flow Policy.
_Avoid_: service class, port list
