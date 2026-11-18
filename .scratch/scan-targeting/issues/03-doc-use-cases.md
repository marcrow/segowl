# Doc: scan targeting use cases

Status: done
Blocked by: –
Spec: ../spec.md
Type: task

## What

Add a section in the user guide (docs/guide/) explaining the scan targeting feature
and its use cases. The section should cover:

### Use case 1: zone-specific profiles
Create a profile per zone when you know the zone's specifics up front.
Example: an "iLO sweep" profile targeting only the iLO zone with iLO-specific ports
(623, 443, 17990), while a "broad-tcp" profile targets all zones.

### Use case 2: second-pass scans after discovery
After a first discovery scan, tag interesting machines (manually or via Automations),
then create a targeted profile for the second pass.
Example: discovery scan finds admin interfaces → tag them `ilo` or `admin` →
create an "admin-deep" profile targeting `tag=admin` with deeper ports/options.

### Use case 3: focused full scans via tags
Use Automations to tag machines based on scan results (e.g. `windows`, `linux`,
`web-server`), then create full-scan profiles targeting those tags.
Example: Automation tags machines with open 3389 as `windows` →
"windows-full" profile targets `tag=windows` with Windows-specific ports and scripts.

## Acceptance

- the guide has a "Scan Targeting" section explaining the feature and the 3 use cases
- each use case shows a concrete example with zone/tag/profile names
