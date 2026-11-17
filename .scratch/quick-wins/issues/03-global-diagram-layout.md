# Global diagram layout improvement

Status: wontfix
Blocked by: –
Spec: ../spec.md
Type: task

## What

Test `cose` (Cytoscape.js force-directed layout) as a replacement for the `circle` layout in the global zone → zone diagram. The circle layout spreads zones too far apart with 10+ zones.

Steps:
1. In `report_graph.js`, switch the global view layout from `circle` to `cose` with reasonable defaults.
2. Test with the demo Mission and with a ~10 zone inventory.
3. If `cose` clusters connected zones closer and improves readability, keep it.
4. Keep zoom/pan interaction and `cy.fit()` after layout.
5. Per-source diagrams keep their current layout (the options panel already lets the auditor choose).

## Acceptance

- with 10 zones, the global diagram is more compact and connected zones are visually grouped
- diagram still interactive (zoom, pan, click)
- no regression on small (3-4 zone) Missions

## Answer

Tested `cose` with the demo (5 zones): the force-directed layout compresses zones too tightly and makes the diagram less readable than the circle layout. Port tags and edges overlap. The circle layout spreads zones evenly and keeps the diagram legible at all sizes tested. Keeping `circle` as default.
