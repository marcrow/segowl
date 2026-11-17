# Global diagram layout improvement

Status: resolved
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

Circle seed + cose refinement in `report_graph.js`. The circle layout runs first (deterministic seed), then cose (`randomize: false, animate: false`) clusters connected zones closer. Guard `if (n > 1)` skips cose for single-zone views. `idealEdgeLength: 200` leaves room for port tags.
