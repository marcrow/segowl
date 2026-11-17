# Quick wins: verdict tooltips, scan file links, global diagram layout

Status: resolved

Vocabulary: `GLOSSARY.md` (Verdict, Scan). No dependencies on other features.

## 1. Verdict tooltips in detail views

The `_vb()` badge renders verdicts (OPEN, REACHABLE, ALIVE, BLOCKED, UNSEEN) with no explanation. Add a `title` attribute with a one-line definition from the glossary.

```python
VERDICT_TIP = {
    OPEN: "At least one open port: a service is reachable",
    REACH: "No open port but a closed port answered (RST): L4 flow crosses",
    ALIVE: "Answers ping/ARP but no port gets through — scan deeper",
    BLOCK: "No answer to discovery, or only filtered ports",
    NODATA: "This Interface was not in the Scan output",
}
```

Applies to: per-source tables, per-target tables, all-targets. The matrix already has its own legend.

## 2. Scan file links in detail views

Scan names are plain text in `_source_table_html()`, `_port_detail()` and `_scans_tab()`. Make them clickable links to the raw scan file served by the app.

- New route: serve the `scans/` directory via `_static()` (path traversal guard already exists).
- Link priority when multiple formats exist for the same Scan: `.nmap` > `.gnmap` > `.xml`.
- Serve as `text/plain` with `X-Content-Type-Options: nosniff` (scan content is attacker-influenced).
- In the standalone `report.html` (no server): links are omitted (no server to serve files from). The report already works offline; scan file links are an app-only feature.

## 3. Global diagram layout

The global zone → zone diagram uses a `circle` layout with radius `Math.max(200, n * 62)`. With 10+ zones the diagram is too spread out.

- Test `cose` (force-directed) as an alternative: it clusters connected zones closer.
- If `cose` works better, make it the default for the global view (per-source views keep their current layout with the options panel).
- Keep the existing zoom/pan interaction.
