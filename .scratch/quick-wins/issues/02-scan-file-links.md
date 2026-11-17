# Clickable scan file links in detail views

Status: done
Blocked by: –
Spec: ../spec.md
Type: task

## What

- New route in `app.py` to serve files from the `scans/` directory (reuse `_static()`, path traversal guard).
- Serve with `Content-Type: text/plain` and `X-Content-Type-Options: nosniff` (scan content is attacker-influenced).
- Turn scan name text into `<a href>` in `_source_table_html()`, `_port_detail()` and `_scans_tab()`.
- Link priority: when a Scan has multiple file formats, prefer `.nmap` > `.gnmap` > `.xml`.
- In standalone `report.html`: no links (no server). The link rendering is app-only.

## Acceptance

- click a scan name in per-source detail: browser opens the `.nmap` file as text
- `.xml` file also viewable when no `.nmap` exists
- path traversal attempt (`../../etc/passwd`) returns 404
- standalone report.html: scan names remain plain text, no broken links

## Answer

- `_scan_name()` helper in `render/html.py` emits `<span class="scan-name" data-scan="stem">` on all three sites.
- `report.js` activates links when `window.self !== window.top` (embedded in the app iframe).
- `_scan_file()` route in `app.py` resolves stem to `.nmap` > `.gnmap` > `.xml`, serves as `text/plain`. Path traversal guard reuses the same `is_relative_to` pattern.
- Test: `test_scan_file_route_serves_text_and_blocks_traversal`.
