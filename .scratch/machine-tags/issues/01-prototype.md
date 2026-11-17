# Prototype: tags in the inventory editor

Status: ready-for-human
Blocked by: –
Spec: ../spec.md
Type: prototype

## What

Throwaway HTML mockup showing: (1) the inventory grid with a tags column, (2) autocomplete on existing tags, (3) bulk tag assign on selected rows. Use the existing Tabulator setup from `prototype_app/` or the live inventory editor.

## Acceptance

- the user clicks through and validates the tag editing UX
- bulk operations feel natural (select rows, right-click or toolbar button, type tag)

## Implementation

Branch `prototype/machine-tags`. Run with `uv run segowl serve <mission>`, open `/inventory`.

**What's built:**
- Tags column appears on the first click of **Tag ▾** (or loads if the inventory already has a `tags` header)
- **Cell editor**: double-click (or single-click per the grid's cellClick handler) opens a custom editor with comma-separated input; a `<datalist>` autocompletes on the last token against all existing tags in the Mission
- **Tag chips**: tags render as pills in the cell (`.pill` class, `.badtok` for invalid charset)
- **Bulk apply / remove**: Tag ▾ opens a toolbar dropdown; type a tag and **+ Apply** or **− Remove** on the current selection
- **Machine sync**: editing tags on one Interface updates all Interfaces of the same Machine (via `syncMachineTags` on `cellEdited`, and in the bulk path)
- **Undo**: the undo bar tracks tag changes

**Known limits (prototype-only):**
- "Just type" fill, Ctrl+D, the fill handle and paste replace the whole cell without sync or validation — they skip the custom editor path. Acceptable for prototype, ticket 03 decides the UX.
- Storage uses `,` as separator in the editor; the spec says `;` in the CSV. Ticket 02 (data model) handles the wire format.
- No right-click context menu for bulk tag — only the toolbar.

## Comments

Verdict questions for the user:

1. ~~**Toolbar only, or also right-click?**~~ → **both** (implemented: right-click on tags cells opens a context menu with the same input + Apply/Remove)
2. ~~**Should the tags column always be visible?**~~ → **yes** (implemented: always visible)
3. ~~**Should "just type" on tag cells replace the cell or add a tag?**~~ → **add** (implemented: adds a tag + machine sync)
4. ~~**Auto-lowercase or flag?**~~ → **auto-lowercase** (implemented: editor normalise + bulk apply)
5. **Header tooltip added** — hover on "tags" shows help text
