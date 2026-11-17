## Dev server

`uv run segowl serve <mission-folder> --port 8000`

## Web app UI patterns

CSS components (`.mback`, `.seg`, `.pill`, `.card`, `.btn`) and JS globals (`$`, `esc`, `api`, `toast`)
are defined in `segowl/assets/app.css` and `segowl/assets/app_common.js`.
Read both before writing a new page.

## Agent skills

### Issue tracker

Issues are tracked as local markdown files under `.scratch/<feature>/`. See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `GLOSSARY.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.
