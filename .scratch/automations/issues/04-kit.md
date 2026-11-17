# Kit integration for Automations

Status: ready-for-agent
Blocked by: 03
Spec: ../spec.md
Type: task

## What

- Detect portable Automations: condition uses only `port`, `state`, `protocol`, `tag` (no `zone`, `machine`).
- Kit export: copy portable Automations to the Kit's `automations.ini`.
- Kit activation: show available Automations from the Kit, let the auditor pick which ones to copy into the Mission's `automations.ini`.

## Acceptance

- an Automation with `zone = Admin` is not portable (rejected from Kit export)
- an Automation with `port = 3389 and state = open` is portable
- activating a Kit Automation copies it to the Mission file
