# Condition parser

Status: ready-for-agent
Blocked by: –
Spec: ../spec.md
Type: task

## What

Recursive-descent parser for the Automation condition language. Whitelist of fields (`port`, `state`, `protocol`, `zone`, `machine`, `tag`) and operators (`=`, `!=`, `and`, `or`, parentheses).

Security: no `eval`, no arbitrary code. Max condition length 500 chars, max nesting depth 4. Values with spaces must be quoted. `html.escape` on any value rendered in the report.

Returns a predicate function: `(port, state, protocol, zone, machine, tags) -> bool`.

## Acceptance

- parses all examples from the spec
- rejects: `; drop table`, `__import__`, unquoted spaces, unknown fields, depth > 4
- `port = 80 and port = 443` is always false (documents the edge case)
