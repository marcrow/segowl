# Automations UI: hybrid editor with autocomplete

Status: ready-for-agent

Vocabulary: `GLOSSARY.md` (Automation). Depends on: `automations/` (engine).

## Goal

A page in the web app to create, edit, delete and test Automations. Hybrid mode: a visual builder for simple conditions (dropdowns for field/operator/value, AND/OR buttons) and a text mode for complex expressions, with autocomplete.

Non-goals: drag-and-drop grouping, visual rule chaining.

## Constraints

- Autocomplete suggests: field names, operators, Zone names (from inventory), Machine names, existing Machine Tags, port numbers (common ports from Port Labels).
- The visual builder generates the text condition; switching to text mode shows it editable; switching back parses it (or warns if unparsable by the visual builder).
- Parentheses for grouping (not brackets — AZERTY keyboard).
- UX validated by prototype before implementation (follow-the-process).

## Stages

### Stage 1: prototype
- Throwaway HTML mockup of the Automations page: list of Automations, add/edit modal with the hybrid editor, autocomplete, test button.

### Stage 2: implementation
- Automations page in the app navigation.
- CRUD on `automations.ini` via the app API.
- Autocomplete backed by inventory data (Zones, Machines, Tags) and Port Labels.
- Test button: run the condition against current Scan results, show how many observations match and which Machines are affected.
- Warning display for `state = open` exclusions.
