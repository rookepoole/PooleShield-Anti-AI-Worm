# PooleShield Roadmap

## Current release: v5.2.1

PooleShield now has a stable Engine API, a local desktop prototype, and a first metadata-only Results UI for operator review.

## Completed through v5.2.1

- v3.6: CI safety checks and repo privacy guardrails.
- v3.7: local configuration system.
- v3.8: named scan profiles.
- v3.9: local metadata-only SQLite scan history.
- v4.0: Engine API and JSON request/response bridge.
- v4.1: desktop UI prototype using PySide6 / Qt.
- v5.2.1: Results UI with metadata table, filters, detail panel, and privacy-bundle path workflow.

## Next: v5.2.1 Baseline Manager UI

Focus the next release on managing trusted baseline entries safely inside the desktop app:

- view trusted files
- view trusted archives
- trust selected item
- remove trust
- import/export baseline
- baseline diff
- archive entry trust controls
- show baseline as local/private only

## Later

- v5.2.1: rule pack editor
- v5.2.1: portable Windows build
- v5.2.1: installer
- v5.2: signed release
- v5.3: polished Windows app

Safety boundary remains read-only by default. No execution, deletion, automatic quarantine, process killing, hooks, drivers, or raw private upload by default.
