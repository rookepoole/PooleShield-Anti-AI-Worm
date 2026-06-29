# PooleShield Roadmap

## Current release: v4.1

PooleShield now has a stable Engine API and a first local desktop UI prototype.

## Completed through v4.1

- v3.6: CI safety checks and repo privacy guardrails.
- v3.7: local configuration system.
- v3.8: named scan profiles.
- v3.9: local metadata-only SQLite scan history.
- v4.0: Engine API and JSON request/response bridge.
- v4.1: desktop UI prototype using PySide6 / Qt.

## Next: v4.2 Results UI

Focus the next release on making results review useful inside the desktop app:

- sortable results table
- filter by decision
- filter by risk label
- action-item view
- file detail panel
- hash display
- archive parent display
- baseline match indicator
- rule-pack match indicator
- export privacy bundle button

## Later

- v4.3: baseline manager UI
- v4.4: rule pack editor
- v5.0: portable Windows build
- v5.1: installer
- v5.2: signed release
- v5.3: polished Windows app

Safety boundary remains read-only by default. No execution, deletion, automatic quarantine, process killing, hooks, drivers, or raw private upload by default.
