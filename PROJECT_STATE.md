# PooleShield Project State

Version: 4.0.0

Current milestone: v4.0 adds a UI-ready Engine API layer so config, scan profiles, scan history, rule-pack validation, and baseline-aware file AV scans can be called from Python functions or a JSON request/response bridge instead of being coupled only to the CLI.

Completed: deterministic ChatGPT DAT archive pass, metadata rollup dashboard, read-only file/folder AV scanner, file AV review ledger, trusted hash baseline, baseline-aware file AV scan, local rule packs, archive-aware baseline merge, final scan summaries, CI safety checks, local configuration system, named scan profiles, local SQLite scan history, and the first stable Engine API bridge.

Privacy boundary remains intact: raw logs, decoded DAT text, normalized event JSONL, local review evidence, raw scanned file contents, baseline JSON, local config JSON, local history SQLite DBs, and private Poole Math / Poole Manifold / Poole Defect Calculus IP are not included in privacy bundles or public repo commits.

Next: test v4.0 locally with pytest, repo safety check, `engine-dispatch`, and a config-driven baseline-aware scan through the Engine API. If clean, push v4.0. After v4.0, begin v4.1 desktop UI prototype planning.
