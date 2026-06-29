# PooleShield Project State

Version: 4.3.0

Current milestone: v4.3 adds the first Baseline Manager UI layer on top of the v4.1 desktop prototype, v4.2 Results UI, and v4.0 Engine API. The desktop app now has Dashboard, Scan Folder, Results, Baseline, History, and About tabs. The Baseline tab loads metadata-only trusted-baseline entries, filters by decision/kind/search text, shows a details panel, copies SHA/path values, and compares two baseline JSON files by SHA256.

Completed: deterministic ChatGPT DAT archive pass, metadata rollup dashboard, read-only file/folder AV scanner, file AV review ledger, trusted hash baseline, baseline-aware file AV scan, local rule packs, archive-aware baseline merge, final scan summaries, CI safety checks, local configuration system, named scan profiles, local SQLite scan history, stable Engine API bridge, first desktop UI prototype, Results UI, and first Baseline Manager UI.

Privacy boundary remains intact: raw logs, decoded DAT text, normalized event JSONL, local review evidence, raw scanned file contents, baseline JSON, local config JSON, local history SQLite DBs, local result bundles, and private Poole Math / Poole Manifold / Poole Defect Calculus IP are not included in privacy bundles or public repo commits.

Next: test v4.3 locally with pytest, repo safety check, privacy leak check, `desktop --status`, `baseline-load`, `baseline-diff`, and a CLI or UI-launched baseline-aware scan. If clean, upload the generated v4.3 privacy bundle for verification before pushing v4.3. After v4.3, continue to v4.4 Rule Pack Editor UI.
