# PooleShield Project State

Version: 3.9.0

Current milestone: v3.9 adds local SQLite scan history so operators and future UI builds can track scan timestamps, final verdicts, profiles, baseline matches, and action-item counts without storing raw scanned file contents.

Completed: deterministic ChatGPT DAT archive pass, metadata rollup dashboard, read-only file/folder AV scanner, file AV review ledger, trusted hash baseline, baseline-aware file AV scan, local rule packs, archive-aware baseline merge, final scan summaries, CI safety checks, local configuration system, and named scan profiles.

Privacy boundary remains intact: raw logs, decoded DAT text, normalized event JSONL, local review evidence, raw scanned file contents, baseline JSON, local config JSON, local history SQLite DBs, and private Poole Math / Poole Manifold / Poole Defect Calculus IP are not included in privacy bundles or public repo commits.

Next: test v3.9 history-init/history-record/history-list and a config-driven baseline-aware scan with --record-history, then push v3.9 if clean.
