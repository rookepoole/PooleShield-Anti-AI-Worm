# PooleShield Project State

Version: 5.0.0

Current milestone: v5.0 adds the first portable Windows build path. The package now includes a portable launcher, PyInstaller build helper, build requirements, a PowerShell build script, and guide documentation while preserving the same defensive local-only boundary.

Completed: deterministic ChatGPT DAT archive pass, metadata rollup dashboard, read-only file/folder AV scanner, file AV review ledger, trusted hash baseline, baseline-aware file AV scan, local rule packs, archive-aware baseline merge, final scan summaries, CI safety checks, local configuration system, named scan profiles, local SQLite scan history, stable Engine API bridge, desktop UI prototype, Results UI, Baseline Manager UI, Rule Pack Editor UI, and portable Windows build planning/tooling.

Privacy boundary remains intact: raw logs, decoded DAT text, normalized event JSONL, local review evidence, raw scanned file contents, baseline JSON, local config JSON, local history SQLite DBs, local edited rule packs, local result bundles, portable build outputs, executables, and private Poole Math / Poole Manifold / Poole Defect Calculus IP are not included in privacy bundles or public repo commits.

Next: test v5.0 locally with pytest, repo safety check, privacy leak check, `desktop --status`, `portable-build --status`, `portable-build --dry-run`, `portable-build --write-spec`, and a CLI baseline-aware scan. Upload the generated v5.0 privacy bundle before pushing v5.0.
