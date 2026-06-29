# PooleShield Project State

Version: 5.1.0

Current milestone: v5.1 adds local Windows installer tooling on top of the verified v5.0 portable build. The installer helper can inspect a portable folder, generate a local Inno Setup script, produce a dry-run build plan, and optionally compile an installer only when the operator explicitly runs the compiler.

Completed: deterministic ChatGPT DAT archive pass, metadata rollup dashboard, read-only file/folder AV scanner, file AV review ledger, trusted hash baseline, baseline-aware file AV scan, local rule packs, archive-aware baseline merge, final scan summaries, CI safety checks, local configuration system, named scan profiles, local SQLite scan history, stable Engine API bridge, desktop UI prototype, Results UI, Baseline Manager UI, Rule Pack Editor UI, portable Windows build path, and verified portable runtime smoke test.

Privacy boundary remains intact: raw logs, decoded DAT text, normalized event JSONL, local review evidence, raw scanned file contents, baseline JSON, local config JSON, local history SQLite DBs, local result bundles, local edited rule packs, installer outputs, portable build outputs, and private Poole Math / Poole Manifold / Poole Defect Calculus IP are not included in privacy bundles or public repo commits.

Next: test v5.1 locally with pytest, repo safety check, privacy leak check, installer-build status/dry-run/write-script, and a baseline-aware scan. If clean, upload the generated v5.1 privacy bundle for verification before pushing v5.1. After v5.1, compile the actual installer locally and verify installer metadata before moving toward signed releases.
