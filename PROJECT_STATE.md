# PooleShield Project State

Version: 5.1.1

Current milestone: v5.1.1 is a patch release for the Windows installer tooling. It fixes the v5.1 `installer-build --run-iscc --portable-dir ...` bug so the final Inno Setup compile step uses the operator-supplied portable folder instead of falling back to the default `dist/PooleShield` path.

Completed: deterministic ChatGPT DAT archive pass, metadata rollup dashboard, read-only file/folder AV scanner, file AV review ledger, trusted hash baseline, baseline-aware file AV scan, local rule packs, archive-aware baseline merge, final scan summaries, CI safety checks, local configuration system, named scan profiles, local SQLite scan history, stable Engine API bridge, desktop UI prototype, Results UI, Baseline Manager UI, Rule Pack Editor UI, portable Windows build path, verified portable runtime smoke test, Windows installer tooling, and the installer portable-dir patch.

Privacy boundary remains intact: raw logs, decoded DAT text, normalized event JSONL, local review evidence, raw scanned file contents, baseline JSON, local config JSON, local history SQLite DBs, local result bundles, local edited rule packs, installer outputs, portable build outputs, generated installer scripts, and private Poole Math / Poole Manifold / Poole Defect Calculus IP are not included in privacy bundles or public repo commits.

Next: test v5.1.1 locally with pytest, repo safety check, privacy leak check, installer-build status/dry-run/write-script, and an actual `--run-iscc --portable-dir` compile against `C:\Users\rookp\Desktop\PooleShieldPortable_v5_0_RELEASE`. Upload the metadata-only installer verification ZIP before pushing v5.1.1.
