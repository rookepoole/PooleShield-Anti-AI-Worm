# PooleShield Project State

Version: 5.3.0

Current milestone: v5.3 adds a Safe Corpus + Benchmark Harness for code testers. It supports metadata/features-only benchmark records, safe synthetic fixtures, EICAR-style markers without the canonical EICAR string, and adapters for EMBER/SOREL-style feature JSONL rows.

Completed: deterministic ChatGPT DAT archive pass, metadata rollup dashboard, read-only file/folder AV scanner, file AV review ledger, trusted hash baseline, baseline-aware file AV scan, local rule packs, archive-aware baseline merge, final scan summaries, CI safety checks, local configuration system, named scan profiles, local SQLite scan history, stable Engine API bridge, desktop UI prototype, Results UI, Baseline Manager UI, Rule Pack Editor UI, portable Windows build path, installer tooling and installer install/uninstall smoke, release packaging/integrity manifest, public v5.2.1 pre-release, and README public release links.

Privacy boundary remains intact: raw logs, decoded DAT text, normalized event JSONL, local review evidence, raw scanned file contents, baseline JSON, local config JSON, local history SQLite DBs, local result bundles, local edited rule packs, installer outputs, portable build outputs, generated installer scripts, generated release manifests, and private Poole Math / Poole Manifold / Poole Defect Calculus IP are not included in privacy bundles or public repo commits.

Next: test v5.3 locally with pytest, repo safety check, privacy leak check, safe-corpus-status, and safe-corpus-benchmark against `examples/safe_corpus/tiny_feature_dataset.jsonl`. Upload the metadata-only/privacy-safe benchmark bundle before pushing v5.3.
