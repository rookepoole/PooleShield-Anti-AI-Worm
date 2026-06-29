# PooleShield Project State

Version: 3.7.0

Current milestone: v3.7 adds a local configuration system so operators can keep baseline paths, rule-pack paths, output locations, risk profile, privacy bundle defaults, and scan limits in one validated JSON file.

Completed: deterministic ChatGPT DAT archive pass, metadata rollup dashboard, read-only file/folder AV scanner, file AV review ledger, trusted hash baseline, baseline-aware file AV scan, local rule packs, archive-aware baseline merge, final scan summaries, and CI safety checks.

Privacy boundary remains intact: raw logs, decoded DAT text, normalized event JSONL, local review evidence, raw scanned file contents, baseline JSON, local config JSON, and private Poole Math / Poole Manifold / Poole Defect Calculus IP are not included in privacy bundles or public repo commits.

Next: test v3.7 config-init/config-validate and a config-driven baseline-aware scan, then push v3.7 if clean.
