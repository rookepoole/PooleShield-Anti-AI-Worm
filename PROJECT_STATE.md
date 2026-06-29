# PooleShield Project State

Version: 3.8.0

Current milestone: v3.8 adds named file-AV scan profiles so operators can choose quick, standard, developer, strict, deep, archive-heavy, or privacy-sensitive scan behavior without manually tuning limits each time.

Completed: deterministic ChatGPT DAT archive pass, metadata rollup dashboard, read-only file/folder AV scanner, file AV review ledger, trusted hash baseline, baseline-aware file AV scan, local rule packs, archive-aware baseline merge, final scan summaries, CI safety checks, and local configuration system.

Privacy boundary remains intact: raw logs, decoded DAT text, normalized event JSONL, local review evidence, raw scanned file contents, baseline JSON, local config JSON, and private Poole Math / Poole Manifold / Poole Defect Calculus IP are not included in privacy bundles or public repo commits.

Next: test v3.8 scan profiles locally with profile-list/profile-show and a developer-profile config-driven baseline-aware scan, then push v3.8 if clean.
