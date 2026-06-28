# PooleShield Project State

Version: 3.4.2

Current milestone: v3.4.2 adds merge-safe trusted baseline building so newly reviewed files and archive entries can be added without replacing an existing local baseline.

Completed: deterministic ChatGPT DAT archive pass, metadata rollup dashboard, read-only file/folder AV scanner, file AV review ledger, trusted hash baseline, baseline-aware file AV scan, and local rule packs.

Privacy boundary remains intact: raw logs, decoded DAT text, normalized event JSONL, local review evidence, raw scanned file contents, baseline JSON, and private Poole Math / Poole Manifold / Poole Defect Calculus IP are not included in privacy bundles.

Next: test archive baseline merge on the real-small rule-pack scan, then push v3.4.2 if clean.
