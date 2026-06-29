# PooleShield Project State

Version: 3.6.0

Current milestone: v3.6 adds CI safety checks so the public GitHub repo fails builds if generated/private artifacts are accidentally committed.

Completed: deterministic ChatGPT DAT archive pass, metadata rollup dashboard, read-only file/folder AV scanner, file AV review ledger, trusted hash baseline, baseline-aware file AV scan, local rule packs, archive-aware baseline merge, and final scan summaries.

Privacy boundary remains intact: raw logs, decoded DAT text, normalized event JSONL, local review evidence, raw scanned file contents, baseline JSON, and private Poole Math / Poole Manifold / Poole Defect Calculus IP are not included in privacy bundles or public repo commits.

Next: run local CI safety checks, push v3.6 if clean, then begin v3.7 configuration system.
