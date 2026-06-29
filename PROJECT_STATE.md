# PooleShield Project State

Version: 3.6.2

Current milestone: v3.6.2 updates GitHub Actions to current Node-24-compatible major versions while preserving the v3.6 CI safety checks and v3.6.1 pytest bootstrap fix.

Completed: deterministic ChatGPT DAT archive pass, metadata rollup dashboard, read-only file/folder AV scanner, file AV review ledger, trusted hash baseline, baseline-aware file AV scan, local rule packs, archive-aware baseline merge, final scan summaries, CI safety checks, and GitHub Actions dependency bootstrap.

Privacy boundary remains intact: raw logs, decoded DAT text, normalized event JSONL, local review evidence, raw scanned file contents, baseline JSON, and private Poole Math / Poole Manifold / Poole Defect Calculus IP are not included in privacy bundles or public repo commits.

Next: push v3.6.2 and confirm CI passes without the Node 20 deprecation warning, then begin v3.7 configuration system.
