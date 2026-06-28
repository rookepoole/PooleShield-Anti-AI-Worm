# PooleShield Project State

Version: 3.3.0

Current milestone: v3.3 adds a baseline-aware file AV scan command that runs a read-only file/folder scan and applies the local trusted hash baseline in one workflow.

Completed: deterministic ChatGPT DAT archive pass, v2.1.1 metadata rollup dashboard, v3.0.1 read-only file/folder AV scanner, v3.1 file AV review ledger, and v3.2 trusted hash baseline.

Privacy boundary remains intact: raw ChatGPT logs, decoded DAT text, normalized event JSONL, local review evidence, raw scanned file contents, baseline JSON, and private Poole Math / Poole Manifold / Poole Defect Calculus IP are not included in privacy bundles.

Next: test `file-av-scan-baseline` on the real-small folder, verify the privacy bundle, then push v3.3 if clean.
