# PooleShield v5.3.0

PooleShield is a privacy-first second-opinion defensive scanner for suspicious files, archives, scripts, AI-agent logs, exported chat/data bundles, and local workflow artifacts.

PooleShield is defensive only. It reads local artifacts, scores static/local risk signals, and writes review reports. It does **not** execute scanned content, follow links, send emails, delete files, quarantine files, kill processes, install drivers, or modify the scanned corpus.

## Latest public pre-release

PooleShield v5.2.1 is available as a public GitHub pre-release:

- Release: https://github.com/rookepoole/PooleShield-Anti-AI-Worm/releases/tag/v5.2.1
- Portable ZIP: PooleShieldPortable_v5.2.1.zip
- Windows installer: PooleShieldSetup_v5.2.1.exe
- Checksums: SHA256SUMS_v5.2.1.txt
- Public manifest: PUBLIC_RELEASE_MANIFEST_v5.2.1.json

This installer is not code-signed yet, so Windows SmartScreen may warn because the binary is unsigned/new. Verify the SHA256 checksums before running.

Expected SHA256 values:

- 7CF9E6978DFC929E72DC45A0E8828F7841250B43ADEEFB6352515469B5C41831  PooleShieldPortable_v5.2.1.zip
- D9CEEDCB7B109C04BA68C7CA875EABABF959AA245D7A74BCDC95F37E6CB5C3E6  PooleShieldSetup_v5.2.1.exe

## v5.3 milestone

v5.3 adds a safe corpus and benchmark harness for code testers:

```text
dataset_schema.py
pooleshield_benchmark.py
dataset_adapters/eicar_fixture_adapter.py
dataset_adapters/ember_adapter.py
dataset_adapters/sorel_adapter.py
SAFE_CORPUS_GUIDE.md
examples/safe_corpus/tiny_feature_dataset.jsonl
safe-corpus-status CLI command
safe-corpus-fixture CLI command
safe-corpus-benchmark CLI command
safe_corpus.status / safe_corpus.benchmark Engine API operations
```

This is not malware download support. It is the safe benchmark step: feature vectors, metadata, labels, hashes, and synthetic fixtures only.

## Quick local checks

```powershell
python -m pytest -q
python .\tools\repo_safety_check.py --root .
python .\tools\privacy_leak_check.py --root .
python .\pooleshield_operator.py desktop --status
python .\pooleshield_operator.py safe-corpus-benchmark --dataset .\examples\safe_corpus\tiny_feature_dataset.jsonl --output-dir .\out\safe_corpus_v5_3 --clean-output
```

## Safe corpus benchmark smoke test

```powershell
python .\pooleshield_operator.py safe-corpus-benchmark `
  --dataset .\examples\safe_corpus\tiny_feature_dataset.jsonl `
  --output-dir .\out\safe_corpus_v5_3 `
  --clean-output `
  --bundle-output `
  --privacy-bundle
```

Upload only the generated privacy bundle if you want review:

```text
out\safe_corpus_v5_3\pooleshield_results_bundle.zip
```

## Privacy rules

Privacy bundles exclude content-bearing/private files such as:

```text
normalized_events.jsonl
extracted_dat_text/
extracted_dat_content/
extracted_text_like/
review_evidence_local.md
review_evidence_report.json
trusted_file_baseline.json
pooleshield_config.json
local_history/*.sqlite
installer_output/
build/
dist/
release_manifest_response.json
release_notes_draft.md
```

The file AV scanner does not include raw file contents or matched snippets in its reports.
