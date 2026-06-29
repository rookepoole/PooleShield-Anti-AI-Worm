# PooleShield v5.2.0

PooleShield is a privacy-first second-opinion defensive scanner for suspicious files, archives, scripts, AI-agent logs, exported chat/data bundles, and local workflow artifacts.

PooleShield is defensive only. It reads local artifacts, scores static/local risk signals, and writes review reports. It does **not** execute scanned content, follow links, send emails, delete files, quarantine files, kill processes, install drivers, or modify the scanned corpus.

## v5.2 milestone

v5.2 adds release packaging and integrity-manifest tooling for already-built local release artifacts:

```text
release_manifest.py
RELEASE_PACKAGING_GUIDE.md
release-manifest CLI command
release.status / release.manifest Engine API operations
SHA256 checksum generation
release notes draft generation
```

This is not a new detection feature. It is the clean release step after the verified v5.0 portable build, v5.1 installer tooling, v5.1.1 installer patch, and installer install/uninstall smoke test.

## Quick local checks

```powershell
python -m pytest -q
python .\tools\repo_safety_check.py --root .
python .\tools\privacy_leak_check.py --root .
python .\pooleshield_operator.py desktop --status
python .\pooleshield_operator.py release-manifest --help
```

## Release manifest smoke test

```powershell
python .\pooleshield_operator.py release-manifest `
  --release-version 5.2.0 `
  --portable-dir C:\Users\rookp\Desktop\PooleShieldPortable_v5_0_RELEASE `
  --installer-path C:\path\to\PooleShieldSetup.exe `
  --output .\release_manifest_response.json `
  --notes-output .\release_notes_draft.md
```

Do not commit release manifests, release notes drafts, installer outputs, build folders, generated scripts, result bundles, local configs, baselines, or history databases unless intentionally curated later.

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
