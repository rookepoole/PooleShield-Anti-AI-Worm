# PooleShield v3.0.1

PooleShield is a privacy-first defensive scanner for AI-agent workflows, exported chat/log archives, prompt-injection propagation, and local file/folder antivirus triage.

PooleShield is defensive only. It reads local artifacts, scores static/local-geometry risk signals, and writes review reports. It does **not** execute scanned content, follow links, send emails, delete files, quarantine files, kill processes, install drivers, or modify the scanned corpus.

## v3.0.1 milestone

v3.0.1 adds a read-only second-opinion file/folder antivirus scanner:

```text
scan-file
scan-folder
scan-archive
av-scan
```

The scanner reports hashes, metadata, extension/magic mismatch, script risk, entropy risk, archive-entry risk, and dry-run quarantine recommendations.

## Quick AV test

```powershell
python .\pooleshield_operator.py scan-folder --path .\examples\file_av_fixture --output-dir .\out\file_av_demo --clean-output --bundle-output --privacy-bundle
```

Upload only:

```text
out\file_av_demo\pooleshield_results_bundle.zip
```

## DAT/archive workflow

The v2.x deterministic DAT workflow remains available:

```powershell
python .\pooleshield_operator.py dat-batch --path "C:\Users\rookp\Desktop\ChatGPT logs" --output-dir .\out\dat_batch_0050 --clean-output --start-index 50 --batch-size 150 --policy-profile balanced --bundle-output --privacy-bundle
```

Roll up completed batches:

```powershell
python .\pooleshield_operator.py batch-rollup --path "dat_batch_0050=.\out\dat_batch_0050\dat_chat_scan" --output-dir .\out\dat_archive_rollup --bundle-output --privacy-bundle
```

## Privacy rules

Privacy bundles exclude content-bearing files such as:

```text
normalized_events.jsonl
extracted_dat_text/
review_evidence_local.md
review_evidence_report.json
```

The file AV scanner does not include raw file contents or matched snippets in its reports.

## IP boundary

The public/source-available code is not a publication of private Poole Math, Poole Manifold, Poole Defect Calculus, private benchmark data, or unpublished manuscripts. See `NOTICE.md`, `LICENSE`, and `docs/IP_BOUNDARIES.md` when present.

## Guide files

- `FILE_AV_GUIDE.md` — v3.0.1 file/folder AV scanner
- `DAT_BATCH_GUIDE.md` — deterministic DAT batch workflow
- `BATCH_ROLLUP_GUIDE.md` — metadata rollup dashboard
- `PRIVACY_BUNDLE_GUIDE.md` — privacy-safe upload workflow
- `PROJECT_STATE.md` / `NEXT_BEST_MOVE.md` — continuity files


## File AV review ledger

PooleShield v3.1 adds a metadata-only review ledger for file/folder AV scans. Use it to mark known trusted helper scripts or local source/test artifacts as `ALLOW_LOG` without weakening the standard scanner profile.

```powershell
python .\pooleshield_operator.py file-av-review --output-dir .\out\file_av_scan --bundle-output --privacy-bundle
python .\pooleshield_operator.py file-av-apply-ledger --output-dir .\out\file_av_scan --ledger .\out\file_av_scan\file_av_review_ledger_template.csv --bundle-output --privacy-bundle
```

The review ledger does not read scanned file contents and does not execute, delete, quarantine, or modify files.


## v3.2 Trusted File Baseline

PooleShield can build a local trusted-hash baseline from reviewed file AV decisions and apply it to future scans. Baseline matches become `ALLOW_LOG`, not silent allow, so trusted local files remain auditable.

```powershell
python .\pooleshield_operator.py file-av-build-baseline --output-dir .\out\file_av_real_small_dev --baseline-path .\local_trust\trusted_file_baseline.json
python .\pooleshield_operator.py file-av-apply-baseline --output-dir .\out\file_av_real_small_dev_rescan --baseline .\local_trust\trusted_file_baseline.json
```

Privacy bundles exclude the local trusted baseline database.


## Baseline-aware file AV scan

After building a local trusted baseline, run a read-only file scan and apply that baseline in one command:

```powershell
python .\pooleshield_operator.py file-av-scan-baseline --path "C:\path\to\folder" --baseline "C:\path\to\trusted_file_baseline.json" --output-dir .\out\file_av_baseline_scan --risk-profile developer --bundle-output --privacy-bundle
```

This command is still dry-run only. It does not execute, delete, quarantine, or modify scanned files.


## v3.5 local rule packs

PooleShield supports optional JSON rule packs for read-only file AV scans. Rule packs can add labels/risk deltas for local policy, suspicious filenames, archive entries, and static text patterns. Rule packs do not execute, delete, quarantine, modify, or silently allow files.

## v3.5 archive-aware baseline

v3.5 allows a reviewed archive hash in the local trusted baseline to cover its archive entries with `ALLOW_LOG` on future scans. Unknown archives and script entries remain conservative. This is intended for trusted release packages and developer workflows, not for silently allowing arbitrary downloaded ZIP files.


## v3.5 final scan summary

Baseline-aware file AV scans now emit `FINAL_SCAN_SUMMARY.md/json` so operators can read one final effective verdict after rules and baselines are applied. Original scan decisions remain available for audit, but the final summary is the recommended first report.


## CI safety checks

PooleShield v3.6 includes GitHub Actions and a local repo safety checker.

Before pushing, run:

```powershell
python -m pytest -q
python .\tools\repo_safety_check.py --root .
```

The safety checker blocks private/generated artifacts such as scan outputs, result bundles, local baselines, decoded DAT text, normalized event JSONL, and local review evidence.
