# PooleShield File AV Trusted Baseline Guide

Version: 3.2.1

## Purpose

The trusted baseline database lets PooleShield remember known-good file hashes across repeated file/folder AV scans. It is meant for local helper scripts, PooleShield source/test fixtures, trusted internal tools, and reviewed files that would otherwise be flagged repeatedly.

## Safety boundary

The baseline system is metadata-only and read-only:

```text
No execution
No delete
No quarantine
No file modification
No process killing
No real-time hooks
No kernel driver
```

A baseline match is converted to `ALLOW_LOG`, not silent allow, so trusted files remain auditable.

## Build a baseline from reviewed decisions

First run a file AV scan, build a review ledger, and apply the ledger. Then build the baseline:

```powershell
python .\pooleshield_operator.py file-av-build-baseline `
  --output-dir .\out\file_av_real_small_dev `
  --baseline-path .\local_trust\trusted_file_baseline.json `
  --bundle-output `
  --privacy-bundle
```

By default, the baseline only includes files that were explicitly reviewed and changed/applied to `ALLOW` or `ALLOW_LOG`. This avoids accidentally trusting every ordinary allowed file.

## Apply a baseline to a new scan

```powershell
python .\pooleshield_operator.py scan-folder `
  --path "$env:USERPROFILE\Desktop\PooleShieldRealScanSmall" `
  --output-dir .\out\file_av_real_small_dev_rescan `
  --clean-output `
  --risk-profile developer `
  --bundle-output `
  --privacy-bundle

python .\pooleshield_operator.py file-av-apply-baseline `
  --output-dir .\out\file_av_real_small_dev_rescan `
  --baseline .\local_trust\trusted_file_baseline.json `
  --bundle-output `
  --privacy-bundle
```

## Privacy behavior

Privacy bundles exclude the local trust database itself:

```text
trusted_file_baseline.json
trusted_file_baseline.csv
trusted_file_baseline.md
```

The bundle keeps summaries and effective decisions so the scan remains auditable without uploading the local trust database.

## Recommended use

Use baselines for stable, known-good local files that you have already reviewed. Do not use a baseline to approve unknown downloads, files from other people, newly modified scripts, or anything you are not authorized to scan.


## Missing baseline troubleshooting

If `file-av-apply-baseline` reports that the trusted baseline file is missing, build it first with `file-av-build-baseline` or pass an absolute path to an existing `trusted_file_baseline.json`.

The apply command never creates a baseline automatically because that could silently trust files that have not been reviewed.


## v3.3 one-command scan + baseline

Use `file-av-scan-baseline` to run a fresh read-only scan and apply a trusted baseline in one workflow. See `FILE_AV_BASELINE_SCAN_GUIDE.md`.
