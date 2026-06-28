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

## v3.4.2 archive-aware baseline behavior

PooleShield v3.4.2 extends trusted baselines to archive entries:

```text
Reviewed archive hash in baseline -> archive entries may become ALLOW_LOG
Unknown archive with risky entries -> still REQUIRE_APPROVAL/BLOCK as before
```

This is useful for known PooleShield release packages or other reviewed developer archives. It does not weaken the default scanner because the parent archive hash must already exist in the local trusted baseline.

Baseline matches remain auditable:

```text
baseline_trusted_hash      direct file/hash match
baseline_trusted_archive   archive entry allowed by reviewed parent archive hash
```

The baseline database is local metadata and is excluded from privacy bundles.


## Merge into an existing baseline

Use `--merge-existing` when adding newly reviewed files or archive entries to a
baseline you already trust. Without this flag, `file-av-build-baseline` writes a
fresh baseline from the selected output folder.

```powershell
python .\pooleshield_operator.py file-av-build-baseline `
  --output-dir .\out\file_av_real_small_rules `
  --baseline-path "C:\Users\rookp\pooleshield_v3_2_package\local_trust\trusted_file_baseline.json" `
  --merge-existing `
  --bundle-output `
  --privacy-bundle
```

This is the preferred workflow for reviewed archives: unknown archives remain
conservative, while reviewed archive/container hashes and reviewed archive-entry
hashes can be remembered locally.
