# PooleShield v3.0.1 File/Folder AV Guide

PooleShield v3.0.1 adds a read-only, second-opinion file/folder antivirus scanner.

## Safety boundary

The v3.0 AV scanner does **not**:

- execute scanned files
- delete files
- quarantine files
- modify files
- kill processes
- install drivers
- hook the filesystem
- upload file contents

It writes metadata reports and dry-run quarantine recommendations only.

## Commands

Scan a folder:

```powershell
python .\pooleshield_operator.py scan-folder --path "C:\path\to\folder" --output-dir .\out\file_av_scan --clean-output --bundle-output --privacy-bundle
```

Scan one file:

```powershell
python .\pooleshield_operator.py scan-file --path "C:\path\to\file" --output-dir .\out\file_av_scan --clean-output --bundle-output --privacy-bundle
```

Scan an archive:

```powershell
python .\pooleshield_operator.py scan-archive --path "C:\path\to\archive.zip" --output-dir .\out\archive_av_scan --clean-output --bundle-output --privacy-bundle
```

Or use the generic command:

```powershell
python .\pooleshield_operator.py av-scan --path "C:\path\to\folder" --output-dir .\out\file_av_scan --clean-output --bundle-output --privacy-bundle
```

## Reports

The scanner writes:

- `file_av_report.json`
- `file_av_report.csv`
- `file_av_report.md`
- `dry_run_quarantine_plan.json`
- `dry_run_quarantine_plan.csv`
- `dry_run_quarantine_plan.md`
- `archive_inventory.json`
- `RUN_SUMMARY_FILE_AV.json`
- `RUN_SUMMARY_FILE_AV.md`

## Decision meanings

```text
ALLOW            low-risk static metadata/content signal
ALLOW_LOG        safe to keep but worth logging
REQUIRE_APPROVAL review before opening/executing/sharing
BLOCK            dry-run quarantine recommendation; no file is moved
QUARANTINE       reserved for later enforced containment layers
```

## Privacy

The v3.0 scanner reports paths, hashes, metadata, risk labels, and decisions. It does not include raw file contents or matched snippets in report bundles.

## First test command

```powershell
python .\pooleshield_operator.py scan-folder --path .\examples\file_av_fixture --output-dir .\out\file_av_demo --clean-output --bundle-output --privacy-bundle
```

Expected: the benign note should be `ALLOW`, the inert PowerShell fixture should require review or block, and the fake MZ text file should be logged due to extension/magic mismatch.


## v3.0.1 developer risk profile

The default file AV profile is `standard` and should be used for normal user folders.

Use the `developer` profile only when scanning trusted source-code packages, PooleShield release ZIPs, local test fixtures, or generated helper scripts that are expected to contain detector strings as inert text.

```powershell
python .\pooleshield_operator.py scan-folder --path ".\some_trusted_source_folder" --output-dir .\out\file_av_dev --clean-output --risk-profile developer --bundle-output --privacy-bundle
```

The developer profile does not execute or modify files. It only caps source/test/reference-code false positives when a file clearly appears to be local developer/reference material.


## v3.1 review ledger

After a file/folder scan, generate a review ledger with:

```powershell
python .\pooleshield_operator.py file-av-review --output-dir .\out\file_av_scan --bundle-output --privacy-bundle
```

Edit `file_av_review_ledger_template.csv`, then apply it:

```powershell
python .\pooleshield_operator.py file-av-apply-ledger --output-dir .\out\file_av_scan --ledger .\out\file_av_scan\file_av_review_ledger_template.csv --bundle-output --privacy-bundle
```

This is intended for local trust decisions such as known helper scripts. Use the standard scanner profile for unknown user files.


## Trusted baseline

Use `file-av-build-baseline` and `file-av-apply-baseline` for known-good helper scripts or source/test files that have already been reviewed. See `FILE_AV_BASELINE_GUIDE.md`.
