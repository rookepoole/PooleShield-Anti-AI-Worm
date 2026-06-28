# PooleShield File AV Review Ledger Guide

Version: 3.2.0

The file-AV review ledger lets an operator approve known/trusted findings from a read-only file scan without weakening the scanner profile.

## Safety boundary

This workflow is metadata-only. It does not execute, delete, quarantine, restore, or modify scanned files.

## Build a review ledger

```powershell
python .\pooleshield_operator.py file-av-review --output-dir .\outile_av_real_small_dev --bundle-output --privacy-bundle
```

Edit:

```text
file_av_review_ledger_template.csv
```

Allowed operator decisions:

```text
KEEP_ORIGINAL
ALLOW
ALLOW_LOG
REQUIRE_APPROVAL
BLOCK
QUARANTINE
```

Recommended use:

- Use `ALLOW_LOG` for trusted helper scripts, source files, test fixtures, and known local artifacts that are safe but worth auditing.
- Keep `REQUIRE_APPROVAL`, `BLOCK`, or `QUARANTINE` for unknown files, unexpected scripts, suspicious archives, or files from untrusted sources.

## Apply the ledger

```powershell
python .\pooleshield_operator.py file-av-apply-ledger --output-dir .\outile_av_real_small_dev --ledger .\outile_av_real_small_devile_av_review_ledger_template.csv --bundle-output --privacy-bundle
```

Output files:

```text
effective_file_av_decisions.json
effective_file_av_decisions.csv
effective_file_av_decisions.md
file_av_allowlist.json
file_av_denylist.json
```

## Privacy model

Reports include paths, hashes, labels, and reasons. They do not include raw scanned file contents.
