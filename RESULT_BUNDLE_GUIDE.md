# PooleShield Result Bundle Guide

PooleShield v1.8 can create a single ZIP file from an output folder so you do not need to upload JSON, CSV, and Markdown files one at a time.

## Demo with automatic ZIP

```powershell
python .\pooleshield_operator.py demo --clean-output --bundle-output
```

Default bundle:

```text
out\demo\pooleshield_results_bundle.zip
```

## Real scan with automatic ZIP

```powershell
python .\pooleshield_operator.py scan --path "C:\path\to\folder" --output-dir .\out\real_scan --clean-output --policy-profile balanced --bundle-output
```

Default bundle:

```text
out\real_scan\pooleshield_results_bundle.zip
```

## Apply ledger and rebuild ZIP

```powershell
python .\pooleshield_operator.py apply-ledger --output-dir .\out\real_scan --ledger .\out\real_scan\review_ledger_template.csv --bundle-output
```

## Bundle an existing output folder

```powershell
python .\pooleshield_operator.py bundle --output-dir .\out\real_scan
```

## What the bundle contains

The ZIP contains report files such as:

- `RUN_SUMMARY.json`
- `RUN_SUMMARY.md`
- `scan_report.json`
- `policy_decisions.json`
- `approval_queue.json`
- `review_ledger_template.csv`
- `effective_policy_decisions.json`, when present
- `allowlist.json`, when present
- `denylist.json`, when present
- `BUNDLE_MANIFEST.json`

It excludes generated ZIP files, caches, virtual environments, and binary files.


## v1.8 privacy bundle note

For real chat/export scans, prefer `--privacy-bundle` when uploading results for review. It excludes `normalized_events.jsonl`, which may contain raw chat/log text, while preserving hashes, labels, decisions, and summaries.


## v2.0 privacy fix

Privacy bundles exclude both `review_evidence_local.md` and `review_evidence_report.json`, because both may contain redacted matched-context snippets from local reviewed files.
