# PooleShield v5.4 Safe External Dataset Dry-Run Guide

Version: `5.4.0-candidate`

This patch adds a stronger code-tester workflow for external feature-only datasets.
It is designed for EMBER/SOREL-style exported rows, lab-generated feature CSVs, or other malware-derived metadata where the actual samples are not present.

## What this adds

New module:

```text
safe_dataset_lab.py
```

New CLI command:

```text
safe-dataset-dry-run
```

New Engine API operation:

```text
safe_dataset.dry_run
```

New guide:

```text
SAFE_DATASET_DRY_RUN_GUIDE.md
```

New tests:

```text
tests/test_safe_dataset_lab.py
```

## Safety boundary

The dry-run path accepts only JSONL/CSV feature rows. It does **not**:

- download malware
- execute samples
- unpack archives
- open file paths referenced inside dataset rows
- collect binaries
- quarantine or delete files
- upload raw contents

It rejects rows containing obvious raw-binary/payload/download fields, executable/archive sample paths, or `raw_binary_present=true`.

## Quick JSONL smoke

```powershell
$ErrorActionPreference = "Stop"
cd "C:\Users\rookp\Desktop\PooleShield-Anti-AI-Worm"

New-Item -ItemType Directory -Force -Path ".\examples\safe_corpus" | Out-Null
@'
{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","label":1,"features_only":true,"raw_binary_present":false,"features":{"entropy":7.4,"malicious_vendor_ratio":0.9}}
{"sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","label":0,"features_only":true,"raw_binary_present":false,"features":{"entropy":4.2,"malicious_vendor_ratio":0.0}}
{"sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","label":"malicious","sample_path":"C:\\Users\\rookp\\Desktop\\samples\\dropper.exe","features":{"entropy":7.9}}
'@ | Set-Content -Encoding UTF8 ".\examples\safe_corpus\external_feature_dry_run_sample.jsonl"

python .\pooleshield_operator.py safe-dataset-dry-run `
  --input .\examples\safe_corpus\external_feature_dry_run_sample.jsonl `
  --source external_sample `
  --output-dir .\out\safe_dataset_dry_run_v5_4 `
  --clean-output `
  --write-safe-jsonl `
  --bundle-output `
  --privacy-bundle
```

Expected behavior:

- 2 rows accepted
- 1 row rejected because it references an executable sample path
- no row paths are opened
- privacy bundle is created
- local absolute paths are redacted inside the bundle copy

Upload only:

```text
C:\Users\rookp\Desktop\PooleShield-Anti-AI-Worm\out\safe_dataset_dry_run_v5_4\pooleshield_results_bundle.zip
```

## Real external dataset usage

For a feature-only JSONL:

```powershell
python .\pooleshield_operator.py safe-dataset-dry-run `
  --input "C:\path\to\feature_rows.jsonl" `
  --source external_jsonl `
  --output-dir .\out\external_jsonl_dry_run `
  --clean-output `
  --limit 5000 `
  --write-safe-jsonl `
  --bundle-output `
  --privacy-bundle
```

For a feature-only CSV:

```powershell
python .\pooleshield_operator.py safe-dataset-dry-run `
  --input "C:\path\to\feature_rows.csv" `
  --source external_csv `
  --output-dir .\out\external_csv_dry_run `
  --clean-output `
  --limit 5000 `
  --write-safe-jsonl `
  --bundle-output `
  --privacy-bundle
```

## Outputs

```text
SAFE_DATASET_DRY_RUN.json
SAFE_DATASET_DRY_RUN.md
safe_external_dataset_preview.jsonl
safe_external_dataset.jsonl       # only with --write-safe-jsonl
safe_external_dataset_rejections.csv
pooleshield_results_bundle.zip    # only with --bundle-output
```

## Commit boundary

Do not commit generated outputs, bundles, downloaded datasets, raw samples, local baselines, history DBs, or private configs.

## v5.4.1 Windows encoding note

`safe-dataset-dry-run` accepts UTF-8 files with or without a byte-order mark (BOM).
This matters on Windows because some PowerShell/write workflows create UTF-8-BOM
JSONL or CSV files. BOM handling does not change the safety boundary: rows are
still metadata/features only, raw binary fields are rejected, and paths/URLs are
not opened or fetched.

## v5.4.2 CLI compatibility note

`safe-dataset-dry-run` accepts both spelling forms below:

```powershell
--write-safe-jsonl
--write-normalized
```

Both mean: write accepted normalized feature-only rows to `safe_external_dataset.jsonl`.

The command also accepts explicit `--redact-paths`. Privacy bundles already redact
local absolute paths by default; `--redact-paths` exists so copy/paste workflows
can be more obvious and less error-prone. Use `--no-redact-paths` only for local
debugging when you do not plan to upload the bundle.
