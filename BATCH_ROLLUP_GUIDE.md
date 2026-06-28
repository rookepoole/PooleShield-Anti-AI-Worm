# PooleShield v2.1.1 Batch Rollup Guide

`batch-rollup` summarizes multiple PooleShield batch output folders or uploaded privacy bundles into one dashboard.

It reads metadata reports only. It does **not** read decoded DAT text, `normalized_events.jsonl`, or local evidence snippets.

## What it creates

```text
batch_rollup.json
batch_rollup.csv
batch_rollup.md
pooleshield_results_bundle.zip   # optional
```

## Recommended local command for the current DAT pass

```powershell
cd "C:\Users\rookp\pooleshield_v2_1_package"

python .\pooleshield_operator.py batch-rollup `
  --path "dat_batch_0000=C:\Users\rookp\pooleshield_v1_8_package\out\dat_chat_scan" `
  --path "dat_batch_0050=C:\Users\rookp\pooleshield_v2_0_package\out\dat_batch_0050\dat_chat_scan" `
  --path "dat_batch_0200=C:\Users\rookp\pooleshield_v2_0_package\out\dat_batch_0200\dat_chat_scan" `
  --path "dat_batch_0350=C:\Users\rookp\pooleshield_v2_0_package\out\dat_batch_0350\dat_chat_scan" `
  --path "dat_batch_0500=C:\Users\rookp\pooleshield_v2_0_package\out\dat_batch_0500\dat_chat_scan" `
  --output-dir .\out\dat_archive_rollup `
  --clean-output `
  --bundle-output `
  --privacy-bundle
```

Upload only:

```text
C:\Users\rookp\pooleshield_v2_1_package\out\dat_archive_rollup\pooleshield_results_bundle.zip
```

## Labeled paths

Use `label=path` to give old or oddly named batches a stable label:

```powershell
--path "dat_batch_0000=C:\Users\rookp\pooleshield_v1_8_package\out\dat_chat_scan"
```

## ZIP bundles also work

You can roll up uploaded/downloaded bundles directly:

```powershell
python .\pooleshield_operator.py batch-rollup `
  --path "dat_batch_0050=C:\Users\rookp\Downloads\batch0050_bundle.zip" `
  --path "dat_batch_0200=C:\Users\rookp\Downloads\batch0200_bundle.zip" `
  --output-dir .\out\bundle_rollup `
  --clean-output `
  --bundle-output `
  --privacy-bundle
```

## Status interpretation

A batch is `complete` when its final effective decisions contain no actionable items:

```text
REQUIRE_APPROVAL = 0
BLOCK = 0
QUARANTINE = 0
```

Older batches may contain a stale `pending_review_rows` bookkeeping value even after final decisions are clean. The rollup treats final effective decisions as operational truth.
