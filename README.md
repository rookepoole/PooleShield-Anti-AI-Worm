# PooleShield v2.1.1

Defensive local-geometry protection prototype for AI-agent / RAG / tool-call worm-risk detection.

PooleShield is defensive only. It reads text-like logs/exports, scores local defect signals, and writes review reports. It does **not** execute scanned content, follow links, send emails, delete files, quarantine files, or modify the scanned corpus.

## What v2.0 adds

v2.0 adds deterministic DAT batching so the operator does **not** need to manually shrink, split, or minimize large ChatGPT `.dat` export folders.

New capabilities:

```text
dat-extract --start-index N --max-files M
dat-batch --start-index N --batch-size M
```

`dat-batch` runs this local workflow in one command:

```text
DAT extract batch → chat-scan → review-triage → intermediate ledger → review-evidence → final_suggested_review_ledger.csv → privacy bundle
```

It does not auto-apply the final evidence ledger.

## Recommended next command

```powershell
python .\pooleshield_operator.py dat-batch --path "C:\Users\rookp\Desktop\ChatGPT logs" --output-dir .\out\dat_batch_0050 --clean-output --start-index 50 --batch-size 150 --policy-profile balanced --bundle-output --privacy-bundle
```

Upload only:

```text
out\dat_batch_0050\pooleshield_results_bundle.zip
```

## Privacy rules

Privacy bundles exclude:

```text
normalized_events.jsonl
extracted_dat_text/
review_evidence_local.md
review_evidence_report.json
```

Do not upload raw extracted DAT text unless intentionally sharing private chat content.

## Main commands

Run safe demo:

```powershell
python .\pooleshield_operator.py demo --clean-output --bundle-output --privacy-bundle
```

Inspect `.dat` exports:

```powershell
python .\pooleshield_operator.py dat-inspect --path "C:\Users\rookp\Desktop\ChatGPT logs" --output-dir .\out\dat_inspect --clean-output --bundle-output --privacy-bundle
```

Extract a deterministic DAT batch only:

```powershell
python .\pooleshield_operator.py dat-extract --path "C:\Users\rookp\Desktop\ChatGPT logs" --output-dir .\out\dat_extract_0050 --clean-output --start-index 50 --max-files 150 --bundle-output --privacy-bundle
```

Run full DAT batch workflow:

```powershell
python .\pooleshield_operator.py dat-batch --path "C:\Users\rookp\Desktop\ChatGPT logs" --output-dir .\out\dat_batch_0050 --clean-output --start-index 50 --batch-size 150 --policy-profile balanced --bundle-output --privacy-bundle
```

Apply a final suggested ledger after review:

```powershell
python .\pooleshield_operator.py apply-ledger --output-dir .\out\dat_batch_0050\dat_chat_scan --ledger .\out\dat_batch_0050\final_suggested_review_ledger.csv --bundle-output --privacy-bundle
```

## Guide files

- `DAT_BATCH_GUIDE.md` — deterministic full DAT batch workflow
- `DAT_EXPORT_GUIDE.md` — inspect `.dat` exports
- `DAT_EXTRACT_GUIDE.md` — locally extract text-like `.dat` blobs
- `REVIEW_TRIAGE_GUIDE.md` — group large approval queues
- `REVIEW_EVIDENCE_GUIDE.md` — local redacted evidence viewer
- `RESULT_BUNDLE_GUIDE.md` — one-file upload bundles
- `PRIVACY_BUNDLE_GUIDE.md` — privacy-safe upload workflow
- `PROJECT_STATE.md` / `NEXT_BEST_MOVE.md` — continuity files


## v2.1.1 batch rollup

After running deterministic DAT batches, summarize them with:

```powershell
python .\pooleshield_operator.py batch-rollup --path "dat_batch_0050=.\out\dat_batch_0050\dat_chat_scan" --output-dir .\out\dat_archive_rollup --bundle-output --privacy-bundle
```

See `BATCH_ROLLUP_GUIDE.md`.
