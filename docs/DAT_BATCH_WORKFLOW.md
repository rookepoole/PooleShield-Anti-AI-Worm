# DAT Batch Workflow

Use `dat-batch` when a large export produces many `.dat` blobs and manual minimization is impractical.

Example:

```powershell
python .\pooleshield_operator.py dat-batch --path "C:\path\to\export" --output-dir .\out\dat_batch_0000 --clean-output --start-index 0 --batch-size 150 --policy-profile balanced --bundle-output --privacy-bundle
```

Then inspect the privacy bundle. If the final suggested ledger is acceptable:

```powershell
python .\pooleshield_operator.py apply-ledger --output-dir ".\out\dat_batch_0000\dat_chat_scan" --ledger ".\out\dat_batch_0000\final_suggested_review_ledger.csv" --bundle-output --privacy-bundle
```

For the next deterministic batch, advance `--start-index` by the batch size.
