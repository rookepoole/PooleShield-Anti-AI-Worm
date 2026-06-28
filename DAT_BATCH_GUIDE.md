# PooleShield v2.0 DAT Batch Guide

v2.0 removes the need to manually minimize or split the ChatGPT `.dat` export folder.

The `dat-batch` command runs one deterministic local batch:

1. Extract only eligible text/json `.dat` blobs for the chosen batch window.
2. Run `chat-scan` on the extracted local text.
3. Run archived-chat review triage.
4. Apply the triage ledger only to create an intermediate effective state.
5. Run local redacted evidence review on remaining pending items.
6. Write `final_suggested_review_ledger.csv` for later inspection/application.
7. Create a privacy bundle that excludes decoded DAT text and local evidence snippets.

It does **not** auto-apply the final evidence ledger.

## Recommended first larger batch

```powershell
cd "C:\Users\rookp"
Remove-Item -Recurse -Force ".\pooleshield_v2_0_package" -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path ".\pooleshield_v2_0_package" | Out-Null
Expand-Archive -Path ".\pooleshield_v2_0_package.zip" -DestinationPath ".\pooleshield_v2_0_package" -Force
cd ".\pooleshield_v2_0_package"

python .\pooleshield_operator.py dat-batch --path "C:\Users\rookp\Desktop\ChatGPT logs" --output-dir .\out\dat_batch_0050 --clean-output --start-index 50 --batch-size 150 --policy-profile balanced --bundle-output --privacy-bundle
```

Upload only:

```text
C:\Users\rookp\pooleshield_v2_0_package\out\dat_batch_0050\pooleshield_results_bundle.zip
```

## Batch indexing

`start-index` counts eligible text/json DAT blobs, not binary images/PDFs/archives.

The first completed sample used the first 50 eligible text-like DAT blobs. So the next start index is usually:

```text
50
```

After a batch completes, open:

```text
out\dat_batch_0050\RUN_SUMMARY_DAT_BATCH.md
```

Use its `Next start index` value for the next batch.

## Privacy rule

Do not upload these local files unless intentionally sharing private content:

```text
dat_extract\extracted_dat_text\
dat_chat_scan\review_evidence_local.md
dat_chat_scan\review_evidence_report.json
dat_chat_scan\normalized_events.jsonl
```

The privacy bundle excludes them automatically.

## Applying the batch ledger later

After the uploaded privacy bundle is checked, apply the final suggested ledger with:

```powershell
python .\pooleshield_operator.py apply-ledger --output-dir .\out\dat_batch_0050\dat_chat_scan --ledger .\out\dat_batch_0050\final_suggested_review_ledger.csv --bundle-output --privacy-bundle
```

Then upload:

```text
out\dat_batch_0050\dat_chat_scan\pooleshield_results_bundle.zip
```
