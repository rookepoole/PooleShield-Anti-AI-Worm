# PooleShield v2.0 Review Evidence Guide

`review-evidence` is the next step after `review-triage` and cumulative ledger application.

It reads the remaining pending `effective_policy_decisions.json` rows on your machine, opens the referenced local source files, finds why they were flagged, and writes:

```text
review_evidence_report.json
review_evidence_summary.csv
review_evidence_suggested_ledger.csv
review_evidence_local.md
RUN_SUMMARY_EVIDENCE.json
RUN_SUMMARY_EVIDENCE.md
```

`review_evidence_local.md` is content-bearing. It can include redacted matched context from local extracted chat/DAT files. Do not upload it unless you intentionally want to share the reviewed text.

When `--privacy-bundle` is used, `review_evidence_local.md` is excluded from the bundle.

## Recommended command for the current DAT-chat review

Run this from the v2.0 package, pointing at the existing v1.8 scan output folder:

```powershell
cd "C:\Users\rookp\pooleshield_v1_9_package"

python .\pooleshield_operator.py review-evidence --output-dir "C:\Users\rookp\pooleshield_v1_8_package\out\dat_chat_scan" --bundle-output --privacy-bundle
```

Then upload only:

```text
C:\Users\rookp\pooleshield_v1_8_package\out\dat_chat_scan\pooleshield_results_bundle.zip
```

## Local review flow

1. Open `review_evidence_local.md` locally.
2. Check each redacted snippet.
3. If the suggested ledger looks right, apply it:

```powershell
python .\pooleshield_operator.py apply-ledger --output-dir "C:\Users\rookp\pooleshield_v1_8_package\out\dat_chat_scan" --ledger "C:\Users\rookp\pooleshield_v1_8_package\out\dat_chat_scan\review_evidence_suggested_ledger.csv" --bundle-output --privacy-bundle
```

4. Upload the new `pooleshield_results_bundle.zip`.

## Safety boundary

The command does not execute, call tools, send, delete, quarantine, or modify scanned content. It only reads local text files and writes review reports.
