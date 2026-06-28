# PooleShield Baseline-Aware File AV Scan Guide

PooleShield v3.3 adds `file-av-scan-baseline`.

This command runs a read-only file/folder scan and applies a local trusted hash baseline in one workflow.

## Safety boundary

It does not execute files, delete files, quarantine files, modify files, kill processes, install hooks, or install drivers.

## Command

```powershell
python .\pooleshield_operator.py file-av-scan-baseline `
  --path "$env:USERPROFILE\Desktop\PooleShieldRealScanSmall" `
  --baseline "C:\Users\rookp\pooleshield_v3_2_package\local_trust\trusted_file_baseline.json" `
  --output-dir .\out\file_av_real_small_baseline `
  --clean-output `
  --risk-profile developer `
  --bundle-output `
  --privacy-bundle
```

## Outputs

- `file_av_report.*` original scan results
- `effective_file_av_baseline_decisions.*` post-baseline effective decisions
- `effective_dry_run_quarantine_plan.*` post-baseline advisory plan
- `RUN_SUMMARY_FILE_AV_BASELINE_SCAN.*` single command summary
- `pooleshield_results_bundle.zip` privacy-safe bundle

## Why this exists

Earlier workflows produced both original dry-run recommendations and baseline-effective decisions. v3.3 keeps both for audit, but also writes an effective post-baseline plan so the operator has one clear final view.


## v3.5 final summary

`file-av-scan-baseline` now writes `FINAL_SCAN_SUMMARY.md/json`, which is the recommended first report for operators. It prioritizes effective post-baseline decisions over original raw scan decisions.
