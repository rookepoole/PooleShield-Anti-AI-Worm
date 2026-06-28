# PooleShield File AV Final Summary Guide

PooleShield v3.5 adds a final operator-facing summary layer for file AV scans.

The goal is to make the final outcome obvious after rule packs and trusted baselines are applied. Earlier reports preserve raw/original scan decisions for audit, but `FINAL_SCAN_SUMMARY.*` is the report operators should read first.

## Outputs

A baseline-aware scan now writes:

```text
FINAL_SCAN_SUMMARY.json
FINAL_SCAN_SUMMARY.md
FINAL_SCAN_SUMMARY_ACTION_ITEMS.csv
```

The final summary prefers effective post-baseline decisions from:

```text
effective_file_av_baseline_decisions.json
```

and falls back to:

```text
effective_file_av_decisions.json
file_av_report.json
```

when needed.

## Verdicts

```text
CLEAN_AFTER_POLICY   No effective REQUIRE_APPROVAL/BLOCK/QUARANTINE items remain.
REVIEW_REQUIRED      One or more effective REQUIRE_APPROVAL items remain.
ACTION_REQUIRED      One or more effective BLOCK or QUARANTINE items remain.
```

## Standalone command

```powershell
python .\pooleshield_operator.py file-av-final-summary --output-dir .\out\file_av_real_small_rules_final --bundle-output --privacy-bundle
```

## Safety boundary

The final summary is metadata-only. It does not include scanned file contents, raw DAT text, normalized event JSONL, local review evidence, or baseline JSON in privacy bundles.

It does not execute, delete, quarantine, modify, upload scanned file contents, kill processes, or install hooks/drivers.
