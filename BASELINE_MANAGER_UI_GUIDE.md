# PooleShield v5.3.0 Baseline Manager UI Guide

PooleShield v5.3.0 adds the first local Baseline Manager UI on top of the v4.0 Engine API and the v4.1/v4.2 desktop prototype.

The Baseline Manager is metadata-only and local-first:

- reads `trusted_file_baseline.json`
- lists trusted hash entries
- filters by trusted decision, kind, SHA/path/label/notes text
- shows SHA256, kind, size, labels, and path hints
- copies selected SHA values for operator review
- compares two baseline JSON files by SHA256
- does not open, execute, delete, quarantine, restore, or trust scanned files
- does not upload raw scanned content
- does not modify the baseline file in v5.3.0

## CLI smoke tests

```powershell
python .\pooleshield_operator.py baseline-load `
  --baseline C:\path\to\trusted_file_baseline.json `
  --decision ALLOW_LOG `
  --limit 25 `
  --output .\baseline_response.json
```

Compare two baselines:

```powershell
python .\pooleshield_operator.py baseline-diff `
  --baseline-a C:\path\to\old_trusted_file_baseline.json `
  --baseline-b C:\path\to\new_trusted_file_baseline.json `
  --limit 25 `
  --output .\baseline_diff_response.json
```

## Engine operations

```text
baseline.load
baseline.diff
```

These operations are UI-ready JSON request/response calls. They only inspect trusted-baseline metadata.

## Desktop tab

The desktop app now includes:

```text
Dashboard
Scan Folder
Results
Baseline
History
About
```

The Baseline tab lets you load a local trusted baseline, filter entries, inspect details, copy selected SHA values, copy the baseline path, and run baseline-vs-baseline comparisons.

## Privacy boundary

Do not commit or upload local baseline files unless you intentionally choose to share them. Privacy bundles exclude `trusted_file_baseline.json` by design.
