# PooleShield v4.3.0

PooleShield is a privacy-first second-opinion defensive scanner for suspicious files, archives, scripts, AI-agent logs, exported chat/data bundles, and local workflow artifacts.

PooleShield is defensive only. It reads local artifacts, scores static/local risk signals, and writes review reports. It does **not** execute scanned content, follow links, send emails, delete files, quarantine files, kill processes, install drivers, or modify the scanned corpus.

## v4.3 milestone

v4.3 adds the first **Baseline Manager UI** on top of the v4.0 Engine API, v4.1 desktop prototype, and v4.2 Results UI:

```text
pooleshield_desktop.py
BASELINE_MANAGER_UI_GUIDE.md
engine operation: baseline.load
engine operation: baseline.diff
operator command: baseline-load
operator command: baseline-diff
Dashboard / Scan Folder / Results / Baseline / History / About tabs
```

The Baseline tab reads local trusted-baseline metadata only. It can list entries, filter entries, inspect details, copy SHA/path values, and compare two baseline JSON files. It does not open scanned files, execute files, delete files, quarantine files, or modify the baseline in v4.3.

## Quick local checks

```powershell
python -m pytest -q
python .\tools\repo_safety_check.py --root .
python .\tools\privacy_leak_check.py --root .
python .\pooleshield_operator.py desktop --status
```

## Baseline Manager smoke test

```powershell
python .\pooleshield_operator.py baseline-load `
  --baseline C:\path\to\trusted_file_baseline.json `
  --decision ALLOW_LOG `
  --limit 25 `
  --output .\baseline_response.json
```

Compare two baseline files:

```powershell
python .\pooleshield_operator.py baseline-diff `
  --baseline-a C:\path\to\old_trusted_file_baseline.json `
  --baseline-b C:\path\to\new_trusted_file_baseline.json `
  --limit 25 `
  --output .\baseline_diff_response.json
```

## Install and launch the UI prototype

```powershell
python -m pip install PySide6
python .\pooleshield_operator.py desktop
```

## Baseline-aware file AV scan

After building a local trusted baseline, run a read-only file scan and apply that baseline in one command:

```powershell
python .\pooleshield_operator.py file-av-scan-baseline `
  --config .\pooleshield_config.json `
  --path "C:\path\to\folder" `
  --clean-output `
  --bundle-output `
  --privacy-bundle
```

This command is still dry-run only. It does not execute, delete, quarantine, or modify scanned files.

## Privacy rules

Privacy bundles exclude content-bearing/private files such as:

```text
normalized_events.jsonl
extracted_dat_text/
extracted_dat_content/
extracted_text_like/
review_evidence_local.md
review_evidence_report.json
trusted_file_baseline.json
pooleshield_config.json
local_history/*.sqlite
baseline_response.json
baseline_diff_response.json
results_response.json
```

The file AV scanner does not include raw file contents or matched snippets in its reports.

## Guide files

- `ENGINE_API_GUIDE.md` — Python/JSON Engine API bridge
- `DESKTOP_UI_GUIDE.md` — Desktop prototype
- `RESULTS_UI_GUIDE.md` — Results UI
- `BASELINE_MANAGER_UI_GUIDE.md` — Baseline Manager UI
