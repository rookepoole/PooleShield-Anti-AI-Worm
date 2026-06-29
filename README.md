# PooleShield v4.2.0

PooleShield is a privacy-first second-opinion defensive scanner for suspicious files, archives, scripts, AI-agent logs, exported chat/data bundles, and local workflow artifacts.

PooleShield is defensive only. It reads local artifacts, scores static/local risk signals, and writes review reports. It does **not** execute scanned content, follow links, send emails, delete files, quarantine files, kill processes, install drivers, or modify the scanned corpus.

## v4.2 milestone

v4.2 upgrades the desktop prototype into a first **Results UI** on top of the v4.0 Engine API:

```text
pooleshield_desktop.py
RESULTS_UI_GUIDE.md
engine operation: results.load
operator command: results-load
Dashboard / Scan Folder / Results / History / About tabs
sortable-style metadata table, filters, detail panel, bundle-path copy button
```

The UI remains local, read-only, and privacy-first. The Results tab reads PooleShield metadata reports only; it does not open or execute scanned files and does not load raw file contents.

## Quick local checks

```powershell
python -m pytest -q
python .\tools\repo_safety_check.py --root .
python .\tools\privacy_leak_check.py --root .
python .\pooleshield_operator.py desktop --status
```

## Install and launch the UI prototype

```powershell
python -m pip install PySide6
python .\pooleshield_operator.py desktop
```

You can also launch directly:

```powershell
python .\pooleshield_desktop.py
```

## Results loader smoke test

After running a scan, load metadata-only results from the output folder:

```powershell
python .\pooleshield_operator.py results-load `
  --output-dir .\out\file_av_desktop_v4_2 `
  --decision ALLOW_LOG `
  --limit 25 `
  --output .\results_response.json
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
```

The file AV scanner and Results UI do not include raw file contents or matched snippets in their reports.

## Guide files

- `ENGINE_API_GUIDE.md` — Python/JSON Engine API bridge.
- `DESKTOP_UI_GUIDE.md` — desktop UI prototype.
- `RESULTS_UI_GUIDE.md` — v4.2 results table, filters, detail panel, and bundle path workflow.
- `CONFIG_GUIDE.md` — local config defaults.
- `SCAN_PROFILE_GUIDE.md` — named scan profiles.
- `SCAN_HISTORY_GUIDE.md` — local metadata-only scan history.
- `CI_SAFETY_GUIDE.md` — repo safety and privacy leak checks.
