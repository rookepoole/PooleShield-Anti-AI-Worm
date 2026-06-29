# PooleShield v4.1.0

PooleShield is a privacy-first second-opinion defensive scanner for suspicious files, archives, scripts, AI-agent logs, exported chat/data bundles, and local workflow artifacts.

PooleShield is defensive only. It reads local artifacts, scores static/local risk signals, and writes review reports. It does **not** execute scanned content, follow links, send emails, delete files, quarantine files, kill processes, install drivers, or modify the scanned corpus.

## v4.1 milestone

v4.1 adds the first desktop UI prototype on top of the v4.0 Engine API:

```text
pooleshield_desktop.py
DESKTOP_UI_GUIDE.md
requirements-ui.txt
operator command: desktop
Dashboard / Scan Folder / History / About tabs
```

The UI calls the local Engine API. It remains read-only and privacy-first.

## Quick local checks

```powershell
python -m pytest -q
python .	oolsepo_safety_check.py --root .
python .	ools\privacy_leak_check.py --root .
python .\pooleshield_operator.py profile-list
python .\pooleshield_operator.py profile-show --name developer
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

## Engine API smoke test

```powershell
@'
{
  "operation": "profile.show",
  "params": {
    "name": "developer"
  }
}
'@ | Set-Content .\engine_request.json

python .\pooleshield_operator.py engine-dispatch --request .\engine_request.json --output .\engine_response.json
```

## Baseline-aware file AV scan

After building a local trusted baseline, run a read-only file scan and apply that baseline in one command:

```powershell
python .\pooleshield_operator.py file-av-scan-baseline `
  --config .\pooleshield_config.json `
  --path "C:\path	oolder" `
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

The file AV scanner does not include raw file contents or matched snippets in its reports.

## Guide files

- `ENGINE_API_GUIDE.md` — Python/JSON Engine API bridge.
- `DESKTOP_UI_GUIDE.md` — v4.1 desktop UI prototype.
- `CONFIG_GUIDE.md` — local config defaults.
- `SCAN_PROFILE_GUIDE.md` — named scan profiles.
- `SCAN_HISTORY_GUIDE.md` — local metadata-only scan history.
- `CI_SAFETY_GUIDE.md` — repo safety and privacy leak checks.
