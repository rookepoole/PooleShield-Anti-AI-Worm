# PooleShield v4.0.0

PooleShield is a privacy-first second-opinion defensive scanner for suspicious files, archives, scripts, AI-agent logs, exported chat/data bundles, and local workflow artifacts.

PooleShield is defensive only. It reads local artifacts, scores static/local risk signals, and writes review reports. It does **not** execute scanned content, follow links, send emails, delete files, quarantine files, kill processes, install drivers, or modify the scanned corpus.

## v4.0 milestone

v4.0 adds a UI-ready Engine API layer:

```text
pooleshield_engine.py
ENGINE_API_GUIDE.md
engine-dispatch
config/profile/history/rule-pack/baseline-scan engine functions
JSON request/response bridge
```

The operator CLI still works, but the newest config/profile/history/baseline-aware workflow now has a callable backend for future desktop UI work.

## Quick local checks

```powershell
python -m pytest -q
python .\tools\repo_safety_check.py --root .
python .\pooleshield_operator.py profile-list
python .\pooleshield_operator.py profile-show --name developer
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

The file AV scanner does not include raw file contents or matched snippets in its reports.

## Guide files

- `ENGINE_API_GUIDE.md` — v4.0 Python/JSON Engine API bridge
- `CONFIG_GUIDE.md` — local config defaults
- `SCAN_PROFILE_GUIDE.md` — named scan profiles
- `SCAN_HISTORY_GUIDE.md` — local metadata-only scan history
- `FILE_AV_GUIDE.md` — read-only file/folder AV scanner
- `FILE_AV_BASELINE_SCAN_GUIDE.md` — baseline-aware one-command scan
- `PRIVACY_BUNDLE_GUIDE.md` — privacy-safe upload workflow
- `PROJECT_STATE.md` / `NEXT_BEST_MOVE.md` — continuity files

## IP boundary

The public/source-available code is not a publication of private Poole Math, Poole Manifold, Poole Defect Calculus, private benchmark data, or unpublished manuscripts. See `NOTICE.md`, `LICENSE`, and `docs/IP_BOUNDARIES.md` when present.
