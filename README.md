# PooleShield v4.4.0

PooleShield is a privacy-first second-opinion defensive scanner for suspicious files, archives, scripts, AI-agent logs, exported chat/data bundles, and local workflow artifacts.

PooleShield is defensive only. It reads local artifacts, scores static/local risk signals, and writes review reports. It does **not** execute scanned content, follow links, send emails, delete files, quarantine files, kill processes, install drivers, or modify the scanned corpus.

## v4.4 milestone

v4.4 adds the first **Rule Pack Editor UI** on top of the v4.0 Engine API, v4.1 desktop prototype, v4.2 Results UI, and v4.3 Baseline Manager UI:

```text
pooleshield_desktop.py
RULE_PACK_EDITOR_UI_GUIDE.md
engine operation: rule_pack.load
engine operation: rule_pack.export_default
engine operation: rule_pack.update_rule
operator command: rule-pack-load
operator command: rule-pack-export-default
operator command: rule-pack-update-rule
Dashboard / Scan Folder / Results / Baseline / Rule Packs / History / About tabs
```

The Rule Packs tab reads local rule-pack metadata, validates rules, filters by enabled/type/search text, exports the public default rule pack to a local editable copy, and writes selected-rule edits to a rule-pack JSON copy. It does not open scanned files, execute files, delete files, quarantine files, or silently trust files.

## Quick local checks

```powershell
python -m pytest -q
python .\tools\repo_safety_check.py --root .
python .\tools\privacy_leak_check.py --root .
python .\pooleshield_operator.py desktop --status
```

## Rule Pack Editor smoke test

```powershell
python .\pooleshield_operator.py rule-pack-load `
  --rule-pack .\examples\rule_packs\file_av_rules.default.json `
  --enabled enabled `
  --limit 25 `
  --output .\rule_pack_response.json
```

Export an editable copy:

```powershell
python .\pooleshield_operator.py rule-pack-export-default `
  --output .\local_rule_packs\file_av_rules.editable.json `
  --force
```

Edit one rule into a copy:

```powershell
python .\pooleshield_operator.py rule-pack-update-rule `
  --rule-pack .\local_rule_packs\file_av_rules.editable.json `
  --output .\local_rule_packs\file_av_rules.edited.json `
  --index 0 `
  --disabled `
  --risk-delta 0.10
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

Privacy bundles and repo commits must exclude content-bearing/private files such as:

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
local_rule_packs/
rule_pack_response.json
rule_pack_export_response.json
rule_pack_update_response.json
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
- `RULE_PACK_EDITOR_UI_GUIDE.md` — Rule Pack Editor UI
