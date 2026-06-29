# PooleShield Scan History Guide

Version: 5.3.0

PooleShield v3.9 adds a **local SQLite scan-history database** for UI/dashboard readiness.

The history database stores metadata only:

```text
scan timestamp
final verdict
scan profile
risk profile
items scanned
baseline matches
action-item counts
output directory
result bundle path if present
```

It does **not** store:

```text
raw scanned file contents
decoded DAT text
normalized event JSONL
trusted baseline JSON
local review evidence
quarantine payloads
private Poole Math / Poole Manifold / Poole Defect Calculus IP
```

## Initialize history

```powershell
python .\pooleshield_operator.py history-init --history-db .\local_history\pooleshield_scan_history.sqlite
```

## Record an existing scan output

```powershell
python .\pooleshield_operator.py history-record `
  --history-db .\local_history\pooleshield_scan_history.sqlite `
  --output-dir .\out\file_av_real_small_profiles `
  --notes "real-small developer-profile scan"
```

This writes local report files into the scan output folder:

```text
SCAN_HISTORY_RECORD.json
SCAN_HISTORY_RECORD.md
```

## Auto-record a baseline-aware scan

```powershell
python .\pooleshield_operator.py file-av-scan-baseline `
  --config .\pooleshield_config.json `
  --path "$env:USERPROFILE\Desktop\PooleShieldRealScanSmall" `
  --record-history `
  --history-notes "developer profile clean scan" `
  --clean-output `
  --bundle-output `
  --privacy-bundle
```

The local config can also set:

```json
{
  "defaults": {
    "history_db": "local_history/pooleshield_scan_history.sqlite",
    "record_history": true
  }
}
```

## List recent scans

```powershell
python .\pooleshield_operator.py history-list `
  --history-db .\local_history\pooleshield_scan_history.sqlite `
  --limit 10
```

Optionally write local JSON/CSV/Markdown history reports:

```powershell
python .\pooleshield_operator.py history-list `
  --history-db .\local_history\pooleshield_scan_history.sqlite `
  --limit 10 `
  --output-dir .\out\scan_history `
  --bundle-output `
  --privacy-bundle
```

## Show one scan

```powershell
python .\pooleshield_operator.py history-show `
  --history-db .\local_history\pooleshield_scan_history.sqlite `
  --scan-id 1
```

## Privacy and Git safety

Local history files are private and must not be committed. v3.9 updates `.gitignore` and the repo safety checker to block:

```text
local_history/
*.sqlite
*.sqlite3
*.db
pooleshield_scan_history.*
```

Keep the database local. Use privacy bundles for sharing scan results.
