# PooleShield Scan Profile Guide

Version: 5.2.1

PooleShield v3.8 adds named file-AV scan profiles. Profiles tune scan breadth and limits while preserving the same safety boundary: read-only, dry-run only, no execution, no deletion, no quarantine, no process killing, no hooks, and no drivers.

## Built-in profiles

```text
quick
standard
developer
strict
deep
archive-heavy
privacy-sensitive
```

## What profiles control

Profiles can set:

```text
risk_profile
recursive
include_hidden
scan_archives
max_bytes_per_file
max_archive_entries
max_archive_entry_bytes
privacy_bundle
```

Profiles do not silently trust files and do not override the trusted baseline. A file only becomes trusted after the operator deliberately reviews it and adds it to the local baseline.

## Commands

List profiles:

```powershell
python .\pooleshield_operator.py profile-list
```

Show one profile:

```powershell
python .\pooleshield_operator.py profile-show --name developer
```

Use a profile in a baseline-aware scan:

```powershell
python .\pooleshield_operator.py file-av-scan-baseline `
  --config .\pooleshield_config.json `
  --scan-profile developer `
  --path "$env:USERPROFILE\Desktop\PooleShieldRealScanSmall" `
  --clean-output `
  --bundle-output `
  --privacy-bundle
```

## Recommended use

| Profile | Use case |
|---|---|
| `quick` | Fast trusted-folder triage; skips archive expansion. |
| `standard` | Normal second-opinion scan. |
| `developer` | Source trees and dev packages where scripts are expected but still audited. |
| `strict` | Untrusted downloads or suspicious folders. |
| `deep` | Slower broad scan with larger file/archive limits. |
| `archive-heavy` | ZIP/JAR/Office-container-heavy folders. |
| `privacy-sensitive` | Private folders where smaller content-read limits are preferred. |

## Local config

Add this to `pooleshield_config.json`:

```json
{
  "defaults": {
    "scan_profile": "developer"
  }
}
```

Optional local overrides can be placed under `scan_profiles`. Keep local configs private and do not commit them to GitHub.
