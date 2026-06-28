# Empty Scan Guide

PooleShield v1.8 adds diagnostics for the most common real-scan mistake: scanning a folder that exists but contains no supported text/log/export files.

A valid scan target should contain at least one readable text-like file, such as:

- `.txt`, `.md`, `.log`
- `.jsonl`, `.json`, `.csv`
- `.yaml`, `.yml`, `.toml`, `.ini`, `.cfg`, `.conf`
- `.html`, `.htm`, `.xml`
- `.eml`, `.msg`

## Diagnose a folder

```powershell
python .\pooleshield_operator.py doctor --path "C:\Users\rookp\Documents\test_pooleshield_scan" --clean-output --bundle-output
```

## Seed safe sample files

This writes inert test notes/logs into the chosen folder so you can verify that the real scan path is working:

```powershell
python .\pooleshield_operator.py doctor --path "C:\Users\rookp\Documents\test_pooleshield_scan" --write-sample-files --clean-output --bundle-output
```

Then run:

```powershell
python .\pooleshield_operator.py scan --path "C:\Users\rookp\Documents\test_pooleshield_scan" --output-dir .\out\real_scan --clean-output --policy-profile balanced --bundle-output
```

PooleShield never executes these files; it only reads text-like content and writes reports.
