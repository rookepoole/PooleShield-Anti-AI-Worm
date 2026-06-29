# PooleShield v5.1.1 Portable Windows Build Guide

PooleShield v5.1.1 adds the first portable Windows build path. This release does **not** add real-time protection, a Windows service, kernel hooks, automatic quarantine, or installer behavior. It only creates a local portable desktop app folder from the existing Engine API and desktop UI.

## Safety boundary

The portable build helper:

- does not scan user files
- does not execute scanned files
- does not delete files
- does not quarantine files
- does not install drivers or hooks
- does not upload raw contents
- does not include local baselines, configs, history DBs, result bundles, or output folders in the build package

Generated build folders must stay local and uncommitted.

## Requirements

Run this on Windows:

```powershell
python -m pip install -r requirements-ui.txt -r requirements-build.txt
```

## Smoke checks

```powershell
python .\pooleshield_operator.py portable-build --status
python .\pooleshield_operator.py portable-build --dry-run --output .\portable_build_plan.json
python .\pooleshield_operator.py portable-build --write-spec --force
python .\pooleshield_portable_launcher.py --status
```

## Build portable folder

```powershell
python .\pooleshield_operator.py portable-build --run-pyinstaller --clean --output .\portable_build_result.json
```

Expected local output:

```text
dist\PooleShield\PooleShield.exe
```

You can also run the full helper script:

```powershell
.\build_portable_windows.ps1
```

## What to upload for review

For this v5.1.1 source-package test, upload the normal PooleShield privacy results bundle after running the scan command. Do **not** upload `dist/PooleShield` unless you intentionally want the executable bundle inspected.

## Do not commit

```text
dist/
build/
.venv-build/
portable_build_plan.json
portable_build_result.json
*.exe
*.msi
*.msix
```
