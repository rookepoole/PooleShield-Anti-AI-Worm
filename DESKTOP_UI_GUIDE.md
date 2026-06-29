# PooleShield v4.1 Desktop UI Prototype Guide

PooleShield v4.1 adds the first local desktop UI prototype on top of the v4.0 Engine API.

The UI is still defensive and local-only:

- no scanned-file execution
- no deletion
- no automatic quarantine
- no process killing
- no Windows service
- no kernel/minifilter driver
- no raw scanned contents uploaded by default

## Dependency

The desktop prototype uses PySide6 / Qt. The CLI and tests still work without PySide6.

```powershell
python -m pip install PySide6
```

Check whether the UI dependency is available:

```powershell
python .\pooleshield_desktop.py --status
```

Launch the UI directly:

```powershell
python .\pooleshield_desktop.py
```

Or launch through the operator CLI:

```powershell
python .\pooleshield_operator.py desktop
```

## Screens in v4.1

- Dashboard: validate config and list scan profiles.
- Scan Folder: run a baseline-aware folder scan using the Engine API.
- History: list local metadata-only scan history rows.
- About: shows the safety boundary and prototype status.

## Recommended local smoke test

```powershell
python -m pytest -q
python .\tools\repo_safety_check.py --root .
python .\tools\privacy_leak_check.py --root .
python .\pooleshield_desktop.py --status
```

Then install PySide6 and launch:

```powershell
python -m pip install PySide6
python .\pooleshield_operator.py desktop
```

## UI scan output

The default UI scan output is:

```text
out/file_av_desktop_v4_1/
```

Upload only the generated privacy bundle if you want review:

```text
out/file_av_desktop_v4_1/pooleshield_results_bundle.zip
```

Do not commit local config, local history DBs, baselines, output folders, or result bundles.
