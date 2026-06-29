# PooleShield Desktop UI Guide

Version: 5.3.0

PooleShield v5.3.0 provides a local desktop prototype on top of the Engine API with Results, Baseline Manager, and Rule Pack Editor tabs.

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

## Screens in v5.3.0

- Dashboard: validate config and list scan profiles.
- Scan Folder: run a baseline-aware folder scan using the Engine API.
- Results: load metadata-only scan results, filter rows, inspect details, and copy the privacy-bundle path.
- Baseline: load trusted baseline metadata, filter entries, copy SHA/path values, and compare two baseline JSON files.
- Rule Packs: load rule-pack metadata, validate rules, filter rows, export an editable copy, and save selected-rule edits to a JSON copy.
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
out/file_av_desktop_v5_1/
```

Upload only the generated privacy bundle if you want review:

```text
out/file_av_desktop_v5_1/pooleshield_results_bundle.zip
```

Do not commit local config, local history DBs, baselines, local edited rule packs, output folders, or result bundles.


## Portable Windows build

v5.3.0 adds a portable build helper. The desktop app can be launched from source with `python .\pooleshield_operator.py desktop` or packaged locally with `python .\pooleshield_operator.py portable-build --run-pyinstaller --clean`. Generated `dist/` and `build/` folders are local artifacts and must not be committed.
