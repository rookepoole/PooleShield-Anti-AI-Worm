# PooleShield v5.0.0

PooleShield is a privacy-first second-opinion defensive scanner for suspicious files, archives, scripts, AI-agent logs, exported chat/data bundles, and local workflow artifacts.

PooleShield is defensive only. It reads local artifacts, scores static/local risk signals, and writes review reports. It does **not** execute scanned content, follow links, send emails, delete files, quarantine files, kill processes, install drivers, or modify the scanned corpus.

## v5.0 milestone

v5.0 adds the first **portable Windows build path** on top of the v4.0 Engine API and the v4.1–v4.4 desktop UI work:

```text
pooleshield_portable_launcher.py
portable_build.py
build_portable_windows.ps1
requirements-build.txt
PORTABLE_WINDOWS_BUILD_GUIDE.md
operator command: portable-build
engine operation: portable.status
engine operation: portable.plan
```

The portable build helper is a local PyInstaller workflow. It can report build status, produce a build plan, write a local PyInstaller spec, and optionally run PyInstaller on Windows. Generated build artifacts are local-only and must not be committed.

## Quick local checks

```powershell
python -m pytest -q
python .\tools\repo_safety_check.py --root .
python .\tools\privacy_leak_check.py --root .
python .\pooleshield_operator.py desktop --status
python .\pooleshield_operator.py portable-build --status
```

## Portable build smoke test

```powershell
python .\pooleshield_operator.py portable-build --dry-run --output .\portable_build_plan.json
python .\pooleshield_operator.py portable-build --write-spec --force
python .\pooleshield_portable_launcher.py --status
```

To build on Windows:

```powershell
python -m pip install -r requirements-ui.txt -r requirements-build.txt
python .\pooleshield_operator.py portable-build --run-pyinstaller --clean --output .\portable_build_result.json
```

Expected local output:

```text
dist\PooleShield\PooleShield.exe
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

Privacy bundles and repo commits must exclude content-bearing/private/generated files such as:

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
portable_build_plan.json
portable_build_result.json
dist/
build/
*.exe
*.msi
*.msix
pooleshield_results_bundle.zip
```

The file AV scanner does not include raw file contents or matched snippets in its reports.

## Guide files

- `ENGINE_API_GUIDE.md` — Python/JSON Engine API bridge
- `DESKTOP_UI_GUIDE.md` — Desktop prototype
- `RESULTS_UI_GUIDE.md` — Results UI
- `BASELINE_MANAGER_UI_GUIDE.md` — Baseline Manager UI
- `RULE_PACK_EDITOR_UI_GUIDE.md` — Rule Pack Editor UI
- `PORTABLE_WINDOWS_BUILD_GUIDE.md` — Portable Windows build workflow
