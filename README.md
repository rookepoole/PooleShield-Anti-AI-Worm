# PooleShield v5.1.1

PooleShield is a privacy-first second-opinion defensive scanner for suspicious files, archives, scripts, AI-agent logs, exported chat/data bundles, and local workflow artifacts.

PooleShield is defensive only. It reads local artifacts, scores static/local risk signals, and writes review reports. It does **not** execute scanned content, follow links, send emails, delete files, quarantine files, kill processes, install drivers, or modify the scanned corpus.

## v5.1.1 milestone

v5.1.1 patches the Windows installer tooling on top of the verified v5.0 portable build:

```text
installer_build.py
build_installer_windows.ps1
WINDOWS_INSTALLER_BUILD_GUIDE.md
requirements-installer.txt
installer-build
installer.status / installer.plan Engine API operations
```

The installer helper can inspect a portable folder, generate an Inno Setup script, show a dry-run compile plan, and optionally run the Inno Setup compiler locally when the operator explicitly requests it. This patch fixes `installer-build --run-iscc --portable-dir ...` so the final compile step uses the supplied portable folder instead of the default `dist/PooleShield` path.

## Quick local checks

```powershell
python -m pytest -q
python .\tools\repo_safety_check.py --root .
python .\tools\privacy_leak_check.py --root .
python .\pooleshield_operator.py desktop --status
```

## Installer tooling smoke test

```powershell
python .\pooleshield_operator.py installer-build --status --portable-dir C:\Users\rookp\Desktop\PooleShieldPortable_v5_0_RELEASE
python .\pooleshield_operator.py installer-build --dry-run --portable-dir C:\Users\rookp\Desktop\PooleShieldPortable_v5_0_RELEASE --output .\installer_build_plan.json
python .\pooleshield_operator.py installer-build --write-script --portable-dir C:\Users\rookp\Desktop\PooleShieldPortable_v5_0_RELEASE --force
```

Do not commit installer outputs, build folders, generated scripts, result bundles, local configs, baselines, or history databases.

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
installer_output/
build/
dist/
```

The file AV scanner does not include raw file contents or matched snippets in its reports.
