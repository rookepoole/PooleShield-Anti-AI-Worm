# PooleShield v5.3.0 Windows Installer Build Guide

PooleShield v5.3.0 adds local Windows installer tooling for the already-built portable app.

The installer path is still local and explicit:

- it reads the existing portable folder, usually `dist/PooleShield/`
- it writes a local Inno Setup script under `build/installer/`
- it can compile that script only if the operator explicitly runs `--run-iscc`
- it does not scan, execute, delete, quarantine, or trust scanned files
- it does not include local configs, baselines, history databases, scan outputs, or result bundles


## v5.3.0 patch note

`installer-build --run-iscc --portable-dir ...` now forwards the supplied portable folder into the final compile step. You no longer need to copy the portable app into `dist/PooleShield` as a workaround.

## Commands

Check readiness:

```powershell
python .\pooleshield_operator.py installer-build --status
```

Create a dry-run plan:

```powershell
python .\pooleshield_operator.py installer-build --dry-run --output .\installer_build_plan.json
```

Write the local Inno Setup script:

```powershell
python .\pooleshield_operator.py installer-build --write-script --force
```

Compile the installer after installing Inno Setup 6:

```powershell
python .\pooleshield_operator.py installer-build --run-iscc --portable-dir C:\Users\rookp\Desktop\PooleShieldPortable_v5_0_RELEASE --force --output .\installer_build_result.json
```

Generated installer artifacts are local build products and must not be committed:

```text
build/
installer_output/
installer_build_plan.json
installer_build_result.json
*.iss
*.exe
*.msi
*.msix
```

## Expected source folder

The installer uses the portable app folder produced by v5.0:

```text
dist/PooleShield/PooleShield.exe
```

If you moved the portable app outside the repo, pass `--portable-dir` to point at it.
