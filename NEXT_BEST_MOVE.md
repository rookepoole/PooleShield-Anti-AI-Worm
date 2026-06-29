# Next Best Move

Test PooleShield v5.1.1 locally and verify the Windows installer `--portable-dir` patch.

v5.1.1 fixes the v5.1 bug where `installer-build --run-iscc --portable-dir ...` ignored the supplied portable folder during the final compile step.

```powershell
python -m pytest -q
python .\tools\repo_safety_check.py --root .
python .\tools\privacy_leak_check.py --root .
python .\pooleshield_operator.py desktop --status
python .\pooleshield_operator.py installer-build --status --portable-dir C:\Users\rookp\Desktop\PooleShieldPortable_v5_0_RELEASE
```

Verify the installer build plan and script using the explicit portable folder:

```powershell
python .\pooleshield_operator.py installer-build `
  --dry-run `
  --portable-dir C:\Users\rookp\Desktop\PooleShieldPortable_v5_0_RELEASE `
  --output .\installer_build_plan.json

python .\pooleshield_operator.py installer-build `
  --write-script `
  --portable-dir C:\Users\rookp\Desktop\PooleShieldPortable_v5_0_RELEASE `
  --force
```

Compile the installer without copying the portable app into `dist\PooleShield`:

```powershell
python .\pooleshield_operator.py installer-build `
  --run-iscc `
  --portable-dir C:\Users\rookp\Desktop\PooleShieldPortable_v5_0_RELEASE `
  --force `
  --output .\installer_build_result.json
```

If that works, upload the metadata-only installer verification ZIP, not the installer executable.
