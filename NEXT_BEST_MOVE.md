# Next Best Move

Test PooleShield v5.1 locally and verify the Windows installer tooling path.

```powershell
python -m pytest -q
python .\tools\repo_safety_check.py --root .
python .\tools\privacy_leak_check.py --root .
python .\pooleshield_operator.py desktop --status
python .\pooleshield_operator.py installer-build --status --portable-dir C:\Users\rookp\Desktop\PooleShieldPortable_v5_0_RELEASE
```

Verify the installer build plan without running Inno Setup:

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

Optional actual installer compile after installing Inno Setup 6:

```powershell
python .\pooleshield_operator.py installer-build `
  --run-iscc `
  --portable-dir C:\Users\rookp\Desktop\PooleShieldPortable_v5_0_RELEASE `
  --output .\installer_build_result.json
```

Run a baseline-aware scan using the CLI for a reproducible v5.1 bundle:

```powershell
python .\pooleshield_operator.py file-av-scan-baseline `
  --config .\pooleshield_config.json `
  --path C:\path\to\scan-folder `
  --clean-output `
  --bundle-output `
  --privacy-bundle
```

Upload only the generated privacy bundle:

```text
out\file_av_desktop_v5_1\pooleshield_results_bundle.zip
```

If the bundle verifies clean, push v5.1. After v5.1, compile the actual installer locally and verify installer metadata.
