# Next Best Move

Test PooleShield v5.0 locally and verify the portable Windows build path.

```powershell
python -m pytest -q
python .\tools\repo_safety_check.py --root .
python .\tools\privacy_leak_check.py --root .
python .\pooleshield_operator.py desktop --status
python .\pooleshield_operator.py portable-build --status
```

Verify the portable build plan without running PyInstaller:

```powershell
python .\pooleshield_operator.py portable-build --dry-run --output .\portable_build_plan.json
python .\pooleshield_operator.py portable-build --write-spec --force
python .\pooleshield_portable_launcher.py --status
```

Optional Windows portable build:

```powershell
python -m pip install -r requirements-ui.txt -r requirements-build.txt
python .\pooleshield_operator.py portable-build --run-pyinstaller --clean --output .\portable_build_result.json
```

Run a baseline-aware scan either from the UI or from the CLI. If using the CLI for a reproducible v5.0 bundle:

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
out\file_av_desktop_v5_0\pooleshield_results_bundle.zip
```

If the bundle verifies clean, push v5.0. After v5.0, continue toward v5.1 Windows installer planning.
