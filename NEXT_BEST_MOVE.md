# Next Best Move

Test PooleShield v4.2 locally and verify the Results UI path.

```powershell
python -m pytest -q
python .\tools\repo_safety_check.py --root .
python .\tools\privacy_leak_check.py --root .
python .\pooleshield_operator.py desktop --status
```

Install the UI dependency and launch the prototype:

```powershell
python -m pip install PySide6
python .\pooleshield_operator.py desktop
```

Run a baseline-aware scan either from the UI or from the CLI. If using the CLI for a reproducible v4.2 bundle:

```powershell
python .\pooleshield_operator.py file-av-scan-baseline `
  --config .\pooleshield_config.json `
  --path "$env:USERPROFILE\Desktop\PooleShieldRealScanSmall" `
  --clean-output `
  --bundle-output `
  --privacy-bundle
```

Verify the metadata-only Results loader:

```powershell
python .\pooleshield_operator.py results-load `
  --output-dir .\out\file_av_desktop_v4_2 `
  --decision ALLOW_LOG `
  --limit 25 `
  --output .\results_response.json
```

Upload only the generated privacy bundle:

```text
out\file_av_desktop_v4_2\pooleshield_results_bundle.zip
```

If the bundle verifies clean, push v4.2. After v4.2, continue to v4.3 Baseline Manager UI.
