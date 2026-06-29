# Next Best Move

Test PooleShield v4.1 locally and verify the desktop UI prototype path.

```powershell
python -m pytest -q
python .	oolsepo_safety_check.py --root .
python .	ools\privacy_leak_check.py --root .
python .\pooleshield_operator.py desktop --status
```

Install the UI dependency and launch the prototype:

```powershell
python -m pip install PySide6
python .\pooleshield_operator.py desktop
```

Run a baseline-aware scan either from the UI or from the CLI. If using the CLI for a reproducible v4.1 bundle:

```powershell
python .\pooleshield_operator.py file-av-scan-baseline `
  --config .\pooleshield_config.json `
  --path "$env:USERPROFILE\Desktop\PooleShieldRealScanSmall" `
  --clean-output `
  --bundle-output `
  --privacy-bundle
```

Upload only the generated privacy bundle:

```text
outile_av_desktop_v4_1\pooleshield_results_bundle.zip
```

If the bundle verifies clean, push v4.1. After v4.1, continue toward v4.2 Results UI: sortable results table, filtering, detail panel, and privacy-bundle export button.
