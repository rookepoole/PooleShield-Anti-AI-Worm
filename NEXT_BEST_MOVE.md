# Next Best Move

Test PooleShield v4.4 locally and verify the Rule Pack Editor UI path.

```powershell
python -m pytest -q
python .\tools\repo_safety_check.py --root .
python .\tools\privacy_leak_check.py --root .
python .\pooleshield_operator.py desktop --status
```

Verify metadata-only rule pack loading:

```powershell
python .\pooleshield_operator.py rule-pack-load `
  --rule-pack .\examples\rule_packs\file_av_rules.default.json `
  --enabled enabled `
  --limit 25 `
  --output .\rule_pack_response.json
```

Export a local editable copy:

```powershell
python .\pooleshield_operator.py rule-pack-export-default `
  --output .\local_rule_packs\file_av_rules.editable.json `
  --force
```

Edit one selected rule into a copy:

```powershell
python .\pooleshield_operator.py rule-pack-update-rule `
  --rule-pack .\local_rule_packs\file_av_rules.editable.json `
  --output .\local_rule_packs\file_av_rules.edited.json `
  --index 0 `
  --disabled `
  --risk-delta 0.10
```

Run a baseline-aware scan either from the UI or from the CLI. If using the CLI for a reproducible v4.4 bundle:

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
out\file_av_desktop_v4_4\pooleshield_results_bundle.zip
```

If the bundle verifies clean, push v4.4. After v4.4, continue to v5.0 portable Windows build planning.
