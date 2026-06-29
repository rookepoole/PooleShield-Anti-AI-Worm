# Next Best Move

Test PooleShield v4.3 locally and verify the Baseline Manager UI path.

```powershell
python -m pytest -q
python .\tools\repo_safety_check.py --root .
python .\tools\privacy_leak_check.py --root .
python .\pooleshield_operator.py desktop --status
```

Verify the metadata-only baseline loader:

```powershell
python .\pooleshield_operator.py baseline-load `
  --baseline C:\path\to\trusted_file_baseline.json `
  --decision ALLOW_LOG `
  --limit 25 `
  --output .\baseline_response.json
```

Optional baseline diff check:

```powershell
python .\pooleshield_operator.py baseline-diff `
  --baseline-a C:\path\to\old_trusted_file_baseline.json `
  --baseline-b C:\path\to\new_trusted_file_baseline.json `
  --limit 25 `
  --output .\baseline_diff_response.json
```

Run a baseline-aware scan either from the UI or from the CLI. If using the CLI for a reproducible v4.3 bundle:

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
out\file_av_desktop_v4_3\pooleshield_results_bundle.zip
```

If the bundle verifies clean, push v4.3. After v4.3, continue to v4.4 Rule Pack Editor UI.
