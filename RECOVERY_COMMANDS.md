# Recovery Commands

```powershell
cd "C:\Users\rookp\pooleshield_v3_5_package"
python -m pytest -q
python .\pooleshield_operator.py file-av-scan-baseline `
  --path "$env:USERPROFILE\Desktop\PooleShieldRealScanSmall" `
  --baseline "C:\Users\rookp\pooleshield_v3_2_package\local_trust\trusted_file_baseline.json" `
  --rule-pack .\examples\rule_packs\file_av_rules.default.json `
  --output-dir .\out\file_av_real_small_rules_summary `
  --clean-output `
  --risk-profile developer `
  --bundle-output `
  --privacy-bundle
Get-Content .\out\file_av_real_small_rules_summary\FINAL_SCAN_SUMMARY.md
```
