# Recovery Commands

## Test v3.3

```powershell
cd "C:\Users\rookp\pooleshield_v3_3_package"
python -m pytest -q
```

## Baseline-aware file AV scan

```powershell
python .\pooleshield_operator.py file-av-scan-baseline `
  --path "$env:USERPROFILE\Desktop\PooleShieldRealScanSmall" `
  --baseline "C:\Users\rookp\pooleshield_v3_2_package\local_trust\trusted_file_baseline.json" `
  --output-dir .\out\file_av_real_small_baseline `
  --clean-output `
  --risk-profile developer `
  --bundle-output `
  --privacy-bundle
```
