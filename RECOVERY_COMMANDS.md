# PooleShield Recovery Commands

## Test v3.1

```powershell
python -m pytest -q
```

## Run file AV scan

```powershell
python .\pooleshield_operator.py scan-folder --path "$env:USERPROFILE\Desktop\PooleShieldRealScanSmall" --output-dir .\outile_av_real_small_dev --clean-output --risk-profile developer --bundle-output --privacy-bundle
```

## Build and apply file AV review ledger

```powershell
python .\pooleshield_operator.py file-av-review --output-dir .\outile_av_real_small_dev --bundle-output --privacy-bundle
python .\pooleshield_operator.py file-av-apply-ledger --output-dir .\outile_av_real_small_dev --ledger .\outile_av_real_small_devile_av_review_ledger_template.csv --bundle-output --privacy-bundle
```
