# Recovery Commands

## Run tests and repo safety checks

```powershell
cd "C:\Users\rookp\Desktop\PooleShield-Anti-AI-Worm"
python -m pytest -q
python .\tools\repo_safety_check.py --root .
```

## Inspect scan profiles

```powershell
python .\pooleshield_operator.py profile-list
python .\pooleshield_operator.py profile-show --name developer
```

## Run config-driven baseline-aware scan with developer profile

```powershell
python .\pooleshield_operator.py file-av-scan-baseline `
  --config .\pooleshield_config.json `
  --scan-profile developer `
  --path "$env:USERPROFILE\Desktop\PooleShieldRealScanSmall" `
  --clean-output `
  --bundle-output `
  --privacy-bundle
```

## Remove private/generated files from Git index if needed

```powershell
git rm -r --cached --ignore-unmatch out local_trust extracted_dat_text extracted_dat_content extracted_text_like __pycache__ .pytest_cache pooleshield_config.json
```
