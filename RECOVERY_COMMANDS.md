# Recovery Commands

## Run tests and repo safety checks

```powershell
cd "C:\Users\rookp\Desktop\PooleShield-Anti-AI-Worm"
python -m pytest -q
python .\tools\repo_safety_check.py --root .
```

## Create and validate local config

```powershell
python .\pooleshield_operator.py config-init --config .\pooleshield_config.json --force
python .\pooleshield_operator.py config-validate --config .\pooleshield_config.json
python .\pooleshield_operator.py config-show --config .\pooleshield_config.json
```

## Remove private/generated files from Git index if needed

```powershell
git rm -r --cached --ignore-unmatch out local_trust extracted_dat_text extracted_dat_content extracted_text_like __pycache__ .pytest_cache pooleshield_config.json .pooleshield_config.json
```

## Push v3.7 after local checks pass

```powershell
git add .
git status --short
git commit -m "Release PooleShield v3.7 configuration system"
git push origin main
```
