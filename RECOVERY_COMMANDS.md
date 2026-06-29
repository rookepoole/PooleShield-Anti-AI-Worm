# Recovery Commands

## Run tests and repo safety checks

```powershell
cd "C:\Users\rookp\Desktop\PooleShield-Anti-AI-Worm"
python -m pytest -q
python .\tools\repo_safety_check.py --root .
```

## Remove private/generated files from Git index if needed

```powershell
git rm -r --cached --ignore-unmatch out local_trust extracted_dat_text extracted_dat_content extracted_text_like __pycache__ .pytest_cache
```

## Push v3.6 after local checks pass

```powershell
git add .
git status --short
git commit -m "Release PooleShield v3.6 CI safety checks"
git push origin main
```
