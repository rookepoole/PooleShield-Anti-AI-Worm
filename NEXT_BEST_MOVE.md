# Next Best Move

Test PooleShield v3.8 locally:

```powershell
python -m pytest -q
python .\tools\repo_safety_check.py --root .
python .\pooleshield_operator.py profile-list
python .\pooleshield_operator.py profile-show --name developer
```

Then run a config-driven baseline-aware file-AV scan using `--scan-profile developer`.

If clean, push v3.8 to GitHub. Next build after v3.8: v3.9 local scan history.
