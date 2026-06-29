# Next Best Move

1. Test v3.7 locally:

```powershell
python -m pytest -q
python .\tools\repo_safety_check.py --root .
```

2. Initialize and validate a local config:

```powershell
python .\pooleshield_operator.py config-init --config .\pooleshield_config.json --force
python .\pooleshield_operator.py config-validate --config .\pooleshield_config.json
```

3. Run a config-driven baseline-aware file AV scan.

4. Push v3.7 if clean.

5. Next build after v3.7: v3.8 scan profiles.
