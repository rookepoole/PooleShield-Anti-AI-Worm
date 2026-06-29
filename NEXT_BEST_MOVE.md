# Next Best Move

1. Run local tests and repo safety checks:

```powershell
python -m pytest -q
python .\tools\repo_safety_check.py --root .
```

2. Push v3.6.2 to GitHub.

3. Confirm the CI run passes and the Node 20 deprecation warning is gone.

4. Next build after v3.6.2: v3.7 configuration system.
