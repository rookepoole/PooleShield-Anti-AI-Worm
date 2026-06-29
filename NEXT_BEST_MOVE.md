# Next Best Move

1. Push v3.6.1 to fix the GitHub Actions CI bootstrap.

2. Confirm GitHub Actions passes on `main`.

3. Begin v3.7 configuration system.

Local pre-push check:

```powershell
python -m pytest -q
python .\tools\repo_safety_check.py --root .
```
