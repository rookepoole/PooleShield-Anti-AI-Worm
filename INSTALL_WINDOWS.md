# PooleShield v1.8 Windows Install

Use a clean destination folder so paths do not become nested.

```powershell
cd "C:\Users\rookp"
Remove-Item -Recurse -Force ".\pooleshield_v0_9_package" -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path ".\pooleshield_v0_9_package" | Out-Null
Expand-Archive -Path ".\pooleshield_v0_9_package.zip" -DestinationPath ".\pooleshield_v0_9_package" -Force
cd ".\pooleshield_v0_9_package"
dir .\pooleshield_cycle10.py
dir .\examples\corpus_scan_fixture
```

Then run:

```powershell
python .\pooleshield_cycle10.py --path .\examples\corpus_scan_fixture --policy-profile balanced --demo-review-decisions --clean-output
```

Outputs appear in `out\cycle10\`.
