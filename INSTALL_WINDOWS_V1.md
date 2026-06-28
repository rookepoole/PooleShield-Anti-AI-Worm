# Install and run PooleShield v1.8 on Windows

```powershell
cd "C:\Users\rookp"
Remove-Item -Recurse -Force ".\pooleshield_v1_3_package" -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path ".\pooleshield_v1_3_package" | Out-Null
Expand-Archive -Path ".\pooleshield_v1_3_package.zip" -DestinationPath ".\pooleshield_v1_3_package" -Force
cd ".\pooleshield_v1_3_package"

dir .\pooleshield_operator.py
dir .\examples\corpus_scan_fixture

python .\pooleshield_operator.py demo --clean-output
```

Real scan example:

```powershell
python .\pooleshield_operator.py scan --path "C:\Users\rookp\Documents\agent_logs" --output-dir .\out\real_scan --clean-output --policy-profile balanced
```

Apply edited review ledger:

```powershell
python .\pooleshield_operator.py apply-ledger --output-dir .\out\real_scan --ledger .\out\real_scan\review_ledger_template.csv
```


## Recommended demo command for uploads

```powershell
python .\pooleshield_operator.py demo --clean-output --bundle-output
```

Upload this single file:

```text
out\demo\pooleshield_results_bundle.zip
```


## Empty scan check

If your real scan reports `0` events, the selected folder probably contains no supported text/log/export files. Run:

```powershell
python .\pooleshield_operator.py doctor --path "C:\Users\rookp\Documents\test_pooleshield_scan" --clean-output --bundle-output
```

To create inert sample files:

```powershell
python .\pooleshield_operator.py doctor --path "C:\Users\rookp\Documents\test_pooleshield_scan" --write-sample-files --clean-output --bundle-output
```
