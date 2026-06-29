$ErrorActionPreference = "Stop"
Write-Host "=== PooleShield v5.1.1 Windows installer build helper ==="
python .\pooleshield_operator.py installer-build --status
python .\pooleshield_operator.py installer-build --dry-run --output .\installer_build_plan.json
python .\pooleshield_operator.py installer-build --write-script --force
Write-Host "To compile the installer, install Inno Setup 6, then run:"
Write-Host "python .\pooleshield_operator.py installer-build --run-iscc --output .\installer_build_result.json"
