$ErrorActionPreference = "Stop"

Write-Host "=== PooleShield v5.2.1 portable Windows build ==="

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

if (-not (Test-Path ".\pooleshield_operator.py")) {
  Write-Host "ERROR: run this script from the PooleShield package/repo root."
  exit 1
}

Write-Host "=== Create build venv ==="
python -m venv .venv-build
.\.venv-build\Scripts\python.exe -m pip install --upgrade pip
.\.venv-build\Scripts\python.exe -m pip install -r requirements-ui.txt -r requirements-build.txt

Write-Host "=== Safety checks ==="
.\.venv-build\Scripts\python.exe -m pytest -q
.\.venv-build\Scripts\python.exe .\tools\repo_safety_check.py --root .
.\.venv-build\Scripts\python.exe .\tools\privacy_leak_check.py --root .

Write-Host "=== Portable build status ==="
.\.venv-build\Scripts\python.exe .\pooleshield_operator.py portable-build --status

Write-Host "=== Write PyInstaller spec ==="
.\.venv-build\Scripts\python.exe .\pooleshield_operator.py portable-build --write-spec --force --output .\portable_build_plan.json

Write-Host "=== Run PyInstaller ==="
.\.venv-build\Scripts\python.exe .\pooleshield_operator.py portable-build --run-pyinstaller --clean --output .\portable_build_result.json

Write-Host "=== Expected portable folder ==="
Write-Host (Join-Path $Root "dist\PooleShield")
Write-Host "Do not commit dist/, build/, .venv-build/, portable_build_result.json, or portable_build_plan.json."
