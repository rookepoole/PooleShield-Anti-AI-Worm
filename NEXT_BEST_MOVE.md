# Next Best Move

Test PooleShield v4.0 locally:

```powershell
python -m pytest -q
python .\tools\repo_safety_check.py --root .
python .\pooleshield_operator.py profile-list
python .\pooleshield_operator.py profile-show --name developer
```

Test the Engine API bridge:

```powershell
@'
{
  "operation": "profile.show",
  "params": {
    "name": "developer"
  }
}
'@ | Set-Content .\engine_request.json

python .\pooleshield_operator.py engine-dispatch --request .\engine_request.json --output .\engine_response.json
```

Then run a config-driven baseline-aware file-AV scan through the v4.0 engine path:

```powershell
python .\pooleshield_operator.py file-av-scan-baseline `
  --config .\pooleshield_config.json `
  --path "$env:USERPROFILE\Desktop\PooleShieldRealScanSmall" `
  --clean-output `
  --bundle-output `
  --privacy-bundle
```

Expected final verdict remains:

```text
CLEAN_AFTER_POLICY
0 REQUIRE_APPROVAL
0 BLOCK
0 QUARANTINE
```

Upload the privacy bundle for verification before pushing v4.0.
