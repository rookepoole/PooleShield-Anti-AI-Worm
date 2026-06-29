# Next Best Move

Test PooleShield v3.9 locally:

```powershell
python -m pytest -q
python .	oolsepo_safety_check.py --root .
python .\pooleshield_operator.py history-init --history-db .\local_history\pooleshield_scan_history.sqlite
```

Then run a config-driven baseline-aware file-AV scan with scan history enabled:

```powershell
python .\pooleshield_operator.py file-av-scan-baseline `
  --config .\pooleshield_config.json `
  --path "$env:USERPROFILE\Desktop\PooleShieldRealScanSmall" `
  --record-history `
  --clean-output `
  --bundle-output `
  --privacy-bundle
```

Verify `SCAN_HISTORY_RECORD.json`, `SCAN_HISTORY_RECORD.md`, and `history-list` output.

If clean, push v3.9 to GitHub. Next build after v3.9: v4.0 engine API refactor for UI readiness.
