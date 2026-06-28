# PooleShield v3.0.1 Recovery Commands

Run tests:

```powershell
python -m pytest -q
```

Run file AV fixture:

```powershell
python .\pooleshield_operator.py scan-folder --path .\examples\file_av_fixture --output-dir .\out\file_av_demo --clean-output --bundle-output --privacy-bundle
```

Run batch rollup after DAT scans:

```powershell
python .\pooleshield_operator.py batch-rollup --path "dat_batch_0050=.\out\dat_batch_0050\dat_chat_scan" --output-dir .\out\dat_archive_rollup --bundle-output --privacy-bundle
```
