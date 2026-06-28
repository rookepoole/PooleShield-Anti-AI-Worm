# PooleShield Recovery Commands

## Run v3.2 tests

```powershell
cd "C:\Users\rookp\pooleshield_v3_2_package"
python -m pytest -q
```

## Build baseline from reviewed file AV decisions

```powershell
python .\pooleshield_operator.py file-av-build-baseline --output-dir .\out\file_av_real_small_dev --baseline-path .\local_trust\trusted_file_baseline.json --bundle-output --privacy-bundle
```

## Apply baseline to a rescan

```powershell
python .\pooleshield_operator.py file-av-apply-baseline --output-dir .\out\file_av_real_small_dev_rescan --baseline .\local_trust\trusted_file_baseline.json --bundle-output --privacy-bundle
```
