# PooleShield File AV Rule Pack Guide

Version: 3.4.2

PooleShield v3.4 adds optional local JSON rule packs for read-only file/folder AV scans.

Rule packs can add labels and risk deltas. They cannot execute files, delete files, quarantine files, modify files, or silently allow files. Broad trust belongs in the trusted hash baseline, not in rule packs.

## Validate the default pack

```powershell
python .\pooleshield_operator.py rule-pack-validate --rule-pack .\examples\rule_packs\file_av_rules.default.json --output-dir .\out\rule_pack_validate --clean-output --bundle-output --privacy-bundle
```

## Use a rule pack in a scan

```powershell
python .\pooleshield_operator.py file-av-scan-baseline `
  --path "$env:USERPROFILE\Desktop\PooleShieldRealScanSmall" `
  --baseline "C:\Users\rookp\pooleshield_v3_2_package\local_trust\trusted_file_baseline.json" `
  --rule-pack .\examples\rule_packs\file_av_rules.default.json `
  --output-dir .\out\file_av_real_small_rules `
  --clean-output `
  --risk-profile developer `
  --bundle-output `
  --privacy-bundle
```

## Supported rule types

- `filename_regex`
- `path_regex`
- `archive_entry_regex`
- `text_regex`
- `extension`
- `magic_type`
- `label_has`

## Privacy

Privacy bundles include rule metadata and decisions, not raw scanned file contents.
