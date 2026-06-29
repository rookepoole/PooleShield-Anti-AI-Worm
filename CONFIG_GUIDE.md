# PooleShield Configuration Guide

Version: 3.8.0

PooleShield v3.8 adds a local JSON configuration system so operators do not need to repeat baseline, rule-pack, output, risk-profile, and privacy defaults on every command.

## Privacy rule

A real `pooleshield_config.json` can contain machine-specific paths such as a local trusted baseline. Keep local configs private unless they contain only public-safe placeholder paths. Do not commit private baselines or scan outputs.

## Create a local config

```powershell
python .\pooleshield_operator.py config-init --config .\pooleshield_config.json
```

Overwrite an existing local config:

```powershell
python .\pooleshield_operator.py config-init --config .\pooleshield_config.json --force
```

## Validate a config

```powershell
python .\pooleshield_operator.py config-validate --config .\pooleshield_config.json
```

Show the effective merged config:

```powershell
python .\pooleshield_operator.py config-show --config .\pooleshield_config.json
```

## Example config fields

```json
{
  "defaults": {
    "output_root": "out",
    "file_av_output_dir": "out/file_av_scan",
    "file_av_baseline_scan_output_dir": "out/file_av_baseline_scan",
    "rule_pack": "examples/rule_packs/file_av_rules.default.json",
    "baseline": "local_trust/trusted_file_baseline.json",
    "risk_profile": "standard",
    "policy_profile": "balanced",
    "privacy_bundle": true,
    "bundle_output": false
  },
  "limits": {
    "max_bytes_per_file": 5242880,
    "max_archive_entries": 500,
    "max_archive_entry_bytes": 2097152
  }
}
```

## Use config with baseline-aware scan

After setting `defaults.baseline` and `defaults.rule_pack`, this shorter command is enough:

```powershell
python .\pooleshield_operator.py file-av-scan-baseline `
  --config .\pooleshield_config.json `
  --path "$env:USERPROFILE\Desktop\PooleShieldRealScanSmall" `
  --clean-output `
  --bundle-output `
  --privacy-bundle
```

The command will resolve these from config unless explicitly overridden:

- `--baseline`
- `--output-dir`
- `--rule-pack`
- `--risk-profile`
- file/archive size limits

## Use config with rule-pack validation

```powershell
python .\pooleshield_operator.py rule-pack-validate --config .\pooleshield_config.json
```

## Safe override pattern

Command-line values win over config values. For example:

```powershell
python .\pooleshield_operator.py file-av-scan-baseline `
  --config .\pooleshield_config.json `
  --path .\sample_folder `
  --risk-profile developer `
  --output-dir .\out\developer_scan
```

## Validation behavior

The config validator checks:

- valid risk profile
- valid policy profile
- positive integer scan limits
- safety flags remain true
- required default path strings exist in the config

`--require-existing-paths` warns if configured rule-pack or baseline paths do not exist yet. This is a warning because new users may create a config before building a trusted baseline.

## v3.8 scan profile default

v3.8 adds `defaults.scan_profile` so the local config can select one named scan behavior.

Example:

```json
{
  "defaults": {
    "scan_profile": "developer"
  }
}
```

Available scan profiles:

```text
quick
standard
developer
strict
deep
archive-heavy
privacy-sensitive
```

Use `profile-list` and `profile-show` to inspect the effective profile.

```powershell
python .\pooleshield_operator.py profile-list --config .\pooleshield_config.json
python .\pooleshield_operator.py profile-show --name developer --config .\pooleshield_config.json
```
