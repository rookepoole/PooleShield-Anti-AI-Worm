# PooleShield Engine API Guide

Version: 5.2.1

PooleShield v4.0 introduced a small Python engine layer so the CLI, desktop UI, and local process bridge can call the same backend functions. v5.2.1 extends that layer with metadata-only rule-pack loading and explicit rule-pack copy/update operations for the Rule Pack Editor UI.

## Safety boundary

The Engine API is still defensive and read-only toward scanned files. It does not execute scanned files, delete files, quarantine files, kill processes, install hooks/drivers, send network requests, or upload raw scanned contents. v5.2.1 can write only operator-requested rule-pack JSON copies.

## Python API

```python
from pooleshield_engine import (
    profile_show,
    file_av_scan_baseline,
    results_load,
    rule_pack_load,
    rule_pack_export_default,
    rule_pack_update_rule,
)

profile = profile_show("developer")

summary = file_av_scan_baseline(
    paths=[r"C:\path\to\folder"],
    config=r".\pooleshield_config.json",
    clean_output=True,
    bundle_output=True,
    privacy_bundle=True,
)

results = results_load(
    output_dir=r".\out\file_av_desktop_v5_1",
    decision="ALLOW_LOG",
    limit=25,
)

rules = rule_pack_load(
    rule_pack=r".\examples\rule_packs\file_av_rules.default.json",
    enabled="enabled",
    limit=25,
)

exported = rule_pack_export_default(
    output_path=r".\local_rule_packs\file_av_rules.editable.json",
    force=True,
)

updated = rule_pack_update_rule(
    rule_pack=r".\local_rule_packs\file_av_rules.editable.json",
    output_path=r".\local_rule_packs\file_av_rules.edited.json",
    index=0,
    enabled=False,
    risk_delta=0.10,
)
```

## JSON request/response API

Request shape:

```json
{
  "operation": "rule_pack.load",
  "params": {
    "rule_pack": ".\\examples\\rule_packs\\file_av_rules.default.json",
    "enabled": "enabled",
    "limit": 25
  }
}
```

Response shape:

```json
{
  "ok": true,
  "engine": "PooleShield Engine API",
  "engine_version": "5.2.1",
  "engine_api_version": "1",
  "operation": "rule_pack.load",
  "result": {}
}
```

Errors are structured, not tracebacks:

```json
{
  "ok": false,
  "engine": "PooleShield Engine API",
  "engine_version": "5.2.1",
  "engine_api_version": "1",
  "operation": "unknown.operation",
  "error_type": "unsupported_operation",
  "error": "unsupported operation..."
}
```

## CLI bridge for UI testing

```powershell
@'
{
  "operation": "rule_pack.load",
  "params": {
    "rule_pack": ".\\examples\\rule_packs\\file_av_rules.default.json",
    "enabled": "enabled",
    "limit": 25
  }
}
'@ | Set-Content .\engine_request.json

python .\pooleshield_operator.py engine-dispatch --request .\engine_request.json --output .\engine_response.json
```

You can also use the convenience commands:

```powershell
python .\pooleshield_operator.py rule-pack-load --rule-pack .\examples\rule_packs\file_av_rules.default.json --enabled enabled --limit 25
python .\pooleshield_operator.py rule-pack-export-default --output .\local_rule_packs\file_av_rules.editable.json --force
python .\pooleshield_operator.py rule-pack-update-rule --rule-pack .\local_rule_packs\file_av_rules.editable.json --output .\local_rule_packs\file_av_rules.edited.json --index 0 --disabled --risk-delta 0.10
```

## Supported operations

```text
config.init
config.validate
config.show
profile.list
profile.show
history.init
history.record
history.list
history.show
rule_pack.validate
rule_pack.load
rule_pack.export_default
rule_pack.update_rule
file_av.scan_baseline
results.load
baseline.load
baseline.diff
```

## v5.2.1 Rule Pack Editor operations

`rule_pack.load` reads a local rule pack as metadata-only rows for the Rule Packs tab. `rule_pack.export_default` copies the public default rule pack to a local editable path. `rule_pack.update_rule` writes one selected-rule edit to an output rule-pack JSON copy. None of these operations scan, execute, trust, delete, or quarantine scanned files.


## v5.2.1 Portable build operations

`portable.status` reports build dependency/source status. `portable.plan` returns the PyInstaller command plan. These operations do not build executables or touch scanned files. The CLI command `portable-build --run-pyinstaller` is the explicit local build action.

## v5.2.1 Installer build operations

`installer.status` reports local installer readiness for an already-built portable folder. `installer.plan` returns the Inno Setup script/compile plan. These operations do not compile an installer or touch scanned files. The CLI command `installer-build --run-iscc` is the explicit local compile action and requires Inno Setup on Windows.

## v5.2 Release packaging operations

`release.status` checks whether local release artifacts are safe and ready for metadata-only manifest generation.

`release.manifest` creates a JSON-safe release manifest containing file names, sizes, SHA256 hashes, and safety metadata. It does not copy artifact contents, execute installers, install software, delete files, quarantine files, or upload data.
