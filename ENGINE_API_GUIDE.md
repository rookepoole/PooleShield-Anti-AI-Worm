# PooleShield Engine API Guide

Version: 4.1.0

PooleShield v4.0 introduces a small Python engine layer so the CLI, future desktop UI, and local process bridge can call the same backend functions.

## Safety boundary

The Engine API is still defensive and read-only by default. It does not execute scanned files, delete files, quarantine files, kill processes, install hooks/drivers, send network requests, or upload raw scanned contents.

## Python API

```python
from pooleshield_engine import profile_show, file_av_scan_baseline

profile = profile_show("developer")

summary = file_av_scan_baseline(
    paths=[r"C:\path\to\folder"],
    config=r".\pooleshield_config.json",
    clean_output=True,
    bundle_output=True,
    privacy_bundle=True,
)
```

## JSON request/response API

Request shape:

```json
{
  "operation": "profile.show",
  "params": {
    "name": "developer"
  }
}
```

Response shape:

```json
{
  "ok": true,
  "engine": "PooleShield Engine API",
  "engine_version": "4.1.0",
  "engine_api_version": "1",
  "operation": "profile.show",
  "result": {}
}
```

Errors are structured, not tracebacks:

```json
{
  "ok": false,
  "engine": "PooleShield Engine API",
  "engine_version": "4.1.0",
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
  "operation": "profile.show",
  "params": {
    "name": "developer"
  }
}
'@ | Set-Content .\engine_request.json

python .\pooleshield_operator.py engine-dispatch --request .\engine_request.json --output .\engine_response.json
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
file_av.scan_baseline
```

## UI-ready direction

The CLI remains available, but v4.0 moves the newest config/profile/history/baseline-scan orchestration behind `pooleshield_engine.py`. A desktop app can now call engine functions directly or send JSON requests to the `engine-dispatch` bridge.
