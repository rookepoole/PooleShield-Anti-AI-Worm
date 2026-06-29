# PooleShield v5.3.0 Results UI Guide

Version: 5.3.0

PooleShield v5.3.0 adds a metadata-only Results UI for reviewing scan output without opening scanned files.

## What changed

New Engine API operation:

```text
results.load
```

New operator command:

```powershell
python .\pooleshield_operator.py results-load --output-dir .\out\file_av_desktop_v5_1
```

Desktop UI additions:

- Results tab
- decision filter
- label filter
- text/path/hash search filter
- metadata table
- detail panel
- privacy-bundle path copy button
- automatic results load after a UI-launched scan

## Safety boundary

The Results UI only reads PooleShield output reports such as:

```text
effective_file_av_baseline_decisions.json
effective_file_av_decisions.json
file_av_report.json
FINAL_SCAN_SUMMARY.json
BUNDLE_MANIFEST.json
```

It does not read raw scanned file contents, execute scanned files, delete files, quarantine files, kill processes, or upload anything.

## CLI smoke test

```powershell
python .\pooleshield_operator.py results-load `
  --output-dir .\out\file_av_desktop_v5_1 `
  --decision ALLOW_LOG `
  --label script `
  --limit 25 `
  --output .\results_response.json
```

Expected response shape:

```json
{
  "ok": true,
  "operation": "results.load",
  "result": {
    "mode": "results-load",
    "metadata_only": true,
    "items_returned": 25
  }
}
```

## UI workflow

1. Open the desktop UI.
2. Run a scan from the Scan Folder tab, or enter an existing output folder in the Results tab.
3. Click **Load results**.
4. Filter by decision, label, or search text.
5. Click a row to inspect metadata-only detail.
6. Click **Copy bundle path** to copy the generated `pooleshield_results_bundle.zip` path.

Upload only the privacy bundle when external review is needed.
