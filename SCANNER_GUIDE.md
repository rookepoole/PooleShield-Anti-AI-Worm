# Cycle 4 Scanner Guide

Cycle 4 is the first bridge from synthetic fixtures to real defensive inspection.

## Inputs

The scanner accepts files or folders containing text-like material:

- `.txt`, `.md`, `.log`, `.html`, `.eml`
- `.jsonl`, `.json`, `.csv` agent/tool traces
- exported RAG chunks or knowledge-base documents

It skips common binary/build folders and never executes scanned content.

## Outputs

- `cycle4_normalized_events.jsonl`: standardized PooleShield events
- `cycle4_scan_report.json`: full risk report
- `cycle4_scan_report.csv`: spreadsheet-friendly event report
- `cycle4_quarantine_manifest.json`: only entries at or above alert threshold
- `cycle4_quarantine_manifest.md`: human-readable manifest

## How to interpret results

`NORMAL` means log-only.  
`WATCH` means review and increase logging.  
`RESTRICT` means block dangerous autonomous tool calls until review.  
`QUARANTINE` means isolate the RAG/memory/tool path from the agent mesh.  
`ISOLATE` means disable the agent or node until review.

The scanner is not claiming malware certainty. It flags local-defect geometry: prompt contamination, dangerous agency, persistence/re-entry, fan-out, cross-context replication, and neighbor pressure.
