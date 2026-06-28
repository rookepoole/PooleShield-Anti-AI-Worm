# PooleShield Review Triage Guide

PooleShield v1.8 adds `review-triage` for large approval queues.

Use it when a scan creates too many review rows to inspect one by one. The command does **not** read normalized event text or decoded DAT text. It reads `approval_queue.json` metadata only: priorities, labels, risk scores, hashes, source paths, and tool-call metadata.

## Why this exists

DAT/chat archive scans can surface many repeated static phrases such as memory-write wording, tool names, or fan-out language. Those items should still be visible, but operators need grouping and a safer review workflow.

## Command

```powershell
python .\pooleshield_operator.py review-triage --output-dir .\out\dat_chat_scan --preset archived-chat-readonly --bundle-output --privacy-bundle
```

## Outputs

- `review_triage_report.json`
- `review_triage_report.md`
- `review_groups.csv`
- `suggested_review_ledger.csv`
- `RUN_SUMMARY_TRIAGE.json`
- `RUN_SUMMARY_TRIAGE.md`

## Presets

### `archived-chat-readonly`

For static archived ChatGPT/DAT logs that are **not** being fed into live autonomous memory/RAG/tool pipelines.

Rules are conservative:

- high-severity `BLOCK`, `RESTRICT`, or risk >= 0.4 stays `KEEP_ORIGINAL`
- tool/fanout-related items stay `KEEP_ORIGINAL`
- persistent-write-only archived text with no tool-call/fanout signal becomes `ALLOW_LOG`

### `strict`

Everything stays `KEEP_ORIGINAL`.

## Important safety note

Do not blindly apply `suggested_review_ledger.csv`. Review the Markdown report and CSV first. If the extracted DAT text will be used as live RAG/memory context for an agent, use `strict` instead.
