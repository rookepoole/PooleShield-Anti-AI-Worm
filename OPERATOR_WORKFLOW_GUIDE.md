# PooleShield v1.8 Operator Workflow

PooleShield v1.8 adds a real operator workflow on top of the cycle demos.
It still does **not** enforce anything on your machine. It reads text-like files,
scores local-defect risk, writes a review queue, and lets a human edit a ledger.

## 1. Run the safe demo

```powershell
python .\pooleshield_operator.py demo --clean-output
```

Outputs go to:

```text
out\demo\
```

## 2. Scan a real folder or exported log set

```powershell
python .\pooleshield_operator.py scan --path "C:\path\to\folder" --output-dir .\out\real_scan --clean-output --policy-profile balanced
```

Important files:

```text
out\real_scan\scan_report.json
out\real_scan\policy_decisions.json
out\real_scan\approval_queue.md
out\real_scan\review_ledger_template.csv
out\real_scan\RUN_SUMMARY.md
```

## 3. Review the ledger

Open:

```text
out\real_scan\review_ledger_template.csv
```

Edit `operator_decision` for rows that need review. Valid values:

```text
PENDING, APPROVE_ONCE, APPROVE_ALWAYS, ALLOW_LOG, FALSE_POSITIVE, DENY, BLOCK, QUARANTINE, KEEP_ORIGINAL
```

Recommended starting decisions:

- `QUARANTINE`: untrusted content tries to write memory/RAG/config or alter future context.
- `DENY` or `BLOCK`: untrusted tool fan-out, sending, deleting, execution, or permission change.
- `ALLOW_LOG`: expected security/admin note mentioning tokens/secrets but not asking for autonomous action.
- `FALSE_POSITIVE`: detector clearly misread harmless content.

## 4. Apply the edited ledger

```powershell
python .\pooleshield_operator.py apply-ledger --output-dir .\out\real_scan --ledger .\out\real_scan\review_ledger_template.csv
```

This writes:

```text
out\real_scan\effective_policy_decisions.json
out\real_scan\effective_policy_decisions.md
out\real_scan\allowlist.json
out\real_scan\denylist.json
```

## Safety boundary

PooleShield v1.8 does not delete, quarantine, block, run, send, or modify anything.
It creates reviewable defensive reports only.


## Upload one ZIP instead of many files

For ChatGPT review or handoff, add `--bundle-output` to the demo, scan, or apply-ledger command.

```powershell
python .\pooleshield_operator.py demo --clean-output --bundle-output
```

Then upload only:

```text
out\demo\pooleshield_results_bundle.zip
```

For a real scan:

```powershell
python .\pooleshield_operator.py scan --path "C:\path\to\folder" --output-dir .\out\real_scan --clean-output --bundle-output
```

Then upload only:

```text
out\real_scan\pooleshield_results_bundle.zip
```


## v1.8 privacy bundle note

For real chat/export scans, prefer `--privacy-bundle` when uploading results for review. It excludes `normalized_events.jsonl`, which may contain raw chat/log text, while preserving hashes, labels, decisions, and summaries.
