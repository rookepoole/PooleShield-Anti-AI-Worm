# PooleShield Privacy Bundle Guide

PooleShield normal result bundles include `normalized_events.jsonl`, which can contain the normalized text of scanned chats/logs. That is useful for local debugging, but it can expose private chat/export content if uploaded.

Use privacy bundles whenever you want to share results without sharing raw normalized event text:

```powershell
python .\pooleshield_operator.py chat-scan --path "C:\path\to\chat_exports" --output-dir .\out\chat_scan --clean-output --policy-profile balanced --bundle-output --privacy-bundle
```

Privacy mode excludes content-bearing normalized JSONL files such as:

```text
normalized_events.jsonl
```

The bundle still includes:

- run summaries
- scan/policy/queue reports
- risk scores and labels
- source paths
- content hashes
- review ledger templates
- quarantine manifests

So the operator can review the structure of results without uploading full chat text.


## v2.0 privacy fix

Privacy bundles exclude both `review_evidence_local.md` and `review_evidence_report.json`, because both may contain redacted matched-context snippets from local reviewed files.
