# Privacy Model

PooleShield is designed so raw content can remain local.

Privacy bundles exclude:

- `normalized_events.jsonl`
- `extracted_dat_text/`
- `review_evidence_local.md`
- `review_evidence_report.json`

Bundles include metadata needed for review:

- run summaries
- scan counts
- policy decisions
- approval queue summaries
- suggested ledgers
- hash manifests

Never upload private logs or decoded DAT text unless you intentionally want a human to inspect that content.
