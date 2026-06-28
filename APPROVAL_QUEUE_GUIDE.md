# PooleShield v1.8 Approval Queue Guide

Cycle 7 adds the human-review layer.

The goal is not to let PooleShield automatically enforce anything on your machine. The goal is to turn detector/policy output into a clean queue that a person can review before an AI agent writes to memory/RAG, sends messages, uses dangerous tools, or fans out across accounts/nodes.

## What Cycle 7 does

1. Scans a folder/log corpus safely.
2. Scores each event with the PooleShield local-defect detector.
3. Applies a policy profile.
4. Builds an approval queue with stable review keys.
5. Builds an editable review-ledger template.
6. Emits JSON, CSV, and Markdown review packets.

## Policy profiles

### Balanced profile

Default in `pooleshield_cycle7.py`.

Balanced keeps WATCH+ items in the approval queue, but downgrades normal expected security-maintenance notes from `REQUIRE_APPROVAL` to `ALLOW_LOG` when the only concern is a sensitive/security label.

Use when you are tuning false positives.

```powershell
python .\pooleshield_cycle7.py --path .\examples\corpus_scan_fixture --policy-profile balanced
```

### Strict profile

Strict preserves Cycle 5 behavior: any secret/token/security-sensitive label requires approval.

Use when scanning unknown or hostile corpora.

```powershell
python .\pooleshield_cycle7.py --path .\examples\corpus_scan_fixture --policy-profile strict
```

## Outputs

```text
cycle7_scan_report.json
cycle7_quarantine_manifest.json
cycle7_policy_decisions.json
cycle7_approval_queue.json
cycle7_approval_queue.md
cycle7_approval_queue.csv
cycle7_review_ledger_template.csv
cycle7_review_ledger_template.json
cycle7_review_ledger_template.md
```

## Review priorities

- `P1`: block/quarantine/restrict-level event.
- `P2`: propagation/persistence/tool-use risk, usually deny or quarantine until reviewed.
- `P3`: sensitive/security maintenance item, usually verify then allow/log.
- `P4`: low-level audit item.

## Safe defaults

Cycle 7 assigns a safe default to each queue item, such as:

- `DENY_UNTIL_REVIEW`
- `DENY_OR_QUARANTINE_UNTIL_REVIEW`
- `VERIFY_EXPECTED_SECRET_ROTATION_THEN_ALLOW_LOG`
- `ALLOW_WITH_AUDIT_LOG`

These are recommendations only. No action is enforced by this prototype.

## Safety boundary

The approval queue does not execute file content, follow links, approve tool calls, mutate data, or quarantine files. It only writes review artifacts.


## Stable review keys

Cycle 7 adds `review_key` to each queue item. Use it for durable review decisions because event IDs can change when text files are scanned at different times.
