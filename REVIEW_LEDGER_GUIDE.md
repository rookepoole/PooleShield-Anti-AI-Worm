# PooleShield Review Ledger Guide

Cycle 7 adds a review ledger so human review decisions can become repeatable
audit knowledge instead of the same item appearing as a brand-new review every
run.

## Safety boundary

The review ledger does **not** enforce anything. It does not quarantine files,
modify permissions, send emails, delete content, execute commands, or change your
system. It only converts policy and approval-queue reports into audit artifacts:

- editable review-ledger template
- optional demo review decisions
- effective policy-decision report
- allowlist JSON
- denylist JSON

## Stable review keys

Cycle 7 approval items include a `review_key`. It is based on stable evidence
such as the node, source, content hash, and label shape rather than a timestamped
event ID. That matters because file-scanner event IDs can change from run to run.

Use `review_key` as the primary field for repeatable review decisions.

## Operator decision values

Edit the `operator_decision` column in `cycle7_review_ledger_template.csv`.

Valid values:

```text
PENDING
APPROVE_ONCE
APPROVE_ALWAYS
ALLOW_LOG
FALSE_POSITIVE
DENY
BLOCK
QUARANTINE
KEEP_ORIGINAL
```

Recommended interpretation:

- `PENDING`: use safe default until a human decides.
- `APPROVE_ONCE`: allow this item once, with audit logging.
- `APPROVE_ALWAYS`: create an allowlist entry for this recurring content hash.
- `ALLOW_LOG`: allow but preserve an audit trail.
- `FALSE_POSITIVE`: treat as allowlisted calibration feedback.
- `DENY` / `BLOCK`: block autonomous action in a future enforcement system.
- `QUARANTINE`: keep the artifact/context out of autonomous workflows until reviewed.
- `KEEP_ORIGINAL`: leave the policy-gate decision unchanged.

## Demo run

```powershell
python .\pooleshield_cycle7.py --path .\examples\corpus_scan_fixture --policy-profile balanced --demo-review-decisions
```

This produces a non-enforcing demo ledger for the bundled fixture.

## Real review flow

Generate a queue and template:

```powershell
python .\pooleshield_cycle7.py --path "C:\path\to\exported\logs" --policy-profile balanced
```

Edit:

```text
cycle7_review_ledger_template.csv
```

Then apply your edited ledger:

```powershell
python .\review_ledger.py apply --policy-report .\cycle7_policy_decisions.json --queue .\cycle7_approval_queue.json --ledger .\cycle7_review_ledger_template.csv
```

Outputs:

```text
cycle7_effective_policy_decisions.json
cycle7_effective_policy_decisions.csv
cycle7_effective_policy_decisions.md
cycle7_allowlist.json
cycle7_denylist.json
```

## Practical meaning

Cycle 7 is the first step toward operational learning:

```text
detection -> policy decision -> review queue -> human decision -> repeatable ledger
```

The next production step would be using the allowlist/denylist in a non-executing
preflight gate before any AI agent performs a dangerous tool call.
