# PooleShield v1.8 Policy Gate Guide

Cycle 5 turns PooleShield from a detector into an auditable defensive policy gate.
It still does **not** execute, exploit, patch, delete, or block anything on its own.
It reads a PooleShield scan report or quarantine manifest and emits decisions that
can be reviewed by a human or wired into a separate production allow/block layer.

## Decision levels

| Decision | Meaning |
|---|---|
| `ALLOW` | No policy trigger. Permit normally. |
| `ALLOW_LOG` | Permit, but keep audit context because minor labels/risk exist. |
| `REQUIRE_APPROVAL` | Do not let an autonomous agent proceed without human approval. |
| `BLOCK` | Block autonomous dangerous actions such as send/forward/delete/execute. |
| `QUARANTINE` | Treat the node/input as a propagation candidate until reviewed. |

## Why this matters

AI-worm defense is not just a scanner problem. The useful security layer is:

1. detect local defect risk,
2. score propagation geometry,
3. convert risk into conservative policy decisions,
4. preserve a reviewable audit trail.

The policy gate focuses on step 3. Cycle 7 adds step 4 through the approval queue.

## One-command Cycle 5 run

```powershell
python .\pooleshield_cycle5.py --path .\examples\corpus_scan_fixture
```

This writes:

```text
cycle5_normalized_events.jsonl
cycle5_scan_report.json
cycle5_scan_report.csv
cycle5_quarantine_manifest.json
cycle5_quarantine_manifest.md
cycle5_policy_decisions.json
cycle5_policy_decisions.csv
cycle5_policy_decisions.md
```

## Apply the policy gate to an existing report

```powershell
python .\policy_gate.py --report .\cycle4_scan_report.json --output .\cycle5_policy_decisions.json --csv .\cycle5_policy_decisions.csv --md .\cycle5_policy_decisions.md
```

You can also pass a quarantine manifest instead of a full scan report:

```powershell
python .\policy_gate.py --report .\cycle4_quarantine_manifest.json --output .\cycle5_policy_decisions.json --csv .\cycle5_policy_decisions.csv --md .\cycle5_policy_decisions.md
```


## Built-in profiles

Cycle 7 includes two JSON policy profiles:

- `policy_config.strict.json`: any secret/token/security-sensitive label requires approval.
- `policy_config.balanced.json`: expected security-sensitive notes become `ALLOW_LOG` unless another risk trigger is present.

Balanced mode is useful for reducing review noise while tuning false positives. Strict mode is better for hostile or unknown corpora.

## Custom policy

Start from the default:

```powershell
python .\policy_gate.py --report .\cycle5_scan_report.json --write-default-policy .\policy_config.json
```

Then run:

```powershell
python .\policy_gate.py --report .\cycle5_scan_report.json --policy .\policy_config.json
```

The default policy is intentionally conservative around:

- untrusted dangerous tool use,
- persistent memory/RAG/config writes,
- fan-out anomalies,
- sensitive-access/secret-interest markers,
- cross-context replication,
- worm-geometry labels.

## Safety boundary

The policy gate is an audit and decision engine. It does not enforce OS/network
controls directly. A real deployment should connect these decisions to a separate
access-control, agent-runtime, or SOC workflow only after review and testing.
