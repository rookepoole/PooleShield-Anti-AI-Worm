# PooleShield v0.4 Calibration Guide

Cycle 3 exists to prevent overclaiming. Before testing against real logs, PooleShield needs labeled fixtures so we can measure false positives, false negatives, and severity accuracy.

## Label fields

Each JSONL/JSON/CSV record may include:

```json
{
  "case_id": "short_case_name",
  "expected_alert": true,
  "expected_min_level": "WATCH"
}
```

Allowed levels:

```text
NORMAL < WATCH < RESTRICT < QUARANTINE < ISOLATE
```

Use `expected_alert: false` and `expected_min_level: NORMAL` for clean benign cases.

Use `expected_alert: true` with the minimum acceptable level for suspicious cases.

## Example command

```powershell
python .\pooleshield_cycle3.py --input .\examples\labeled_calibration_trace.jsonl --normalized .\cycle3_normalized_labeled_events.jsonl --output .\cycle3_calibration_report.json --csv .\cycle3_calibration_report.csv
```

## Output interpretation

- `TP`: suspicious case correctly alerted
- `TN`: benign case correctly stayed normal
- `FP`: benign case alerted
- `FN`: suspicious case stayed normal
- `severity_ok`: predicted level met or exceeded the expected minimum level

The default alert boundary is risk score `0.25`, matching the start of WATCH.

## Poole Math interpretation

The calibration harness is testing whether local-defect geometry behaves correctly:

```text
D(node,t) = local defect density
P(node,t) = neighbor pressure from adjacent nodes
ΔD = rising local defect gradient
worm geometry = replication + fan-out + agency + neighbor pressure
```

A good calibration set should include both:

1. benign high-activity cases, such as trusted weekly digests or internal review workflows
2. suspicious propagation cases, such as untrusted persistence writes, cross-context repetition, and high fan-out after untrusted retrieval

## Important limitation

The included fixture is intentionally small. A perfect score on it only proves the package is wired correctly. The next research step is a larger fixture bank with many benign edge cases.
