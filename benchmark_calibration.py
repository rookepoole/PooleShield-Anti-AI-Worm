#!/usr/bin/env python3
"""
PooleShield v1.8 calibration harness.

Defensive purpose:
  Score labeled AI-agent/RAG/tool events and measure detection quality.
  This harness does not execute tools, call networks, exploit systems, or generate payloads.

Supported input:
  JSONL, JSON, or CSV records. Records may be either native PooleShield events or
  messy raw agent/tool records that the adapter can normalize.

Optional label fields:
  expected_alert: true/false
  expected_min_level: NORMAL|WATCH|RESTRICT|QUARANTINE|ISOLATE
  case_id: stable human-readable case name
  expected_tags: list/string of analyst tags

Example:
  python benchmark_calibration.py --input examples/labeled_calibration_trace.jsonl --output cycle3_calibration_report.json --csv cycle3_calibration_report.csv
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
from dataclasses import asdict
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from adapter_tool_logs import load_records, normalize_record, write_jsonl
from pooleshield import Event, PooleShieldDetector, ScoreBreakdown

VERSION = "1.8.0"
LEVEL_ORDER = {"NORMAL": 0, "WATCH": 1, "RESTRICT": 2, "QUARANTINE": 3, "ISOLATE": 4}
ORDER_LEVEL = {v: k for k, v in LEVEL_ORDER.items()}


def parse_bool(value: Any, default: Optional[bool] = None) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if value is None or value == "":
        return default
    s = str(value).strip().lower()
    if s in {"true", "1", "yes", "y", "alert", "malicious", "suspicious", "positive"}:
        return True
    if s in {"false", "0", "no", "n", "normal", "benign", "negative"}:
        return False
    return default


def normalize_level(value: Any, default: str = "NORMAL") -> str:
    if value is None or value == "":
        return default
    s = str(value).strip().upper()
    aliases = {
        "BENIGN": "NORMAL",
        "CLEAN": "NORMAL",
        "LOW": "WATCH",
        "MEDIUM": "RESTRICT",
        "HIGH": "QUARANTINE",
        "CRITICAL": "ISOLATE",
    }
    s = aliases.get(s, s)
    return s if s in LEVEL_ORDER else default


def expected_from_record(raw: Dict[str, Any]) -> Tuple[bool, str, str, Any]:
    """Return expected_alert, expected_min_level, case_id, expected_tags."""
    case_id = str(raw.get("case_id") or raw.get("id") or raw.get("name") or "")
    expected_min = normalize_level(raw.get("expected_min_level") or raw.get("expected_level"), "")
    expected_alert = parse_bool(raw.get("expected_alert"), None)

    # Fallback from generic labels/ground truth fields.
    if expected_alert is None:
        for key in ["ground_truth", "label", "class", "expected"]:
            if key in raw:
                expected_alert = parse_bool(raw.get(key), None)
                if expected_alert is not None:
                    break

    if not expected_min:
        expected_min = "WATCH" if expected_alert else "NORMAL"
    if expected_alert is None:
        expected_alert = LEVEL_ORDER[expected_min] > LEVEL_ORDER["NORMAL"]
    tags = raw.get("expected_tags") or raw.get("tags") or raw.get("expected_family") or []
    return bool(expected_alert), expected_min, case_id, tags


def normalize_records_with_labels(records: Sequence[Dict[str, Any]], normalized_path: Optional[str] = None) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    for i, raw in enumerate(records):
        event = normalize_record(raw, i)
        expected_alert, expected_min, case_id, tags = expected_from_record(raw)
        event["expected_alert"] = expected_alert
        event["expected_min_level"] = expected_min
        if case_id:
            event["case_id"] = case_id
        if tags:
            event["expected_tags"] = tags
        normalized.append(event)
    if normalized_path:
        write_jsonl(normalized_path, normalized)
    return normalized


def classify_detection(score: ScoreBreakdown, expected_alert: bool, expected_min_level: str, alert_threshold: float) -> Tuple[bool, str, bool]:
    predicted_alert = score.risk_score >= alert_threshold
    if predicted_alert and expected_alert:
        outcome = "TP"
    elif predicted_alert and not expected_alert:
        outcome = "FP"
    elif (not predicted_alert) and expected_alert:
        outcome = "FN"
    else:
        outcome = "TN"
    severity_ok = LEVEL_ORDER.get(score.level, 0) >= LEVEL_ORDER.get(expected_min_level, 0)
    if not expected_alert:
        # Benign rows are severity-ok only if they remain non-alert.
        severity_ok = not predicted_alert
    return predicted_alert, outcome, severity_ok


def safe_div(num: float, den: float) -> float:
    return 0.0 if den == 0 else num / den


def metrics_from_rows(rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    counts = {k: 0 for k in ["TP", "FP", "TN", "FN"]}
    by_level: Dict[str, int] = {}
    for row in rows:
        counts[row["outcome"]] += 1
        by_level[row["predicted_level"]] = by_level.get(row["predicted_level"], 0) + 1
    tp, fp, tn, fn = counts["TP"], counts["FP"], counts["TN"], counts["FN"]
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    return {
        "total_cases": len(rows),
        "confusion": counts,
        "by_predicted_level": dict(sorted(by_level.items(), key=lambda kv: LEVEL_ORDER.get(kv[0], 99))),
        "accuracy": round(safe_div(tp + tn, len(rows)), 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(safe_div(2 * precision * recall, precision + recall), 4),
        "false_positive_rate": round(safe_div(fp, fp + tn), 4),
        "false_negative_rate": round(safe_div(fn, fn + tp), 4),
        "severity_pass_rate": round(safe_div(sum(1 for r in rows if r["severity_ok"]), len(rows)), 4),
    }


def threshold_sweep(scored_pairs: Sequence[Tuple[ScoreBreakdown, bool]], start: float = 0.05, stop: float = 0.90, step: float = 0.05) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    x = start
    while x <= stop + 1e-9:
        rows: List[Dict[str, Any]] = []
        for score, expected_alert in scored_pairs:
            predicted = score.risk_score >= x
            if predicted and expected_alert:
                outcome = "TP"
            elif predicted and not expected_alert:
                outcome = "FP"
            elif (not predicted) and expected_alert:
                outcome = "FN"
            else:
                outcome = "TN"
            rows.append({"outcome": outcome, "predicted_level": score.level, "severity_ok": True})
        m = metrics_from_rows(rows)
        out.append({"threshold": round(x, 2), **{k: m[k] for k in ["precision", "recall", "f1", "false_positive_rate", "false_negative_rate"]}})
        x += step
    return out


def choose_recommended_threshold(sweep: Sequence[Dict[str, Any]], default_threshold: float = 0.25) -> Dict[str, Any]:
    if not sweep:
        return {"threshold": default_threshold, "reason": "default"}
    # Prefer highest F1 and no false positives/negatives. When several thresholds
    # tie, stay closest to PooleShield's default 0.25 alert boundary instead of
    # overfitting to the lowest possible threshold on a tiny fixture.
    best = sorted(
        sweep,
        key=lambda r: (
            r["f1"],
            -r["false_positive_rate"],
            -r["false_negative_rate"],
            -abs(r["threshold"] - default_threshold),
        ),
        reverse=True,
    )[0]
    return {"threshold": best["threshold"], "reason": "max_f1_with_default_threshold_tiebreak", "metrics": best}


def run_calibration(input_path: str, normalized_path: Optional[str], alert_threshold: float) -> Dict[str, Any]:
    raw_records = load_records(input_path)
    normalized = normalize_records_with_labels(raw_records, normalized_path)
    events = [Event.from_dict(e) for e in normalized]
    detector = PooleShieldDetector()
    scores = detector.analyze(events)

    rows: List[Dict[str, Any]] = []
    scored_pairs: List[Tuple[ScoreBreakdown, bool]] = []
    for idx, (raw, norm, score) in enumerate(zip(raw_records, normalized, scores)):
        expected_alert, expected_min, case_id, tags = expected_from_record(norm)
        predicted_alert, outcome, severity_ok = classify_detection(score, expected_alert, expected_min, alert_threshold)
        scored_pairs.append((score, expected_alert))
        rows.append({
            "case_index": idx,
            "case_id": case_id or norm.get("case_id") or f"case_{idx}",
            "node_id": score.node_id,
            "source": score.source,
            "expected_alert": expected_alert,
            "expected_min_level": expected_min,
            "predicted_alert": predicted_alert,
            "predicted_level": score.level,
            "risk_score": score.risk_score,
            "outcome": outcome,
            "severity_ok": severity_ok,
            "worm_risk": score.worm_risk,
            "poole_defect_density": score.poole_defect_density,
            "defect_gradient": score.defect_gradient,
            "matched_labels": ";".join(score.matched_labels),
            "recommended_actions": ";".join(score.recommended_actions),
            "expected_tags": tags,
        })

    sweep = threshold_sweep(scored_pairs)
    return {
        "tool": "PooleShield calibration",
        "version": VERSION,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "input_path": input_path,
        "normalized_path": normalized_path,
        "alert_threshold": alert_threshold,
        "metrics": metrics_from_rows(rows),
        "recommended_threshold": choose_recommended_threshold(sweep),
        "threshold_sweep": sweep,
        "cases": rows,
    }


def write_report_json(path: str, report: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


def write_report_csv(path: str, report: Dict[str, Any]) -> None:
    cases = report.get("cases", [])
    if not cases:
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write("")
        return
    fields = list(cases[0].keys())
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(cases)


def print_summary(report: Dict[str, Any]) -> None:
    print(json.dumps({
        "metrics": report["metrics"],
        "recommended_threshold": report["recommended_threshold"],
    }, indent=2))
    print("\nCases:")
    for row in report["cases"]:
        print(f"- {row['outcome']:2s} level={row['predicted_level']:10s} risk={row['risk_score']:.3f} expected_min={row['expected_min_level']:10s} case={row['case_id']}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="PooleShield v1.8 labeled calibration harness")
    parser.add_argument("--input", "-i", required=True, help="Labeled JSONL/JSON/CSV fixture or labeled raw trace")
    parser.add_argument("--normalized", default="cycle3_normalized_labeled_events.jsonl", help="Write normalized labeled events here")
    parser.add_argument("--output", "-o", default="cycle3_calibration_report.json", help="JSON calibration report path")
    parser.add_argument("--csv", default="cycle3_calibration_report.csv", help="CSV calibration cases path")
    parser.add_argument("--alert-threshold", type=float, default=0.25, help="Risk score threshold for alert/no-alert metrics")
    args = parser.parse_args(argv)

    report = run_calibration(args.input, args.normalized, args.alert_threshold)
    write_report_json(args.output, report)
    write_report_csv(args.csv, report)
    print_summary(report)
    print(f"\nWrote: {args.output}")
    print(f"Wrote: {args.csv}")
    print(f"Wrote: {args.normalized}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
