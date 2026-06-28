#!/usr/bin/env python3
"""
PooleShield Cycle 3 one-command runner.

Runs the labeled calibration harness against a labeled fixture or labeled raw trace.
Use this before testing on real logs so thresholds can be audited for false positives
and false negatives.
"""
from __future__ import annotations

import argparse
from typing import Optional, Sequence

from benchmark_calibration import run_calibration, write_report_json, write_report_csv, print_summary


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="PooleShield v0.4 Cycle 3 calibration runner")
    parser.add_argument("--input", "-i", default="examples/labeled_calibration_trace.jsonl", help="Labeled JSONL/JSON/CSV fixture")
    parser.add_argument("--normalized", default="cycle3_normalized_labeled_events.jsonl", help="Normalized labeled JSONL output")
    parser.add_argument("--output", "-o", default="cycle3_calibration_report.json", help="JSON calibration report")
    parser.add_argument("--csv", default="cycle3_calibration_report.csv", help="CSV calibration cases")
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
