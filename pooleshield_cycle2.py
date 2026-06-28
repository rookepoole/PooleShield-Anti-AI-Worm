#!/usr/bin/env python3
"""
PooleShield Cycle 2 one-command runner.

Normalizes a generic AI-agent/tool-call trace, then runs the PooleShield scorer.
This is a defensive-only wrapper around adapter_tool_logs.py and pooleshield.py.
"""
from __future__ import annotations

import argparse
import os
from typing import Optional, Sequence

from adapter_tool_logs import load_records, normalize_record, write_jsonl
from pooleshield import PooleShieldDetector, read_jsonl, write_json_report, write_csv_report, print_console_report


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="PooleShield v0.2 Cycle 2 adapter + scanner")
    parser.add_argument("--input", "-i", required=True, help="Raw AI-agent/tool-call trace: JSONL, JSON, or CSV")
    parser.add_argument("--normalized", default="normalized_agent_events.jsonl", help="Where to write normalized PooleShield JSONL")
    parser.add_argument("--output", "-o", default="cycle2_report.json", help="JSON report path")
    parser.add_argument("--csv", default="cycle2_report.csv", help="CSV report path")
    args = parser.parse_args(argv)

    records = load_records(args.input)
    normalized_events = [normalize_record(r, i) for i, r in enumerate(records)]
    write_jsonl(args.normalized, normalized_events)

    events = read_jsonl(args.normalized)
    detector = PooleShieldDetector()
    results = detector.analyze(events)
    write_json_report(args.output, results)
    write_csv_report(args.csv, results)
    print(f"Normalized {len(normalized_events)} events -> {args.normalized}")
    print_console_report(results)
    print(f"\nWrote: {args.output}")
    print(f"Wrote: {args.csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
