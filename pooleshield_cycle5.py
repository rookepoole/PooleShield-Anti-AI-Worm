#!/usr/bin/env python3
"""
PooleShield Cycle 5 one-command runner.

Runs a safe Cycle 4 corpus scan, then converts the resulting risk report into
policy-gate decisions: ALLOW, ALLOW_LOG, REQUIRE_APPROVAL, BLOCK, or QUARANTINE.
"""
from __future__ import annotations

import argparse
import json
from typing import Optional, Sequence

from corpus_scanner import scan_and_report
from policy_gate import build_policy_report, write_default_policy


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="PooleShield v1.8 Cycle 5 policy-gate runner")
    parser.add_argument("--path", "-p", nargs="+", default=["examples/corpus_scan_fixture"], help="File/folder path(s) to scan")
    parser.add_argument("--normalized", default="cycle5_normalized_events.jsonl", help="Normalized event output")
    parser.add_argument("--scan-output", default="cycle5_scan_report.json", help="JSON scan report")
    parser.add_argument("--scan-csv", default="cycle5_scan_report.csv", help="CSV scan report")
    parser.add_argument("--manifest", default="cycle5_quarantine_manifest.json", help="JSON quarantine manifest")
    parser.add_argument("--manifest-md", default="cycle5_quarantine_manifest.md", help="Markdown quarantine manifest")
    parser.add_argument("--policy-output", default="cycle5_policy_decisions.json", help="JSON policy-decision report")
    parser.add_argument("--policy-csv", default="cycle5_policy_decisions.csv", help="CSV policy-decision report")
    parser.add_argument("--policy-md", default="cycle5_policy_decisions.md", help="Markdown policy-decision report")
    parser.add_argument("--policy", default=None, help="Optional policy_config.json override")
    parser.add_argument("--threshold", type=float, default=0.25, help="Scanner alert threshold")
    parser.add_argument("--trust", default="untrusted", choices=["trusted", "untrusted", "unknown"], help="Default trust for scanned text")
    parser.add_argument("--no-recursive", action="store_true", help="Only scan top-level files")
    parser.add_argument("--write-default-policy", default=None, help="Write default policy config and exit")
    args = parser.parse_args(argv)

    if args.write_default_policy:
        write_default_policy(args.write_default_policy)
        print(f"Wrote default policy: {args.write_default_policy}")
        return 0

    scan_summary = scan_and_report(
        paths=args.path,
        normalized_path=args.normalized,
        output_path=args.scan_output,
        csv_path=args.scan_csv,
        manifest_path=args.manifest,
        manifest_md_path=args.manifest_md,
        threshold=args.threshold,
        default_trust=args.trust,
        recursive=not args.no_recursive,
    )
    policy_report = build_policy_report(
        report_path=args.scan_output,
        output_path=args.policy_output,
        csv_path=args.policy_csv,
        md_path=args.policy_md,
        policy_path=args.policy,
    )

    summary = {
        "scan": scan_summary,
        "policy_summary": policy_report["summary"],
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    for p in [
        args.normalized, args.scan_output, args.scan_csv, args.manifest, args.manifest_md,
        args.policy_output, args.policy_csv, args.policy_md,
    ]:
        print(f"Wrote: {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
