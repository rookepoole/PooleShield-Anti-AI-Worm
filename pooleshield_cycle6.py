#!/usr/bin/env python3
"""
PooleShield Cycle 7 one-command runner.

Runs a safe corpus scan, applies a policy profile, then builds an approval queue
for human review. Default profile is balanced to reduce noise from benign
security-maintenance notes while still requiring approval for WATCH+ events.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Optional, Sequence

from approval_queue import build_queue
from corpus_scanner import scan_and_report
from policy_gate import build_policy_report


def policy_path_for(profile: str) -> str:
    if profile == "balanced":
        return "policy_config.balanced.json"
    if profile == "strict":
        return "policy_config.strict.json"
    raise ValueError(f"Unknown profile: {profile}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="PooleShield v1.8 Cycle 7 approval-queue runner")
    parser.add_argument("--path", "-p", nargs="+", default=["examples/corpus_scan_fixture"], help="File/folder path(s) to scan")
    parser.add_argument("--normalized", default="cycle7_normalized_events.jsonl", help="Normalized event output")
    parser.add_argument("--scan-output", default="cycle7_scan_report.json", help="JSON scan report")
    parser.add_argument("--scan-csv", default="cycle7_scan_report.csv", help="CSV scan report")
    parser.add_argument("--manifest", default="cycle7_quarantine_manifest.json", help="JSON quarantine manifest")
    parser.add_argument("--manifest-md", default="cycle7_quarantine_manifest.md", help="Markdown quarantine manifest")
    parser.add_argument("--policy-profile", choices=["balanced", "strict"], default="balanced", help="Built-in policy profile")
    parser.add_argument("--policy", default=None, help="Optional custom policy_config.json override")
    parser.add_argument("--policy-output", default="cycle7_policy_decisions.json", help="JSON policy-decision report")
    parser.add_argument("--policy-csv", default="cycle7_policy_decisions.csv", help="CSV policy-decision report")
    parser.add_argument("--policy-md", default="cycle7_policy_decisions.md", help="Markdown policy-decision report")
    parser.add_argument("--queue-output", default="cycle7_approval_queue.json", help="JSON approval queue")
    parser.add_argument("--queue-csv", default="cycle7_approval_queue.csv", help="CSV approval queue")
    parser.add_argument("--queue-md", default="cycle7_approval_queue.md", help="Markdown approval queue")
    parser.add_argument("--threshold", type=float, default=0.25, help="Scanner alert threshold")
    parser.add_argument("--trust", default="untrusted", choices=["trusted", "untrusted", "unknown"], help="Default trust for scanned text")
    parser.add_argument("--no-recursive", action="store_true", help="Only scan top-level files")
    parser.add_argument("--include-allowed", action="store_true", help="Include ALLOW decisions in the approval queue")
    parser.add_argument("--include-redacted-preview", action="store_true", help="Include short redacted content previews in queue output")
    args = parser.parse_args(argv)

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

    chosen_policy = args.policy or policy_path_for(args.policy_profile)
    policy_report = build_policy_report(
        report_path=args.scan_output,
        output_path=args.policy_output,
        csv_path=args.policy_csv,
        md_path=args.policy_md,
        policy_path=chosen_policy,
    )

    queue_report = build_queue(
        policy_report_path=args.policy_output,
        output_path=args.queue_output,
        csv_path=args.queue_csv,
        md_path=args.queue_md,
        normalized_path=args.normalized,
        manifest_path=args.manifest,
        include_allowed=args.include_allowed,
        include_redacted_preview=args.include_redacted_preview,
    )

    summary = {
        "scan": scan_summary,
        "policy_profile": args.policy_profile if not args.policy else "custom",
        "policy_path": chosen_policy,
        "policy_summary": policy_report["summary"],
        "approval_queue_summary": queue_report["summary"],
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    for p in [
        args.normalized, args.scan_output, args.scan_csv, args.manifest, args.manifest_md,
        args.policy_output, args.policy_csv, args.policy_md,
        args.queue_output, args.queue_csv, args.queue_md,
    ]:
        print(f"Wrote: {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
