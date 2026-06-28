#!/usr/bin/env python3
"""
PooleShield Cycle 8 one-command runner.

Runs the v1.8 defensive workflow with clean output hygiene:
  1) safe corpus scan
  2) balanced/strict policy gate
  3) approval queue with stable review keys
  4) editable review-ledger template
  5) optional demo or supplied review-ledger application

Cycle 8 change:
  All generated reports are written under --output-dir by default, so the
  package root stays clean and older cycle reports are not recreated unless
  you explicitly choose those filenames.

Safety boundary:
  This runner does not enforce, quarantine, delete, execute, send, or modify
  the scanned corpus. It writes reports only.
"""
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Optional, Sequence

from approval_queue import build_queue
from corpus_scanner import scan_and_report
from policy_gate import build_policy_report
from review_ledger import build_review_template, write_demo_decisions_from_queue, apply_review_ledger


def policy_path_for(profile: str) -> str:
    if profile == "balanced":
        return "policy_config.balanced.json"
    if profile == "strict":
        return "policy_config.strict.json"
    raise ValueError(f"Unknown profile: {profile}")


def resolve_output(output_dir: Path, value: str) -> str:
    """Resolve a report path under output_dir unless it is absolute."""
    candidate = Path(value)
    if candidate.is_absolute():
        candidate.parent.mkdir(parents=True, exist_ok=True)
        return str(candidate)
    output_dir.mkdir(parents=True, exist_ok=True)
    resolved = output_dir / candidate
    resolved.parent.mkdir(parents=True, exist_ok=True)
    return str(resolved)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="PooleShield v1.8 Cycle 8 clean-output review-ledger runner")
    parser.add_argument("--path", "-p", nargs="+", default=["examples/corpus_scan_fixture"], help="File/folder path(s) to scan")
    parser.add_argument("--output-dir", default="out/cycle8", help="Folder for generated reports. Defaults to out/cycle8")
    parser.add_argument("--clean-output", action="store_true", help="Delete --output-dir before writing new reports")
    parser.add_argument("--normalized", default="cycle8_normalized_events.jsonl", help="Normalized event output")
    parser.add_argument("--scan-output", default="cycle8_scan_report.json", help="JSON scan report")
    parser.add_argument("--scan-csv", default="cycle8_scan_report.csv", help="CSV scan report")
    parser.add_argument("--manifest", default="cycle8_quarantine_manifest.json", help="JSON quarantine manifest")
    parser.add_argument("--manifest-md", default="cycle8_quarantine_manifest.md", help="Markdown quarantine manifest")
    parser.add_argument("--policy-profile", choices=["balanced", "strict"], default="balanced", help="Built-in policy profile")
    parser.add_argument("--policy", default=None, help="Optional custom policy_config.json override")
    parser.add_argument("--policy-output", default="cycle8_policy_decisions.json", help="JSON policy-decision report")
    parser.add_argument("--policy-csv", default="cycle8_policy_decisions.csv", help="CSV policy-decision report")
    parser.add_argument("--policy-md", default="cycle8_policy_decisions.md", help="Markdown policy-decision report")
    parser.add_argument("--queue-output", default="cycle8_approval_queue.json", help="JSON approval queue")
    parser.add_argument("--queue-csv", default="cycle8_approval_queue.csv", help="CSV approval queue")
    parser.add_argument("--queue-md", default="cycle8_approval_queue.md", help="Markdown approval queue")
    parser.add_argument("--template-csv", default="cycle8_review_ledger_template.csv", help="Editable review-ledger CSV template")
    parser.add_argument("--template-json", default="cycle8_review_ledger_template.json", help="Review-ledger template JSON")
    parser.add_argument("--template-md", default="cycle8_review_ledger_template.md", help="Review-ledger template Markdown")
    parser.add_argument("--review-ledger", default=None, help="Optional operator-edited review ledger CSV to apply")
    parser.add_argument("--demo-review-decisions", action="store_true", help="Create and apply demo review decisions for the bundled fixture")
    parser.add_argument("--demo-ledger-csv", default="cycle8_review_decisions_demo.csv", help="Demo review decisions CSV")
    parser.add_argument("--effective-output", default="cycle8_effective_policy_decisions.json", help="Effective decisions JSON after ledger application")
    parser.add_argument("--effective-csv", default="cycle8_effective_policy_decisions.csv", help="Effective decisions CSV")
    parser.add_argument("--effective-md", default="cycle8_effective_policy_decisions.md", help="Effective decisions Markdown")
    parser.add_argument("--allowlist", default="cycle8_allowlist.json", help="Review-generated allowlist JSON")
    parser.add_argument("--denylist", default="cycle8_denylist.json", help="Review-generated denylist JSON")
    parser.add_argument("--threshold", type=float, default=0.25, help="Scanner alert threshold")
    parser.add_argument("--trust", default="untrusted", choices=["trusted", "untrusted", "unknown"], help="Default trust for scanned text")
    parser.add_argument("--no-recursive", action="store_true", help="Only scan top-level files")
    parser.add_argument("--include-allowed", action="store_true", help="Include ALLOW decisions in the approval queue")
    parser.add_argument("--include-redacted-preview", action="store_true", help="Include short redacted content previews in queue output")
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir)
    if args.clean_output and output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Resolve every generated artifact into output_dir unless the user supplied an absolute path.
    args.normalized = resolve_output(output_dir, args.normalized)
    args.scan_output = resolve_output(output_dir, args.scan_output)
    args.scan_csv = resolve_output(output_dir, args.scan_csv)
    args.manifest = resolve_output(output_dir, args.manifest)
    args.manifest_md = resolve_output(output_dir, args.manifest_md)
    args.policy_output = resolve_output(output_dir, args.policy_output)
    args.policy_csv = resolve_output(output_dir, args.policy_csv)
    args.policy_md = resolve_output(output_dir, args.policy_md)
    args.queue_output = resolve_output(output_dir, args.queue_output)
    args.queue_csv = resolve_output(output_dir, args.queue_csv)
    args.queue_md = resolve_output(output_dir, args.queue_md)
    args.template_csv = resolve_output(output_dir, args.template_csv)
    args.template_json = resolve_output(output_dir, args.template_json)
    args.template_md = resolve_output(output_dir, args.template_md)
    args.demo_ledger_csv = resolve_output(output_dir, args.demo_ledger_csv)
    args.effective_output = resolve_output(output_dir, args.effective_output)
    args.effective_csv = resolve_output(output_dir, args.effective_csv)
    args.effective_md = resolve_output(output_dir, args.effective_md)
    args.allowlist = resolve_output(output_dir, args.allowlist)
    args.denylist = resolve_output(output_dir, args.denylist)

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

    template_report = build_review_template(
        queue_path=args.queue_output,
        output_csv=args.template_csv,
        output_json=args.template_json,
        md_path=args.template_md,
    )

    ledger_to_apply = args.review_ledger
    if args.demo_review_decisions:
        write_demo_decisions_from_queue(args.queue_output, args.demo_ledger_csv)
        ledger_to_apply = args.demo_ledger_csv

    effective_summary = None
    if ledger_to_apply:
        effective_report = apply_review_ledger(
            policy_report_path=args.policy_output,
            queue_path=args.queue_output,
            ledger_csv=ledger_to_apply,
            output_path=args.effective_output,
            csv_path=args.effective_csv,
            md_path=args.effective_md,
            allowlist_path=args.allowlist,
            denylist_path=args.denylist,
        )
        effective_summary = effective_report["summary"]

    summary = {
        "output_dir": str(output_dir),
        "scan": scan_summary,
        "policy_profile": args.policy_profile if not args.policy else "custom",
        "policy_path": chosen_policy,
        "policy_summary": policy_report["summary"],
        "approval_queue_summary": queue_report["summary"],
        "review_template_summary": template_report["summary"],
        "applied_review_ledger": ledger_to_apply or "",
        "effective_summary": effective_summary,
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    outputs = [
        args.normalized, args.scan_output, args.scan_csv, args.manifest, args.manifest_md,
        args.policy_output, args.policy_csv, args.policy_md,
        args.queue_output, args.queue_csv, args.queue_md,
        args.template_csv, args.template_json, args.template_md,
    ]
    if args.demo_review_decisions:
        outputs.append(args.demo_ledger_csv)
    if ledger_to_apply:
        outputs.extend([args.effective_output, args.effective_csv, args.effective_md, args.allowlist, args.denylist])
    for path in outputs:
        print(f"Wrote: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
