#!/usr/bin/env python3
"""
PooleShield Cycle 4 one-command runner.

Scans a file or folder of real/exported text-like inputs without executing them,
normalizes events, runs PooleShield, and writes a quarantine manifest.
"""
from __future__ import annotations

import argparse
from typing import Optional, Sequence

from corpus_scanner import scan_and_report


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="PooleShield v1.8 Cycle 4 safe corpus scan runner")
    parser.add_argument("--path", "-p", nargs="+", default=["examples/corpus_scan_fixture"], help="File/folder path(s) to scan")
    parser.add_argument("--normalized", default="cycle4_normalized_events.jsonl", help="Normalized event output")
    parser.add_argument("--output", "-o", default="cycle4_scan_report.json", help="JSON scan report")
    parser.add_argument("--csv", default="cycle4_scan_report.csv", help="CSV scan report")
    parser.add_argument("--manifest", default="cycle4_quarantine_manifest.json", help="JSON quarantine manifest")
    parser.add_argument("--manifest-md", default="cycle4_quarantine_manifest.md", help="Markdown quarantine manifest")
    parser.add_argument("--threshold", type=float, default=0.25, help="Manifest/alert threshold")
    parser.add_argument("--trust", default="untrusted", choices=["trusted", "untrusted", "unknown"], help="Default trust for scanned text")
    parser.add_argument("--no-recursive", action="store_true", help="Only scan top-level files")
    args = parser.parse_args(argv)

    summary = scan_and_report(
        paths=args.path,
        normalized_path=args.normalized,
        output_path=args.output,
        csv_path=args.csv,
        manifest_path=args.manifest,
        manifest_md_path=args.manifest_md,
        threshold=args.threshold,
        default_trust=args.trust,
        recursive=not args.no_recursive,
    )
    import json
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"\nWrote: {args.normalized}")
    print(f"Wrote: {args.output}")
    print(f"Wrote: {args.csv}")
    print(f"Wrote: {args.manifest}")
    print(f"Wrote: {args.manifest_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
