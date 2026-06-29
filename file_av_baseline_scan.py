#!/usr/bin/env python3
"""
PooleShield v3.4 baseline-aware file AV scan workflow.

Run a read-only file/folder AV scan and apply a local trusted-hash baseline in
one operator command. This removes the manual scan -> apply-baseline -> read
two reports loop while preserving audit visibility.

Safety boundary: no execution, deletion, quarantine, file modification, process
killing, real-time hooks, or drivers.
"""
from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from file_antivirus import run_file_av_scan
from file_av_baseline import apply_file_av_baseline, norm_list
from result_bundler import bundle_output_dir
from file_av_final_summary import build_final_scan_summary

VERSION = "5.2.1"
REVIEW_DECISIONS = {"REQUIRE_APPROVAL", "BLOCK", "QUARANTINE"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def write_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(fieldnames), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def build_effective_plan(items: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    plan: List[Dict[str, Any]] = []
    for item in items:
        eff = str(item.get("effective_decision") or item.get("decision") or "")
        if eff not in REVIEW_DECISIONS:
            continue
        labels = ";".join(norm_list(item.get("labels")))
        reasons = ";".join(norm_list(item.get("reasons")))
        plan.append({
            "display_path": item.get("display_path", ""),
            "source_path": item.get("source_path", ""),
            "sha256": item.get("sha256", ""),
            "risk_score": item.get("risk_score", ""),
            "original_decision": item.get("original_decision", item.get("decision", "")),
            "baseline_status": item.get("baseline_status", ""),
            "effective_decision": eff,
            "dry_run_action": "review_before_opening" if eff == "REQUIRE_APPROVAL" else "dry_run_quarantine_recommendation",
            "labels": labels,
            "reason": reasons,
        })
    return plan


def write_effective_plan_md(path: Path, plan: Sequence[Dict[str, Any]]) -> None:
    lines = [
        "# PooleShield Effective Dry-Run Quarantine Plan",
        "",
        "No files were moved, modified, deleted, executed, or quarantined. This file is advisory only.",
        "This plan is based on effective post-baseline decisions, not the original raw scan decisions.",
        "",
        f"Items: `{len(plan)}`",
        "",
        "| Effective decision | Risk | Dry-run action | Path | Labels |",
        "|---|---:|---|---|---|",
    ]
    for item in plan:
        path_text = str(item.get("display_path", "")).replace("|", "\\|")
        labels = str(item.get("labels", "")).replace("|", "\\|")
        lines.append(
            f"| `{item.get('effective_decision')}` | `{item.get('risk_score')}` | "
            f"`{item.get('dry_run_action')}` | `{path_text}` | `{labels}` |"
        )
    path.write_text("\n".join(lines), encoding="utf-8")


def write_summary_md(path: Path, summary: Dict[str, Any]) -> None:
    lines = [
        "# PooleShield Baseline-Aware File AV Scan Summary",
        "",
        f"Version: {VERSION}",
        f"Generated: {summary.get('generated_at')}",
        "",
        "## Summary",
        "",
        f"Items scanned: `{summary.get('items_scanned')}`",
        f"Files scanned: `{summary.get('files_scanned')}`",
        f"Archive entries scanned: `{summary.get('archive_entries_scanned')}`",
        f"Baseline entries: `{summary.get('baseline_entries')}`",
        f"Baseline matches: `{summary.get('baseline_matches')}`",
        f"Pending effective review rows: `{summary.get('pending_review_rows')}`",
        f"By original decision: `{summary.get('by_original_decision')}`",
        f"By effective decision: `{summary.get('by_effective_decision')}`",
        f"Effective dry-run review/quarantine items: `{summary.get('effective_plan_items')}`",
        "",
        "## Safety boundary",
        "",
        "This workflow is read-only and dry-run only. It did not execute, delete, quarantine, modify, or upload scanned file contents.",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def run_file_av_scan_with_baseline(
    paths: Sequence[str],
    baseline: str,
    output_dir: str = "out/file_av_baseline_scan",
    clean_output: bool = False,
    recursive: bool = True,
    include_hidden: bool = False,
    max_bytes_per_file: int = 5 * 1024 * 1024,
    max_archive_entries: int = 500,
    max_archive_entry_bytes: int = 2 * 1024 * 1024,
    scan_archives: bool = True,
    risk_profile: str = "standard",
    scan_profile: Optional[str] = None,
    rule_pack: Optional[str] = None,
    bundle_output: bool = False,
    bundle_path: Optional[str] = None,
    privacy_bundle: bool = True,
) -> Dict[str, Any]:
    scan_summary = run_file_av_scan(
        paths=paths,
        output_dir=output_dir,
        clean_output=clean_output,
        recursive=recursive,
        include_hidden=include_hidden,
        max_bytes_per_file=max_bytes_per_file,
        max_archive_entries=max_archive_entries,
        max_archive_entry_bytes=max_archive_entry_bytes,
        scan_archives=scan_archives,
        risk_profile=risk_profile,
        scan_profile=scan_profile,
        rule_pack=rule_pack,
        mode="file-av-scan-baseline",
        bundle_output=False,
        privacy_bundle=privacy_bundle,
    )
    out = Path(output_dir)
    baseline_summary = apply_file_av_baseline(
        output_dir=output_dir,
        baseline=baseline,
        report_path=str(out / "file_av_report.json"),
        bundle_output=False,
        privacy_bundle=privacy_bundle,
    )
    effective_path = out / "effective_file_av_baseline_decisions.json"
    effective = read_json(effective_path)
    items = effective.get("items", [])
    by_original = Counter(str(i.get("original_decision") or i.get("decision") or "UNKNOWN") for i in items)
    by_effective = Counter(str(i.get("effective_decision") or "UNKNOWN") for i in items)
    pending = sum(1 for i in items if i.get("effective_decision") in REVIEW_DECISIONS)
    effective_plan = build_effective_plan(items)

    plan_json = out / "effective_dry_run_quarantine_plan.json"
    plan_csv = out / "effective_dry_run_quarantine_plan.csv"
    plan_md = out / "effective_dry_run_quarantine_plan.md"
    summary_json = out / "RUN_SUMMARY_FILE_AV_BASELINE_SCAN.json"
    summary_md = out / "RUN_SUMMARY_FILE_AV_BASELINE_SCAN.md"

    write_json(plan_json, {
        "tool": "PooleShield effective dry-run quarantine plan",
        "version": VERSION,
        "generated_at": utc_now(),
        "mode": "file-av-scan-baseline",
        "items": effective_plan,
    })
    write_csv(plan_csv, effective_plan, [
        "effective_decision", "risk_score", "dry_run_action", "display_path", "source_path",
        "sha256", "original_decision", "baseline_status", "labels", "reason",
    ])
    write_effective_plan_md(plan_md, effective_plan)

    raw_summary = scan_summary.get("summary", {}) if isinstance(scan_summary, dict) else {}
    summary: Dict[str, Any] = {
        "tool": "PooleShield baseline-aware file AV scan",
        "version": VERSION,
        "generated_at": utc_now(),
        "mode": "file-av-scan-baseline",
        "output_dir": str(out),
        "paths": list(paths),
        "baseline": baseline,
        "risk_profile": risk_profile,
        "scan_profile": scan_profile or "manual",
        "rule_pack": scan_summary.get("rule_pack", {}) if isinstance(scan_summary, dict) else {},
        "items_scanned": raw_summary.get("items_scanned", len(items)),
        "files_scanned": raw_summary.get("files_scanned", 0),
        "archive_entries_scanned": raw_summary.get("archive_entries_scanned", 0),
        "baseline_entries": baseline_summary.get("baseline_entries", 0),
        "baseline_matches": baseline_summary.get("baseline_matches", 0),
        "pending_review_rows": pending,
        "effective_plan_items": len(effective_plan),
        "by_original_decision": dict(sorted(by_original.items())),
        "by_effective_decision": dict(sorted(by_effective.items())),
        "read_only": True,
        "dry_run_only": True,
        "report_json": str(out / "file_av_report.json"),
        "effective_report_json": str(effective_path),
        "effective_dry_run_quarantine_plan": str(plan_json),
        "bundle_summary": None,
        "result_bundle": str(out / "pooleshield_results_bundle.zip") if bundle_output else "",
    }
    write_json(summary_json, summary)
    write_summary_md(summary_md, summary)
    final_summary = build_final_scan_summary(output_dir=output_dir, report_path=str(effective_path), mode="file-av-scan-baseline")
    summary["final_verdict"] = final_summary.get("verdict")
    summary["final_headline"] = final_summary.get("headline")
    summary["final_actionable_items"] = final_summary.get("actionable_items")
    summary["final_summary_json"] = str(out / "FINAL_SCAN_SUMMARY.json")
    summary["final_summary_md"] = str(out / "FINAL_SCAN_SUMMARY.md")
    write_json(summary_json, summary)
    write_summary_md(summary_md, summary)

    if bundle_output:
        bundle_report = bundle_output_dir(str(out), bundle_path or str(out / "pooleshield_results_bundle.zip"), privacy_mode=privacy_bundle)
        summary["bundle_summary"] = bundle_report
        summary["result_bundle"] = bundle_report.get("bundle_path")
        write_json(summary_json, summary)
        write_summary_md(summary_md, summary)
        bundle_output_dir(str(out), bundle_path or str(out / "pooleshield_results_bundle.zip"), privacy_mode=privacy_bundle)
    return summary
