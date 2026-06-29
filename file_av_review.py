#!/usr/bin/env python3
"""
PooleShield v3.2 file-AV review ledger.

Defensive purpose:
  Build and apply a human review ledger for PooleShield file/folder AV scan
  results. This allows trusted helper scripts, source packages, and known local
  files to be marked ALLOW_LOG locally without weakening scanner rules.

Safety boundary:
  This module reads PooleShield metadata reports and writes review/effective
  decision reports only. It does not read scanned file contents, execute files,
  delete files, quarantine files, or modify scanned files.
"""
from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from result_bundler import bundle_output_dir

VERSION = "4.2.0"
REVIEW_DECISIONS = {"KEEP_ORIGINAL", "ALLOW", "ALLOW_LOG", "REQUIRE_APPROVAL", "BLOCK", "QUARANTINE"}
DEFAULT_REVIEW_DECISIONS = {"REQUIRE_APPROVAL", "BLOCK", "QUARANTINE"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def norm_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str):
        if ";" in value:
            return [v.strip() for v in value.split(";") if v.strip()]
        return [value] if value else []
    return [str(value)]


def file_review_key(item: Dict[str, Any]) -> str:
    seed = "|".join([
        str(item.get("display_path", "")),
        str(item.get("sha256", "")),
        str(item.get("kind", "")),
        str(item.get("decision", "")),
        ";".join(norm_list(item.get("labels"))),
    ])
    return "FAV-" + hashlib.sha256(seed.encode("utf-8", errors="ignore")).hexdigest()[:12].upper()


def load_file_av_report(output_dir: Path, report_path: Optional[str] = None) -> Dict[str, Any]:
    path = Path(report_path) if report_path else output_dir / "file_av_report.json"
    if not path.exists():
        raise FileNotFoundError(f"file AV report not found: {path}")
    report = load_json(path)
    if not isinstance(report.get("items"), list):
        raise ValueError(f"file AV report has no items list: {path}")
    return report


def flatten_reason(item: Dict[str, Any]) -> str:
    return ";".join(norm_list(item.get("reasons")))


def flatten_labels(item: Dict[str, Any]) -> str:
    return ";".join(norm_list(item.get("labels")))


def write_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(fieldnames), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def read_csv_rows(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return [dict(row) for row in csv.DictReader(f)]


def build_review_rows(report: Dict[str, Any], include_decisions: Optional[Sequence[str]] = None) -> List[Dict[str, Any]]:
    include = set(include_decisions or DEFAULT_REVIEW_DECISIONS)
    rows: List[Dict[str, Any]] = []
    for item in report.get("items", []):
        decision = str(item.get("decision", ""))
        if decision not in include:
            continue
        rows.append({
            "review_key": file_review_key(item),
            "operator_decision": "KEEP_ORIGINAL",
            "operator": "",
            "notes": "",
            "original_decision": decision,
            "risk_score": item.get("risk_score", ""),
            "display_path": item.get("display_path", ""),
            "source_path": item.get("source_path", ""),
            "sha256": item.get("sha256", ""),
            "kind": item.get("kind", ""),
            "labels": flatten_labels(item),
            "reasons": flatten_reason(item),
            "dry_run_recommended_action": "review_before_opening" if decision == "REQUIRE_APPROVAL" else "dry_run_quarantine_recommendation",
        })
    rows.sort(key=lambda r: (str(r.get("original_decision")), -float(r.get("risk_score") or 0), str(r.get("display_path"))))
    return rows


def write_review_template_md(path: Path, rows: List[Dict[str, Any]], summary: Dict[str, Any]) -> None:
    lines = [
        "# PooleShield File AV Review Ledger Template",
        "",
        f"Version: {VERSION}",
        f"Generated: {summary.get('generated_at')}",
        "",
        "## Summary",
        "",
        f"Rows: `{len(rows)}`",
        f"By original decision: `{summary.get('by_original_decision')}`",
        "",
        "## How to use",
        "",
        "Edit `operator_decision` in the CSV. Allowed values:",
        "",
        "```text",
        "KEEP_ORIGINAL",
        "ALLOW",
        "ALLOW_LOG",
        "REQUIRE_APPROVAL",
        "BLOCK",
        "QUARANTINE",
        "```",
        "",
        "Use `ALLOW_LOG` for trusted archived/source/test files that are safe to keep but should remain auditable. Do not use this ledger to weaken detections for unknown files.",
        "",
        "## Review rows",
        "",
    ]
    for row in rows[:200]:
        lines += [
            f"### {row.get('original_decision')} risk={row.get('risk_score')} — `{row.get('display_path')}`",
            "",
            f"Review key: `{row.get('review_key')}`",
            f"Labels: `{row.get('labels')}`",
            f"Reasons: `{row.get('reasons')}`",
            "",
        ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def build_file_av_review_template(
    output_dir: str,
    report_path: Optional[str] = None,
    include_decision: Optional[Sequence[str]] = None,
    bundle_output: bool = False,
    bundle_path: Optional[str] = None,
    privacy_bundle: bool = True,
) -> Dict[str, Any]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    report = load_file_av_report(out, report_path)
    rows = build_review_rows(report, include_decision)
    csv_path = out / "file_av_review_ledger_template.csv"
    json_path = out / "file_av_review_ledger_template.json"
    md_path = out / "file_av_review_ledger_template.md"
    summary_path = out / "RUN_SUMMARY_FILE_AV_REVIEW.json"
    summary_md_path = out / "RUN_SUMMARY_FILE_AV_REVIEW.md"
    fieldnames = [
        "review_key", "operator_decision", "operator", "notes", "original_decision", "risk_score",
        "display_path", "source_path", "sha256", "kind", "labels", "reasons", "dry_run_recommended_action",
    ]
    write_csv(csv_path, rows, fieldnames)
    counts = Counter(str(r.get("original_decision")) for r in rows)
    summary: Dict[str, Any] = {
        "tool": "PooleShield file AV review ledger template",
        "version": VERSION,
        "generated_at": utc_now(),
        "mode": "file-av-review",
        "output_dir": str(out),
        "review_rows": len(rows),
        "by_original_decision": dict(sorted(counts.items())),
        "template_csv": str(csv_path),
        "template_json": str(json_path),
        "template_md": str(md_path),
        "bundle_summary": None,
    }
    write_json(json_path, {"summary": summary, "rows": rows})
    write_json(summary_path, summary)
    write_review_template_md(md_path, rows, summary)
    summary_md_path.write_text(
        "# PooleShield File AV Review Summary\n\n"
        f"Version: {VERSION}\n\n"
        f"Review rows: `{len(rows)}`\n\n"
        f"By original decision: `{summary['by_original_decision']}`\n\n"
        f"Template CSV: `{csv_path}`\n",
        encoding="utf-8",
    )
    if bundle_output:
        bundle_report = bundle_output_dir(str(out), bundle_path or str(out / "pooleshield_results_bundle.zip"), privacy_mode=privacy_bundle)
        summary["bundle_summary"] = bundle_report
        summary["result_bundle"] = bundle_report.get("bundle_path")
        write_json(summary_path, summary)
        bundle_output_dir(str(out), bundle_path or str(out / "pooleshield_results_bundle.zip"), privacy_mode=privacy_bundle)
    return summary


def choose_effective_decision(original: str, operator_decision: str) -> Tuple[str, str]:
    op = (operator_decision or "").strip().upper()
    if not op or op == "KEEP_ORIGINAL":
        return original, "pending" if original in DEFAULT_REVIEW_DECISIONS else "not_in_queue"
    if op not in REVIEW_DECISIONS:
        return original, f"invalid_operator_decision:{op}"
    return op, "applied"


def apply_file_av_review_ledger(
    output_dir: str,
    ledger: str,
    report_path: Optional[str] = None,
    bundle_output: bool = False,
    bundle_path: Optional[str] = None,
    privacy_bundle: bool = True,
) -> Dict[str, Any]:
    out = Path(output_dir)
    report = load_file_av_report(out, report_path)
    ledger_path = Path(ledger)
    rows = read_csv_rows(ledger_path)
    ledger_by_key = {str(r.get("review_key", "")).strip(): r for r in rows if str(r.get("review_key", "")).strip()}
    effective_items: List[Dict[str, Any]] = []
    applied = 0
    invalid = 0
    pending = 0
    for item in report.get("items", []):
        original = str(item.get("decision", ""))
        key = file_review_key(item)
        ledger_row = ledger_by_key.get(key)
        operator_decision = ledger_row.get("operator_decision", "") if ledger_row else ""
        effective, status = choose_effective_decision(original, operator_decision)
        if status == "applied":
            applied += 1
        elif status.startswith("invalid"):
            invalid += 1
        if effective in DEFAULT_REVIEW_DECISIONS:
            pending += 1
        row = dict(item)
        row.update({
            "review_key": key,
            "original_decision": original,
            "operator_decision": (operator_decision or "KEEP_ORIGINAL"),
            "effective_decision": effective,
            "review_status": status,
            "operator": ledger_row.get("operator", "") if ledger_row else "",
            "review_notes": ledger_row.get("notes", "") if ledger_row else "",
        })
        effective_items.append(row)
    by_eff = Counter(str(i.get("effective_decision")) for i in effective_items)
    allowlist = [i for i in effective_items if i.get("review_status") == "applied" and i.get("effective_decision") in {"ALLOW", "ALLOW_LOG"}]
    denylist = [i for i in effective_items if i.get("review_status") == "applied" and i.get("effective_decision") in {"BLOCK", "QUARANTINE"}]
    summary: Dict[str, Any] = {
        "tool": "PooleShield file AV ledger apply",
        "version": VERSION,
        "generated_at": utc_now(),
        "mode": "file-av-apply-ledger",
        "output_dir": str(out),
        "ledger": str(ledger_path),
        "total_items": len(effective_items),
        "ledger_rows": len(rows),
        "applied_ledger_rows": applied,
        "invalid_ledger_rows": invalid,
        "pending_review_rows": pending,
        "by_effective_decision": dict(sorted(by_eff.items())),
        "allowlist_entries": len(allowlist),
        "denylist_entries": len(denylist),
        "result_bundle": str(out / "pooleshield_results_bundle.zip") if bundle_output else "",
        "bundle_summary": None,
    }
    effective_json = out / "effective_file_av_decisions.json"
    effective_csv = out / "effective_file_av_decisions.csv"
    effective_md = out / "effective_file_av_decisions.md"
    allow_json = out / "file_av_allowlist.json"
    deny_json = out / "file_av_denylist.json"
    summary_json = out / "RUN_SUMMARY_FILE_AV_LEDGER.json"
    summary_md = out / "RUN_SUMMARY_FILE_AV_LEDGER.md"
    write_json(effective_json, {"summary": summary, "items": effective_items})
    # CSV rows with semicolon-normalized labels/reasons.
    csv_rows: List[Dict[str, Any]] = []
    for i in effective_items:
        row = dict(i)
        row["labels"] = flatten_labels(i)
        row["reasons"] = flatten_reason(i)
        csv_rows.append(row)
    write_csv(effective_csv, csv_rows, [
        "review_key", "display_path", "source_path", "sha256", "kind", "size_bytes",
        "risk_score", "original_decision", "operator_decision", "effective_decision", "review_status",
        "labels", "reasons", "operator", "review_notes",
    ])
    write_json(allow_json, {"summary": {"entries": len(allowlist)}, "items": allowlist})
    write_json(deny_json, {"summary": {"entries": len(denylist)}, "items": denylist})
    write_json(summary_json, summary)
    write_effective_md(effective_md, effective_items, summary)
    summary_md.write_text(
        "# PooleShield File AV Ledger Apply Summary\n\n"
        f"Version: {VERSION}\n\n"
        f"Total items: `{summary['total_items']}`\n"
        f"Applied ledger rows: `{summary['applied_ledger_rows']}`\n"
        f"Pending review rows: `{summary['pending_review_rows']}`\n"
        f"By effective decision: `{summary['by_effective_decision']}`\n",
        encoding="utf-8",
    )
    if bundle_output:
        bundle_report = bundle_output_dir(str(out), bundle_path or str(out / "pooleshield_results_bundle.zip"), privacy_mode=privacy_bundle)
        summary["bundle_summary"] = bundle_report
        summary["result_bundle"] = bundle_report.get("bundle_path")
        write_json(summary_json, summary)
        # Update effective JSON summary and re-bundle.
        write_json(effective_json, {"summary": summary, "items": effective_items})
        bundle_output_dir(str(out), bundle_path or str(out / "pooleshield_results_bundle.zip"), privacy_mode=privacy_bundle)
    return summary


def write_effective_md(path: Path, items: List[Dict[str, Any]], summary: Dict[str, Any]) -> None:
    top = sorted(items, key=lambda x: float(x.get("risk_score", 0) or 0), reverse=True)[:100]
    lines = [
        "# PooleShield Effective File AV Decisions",
        "",
        f"Version: {VERSION}",
        f"Generated: {summary.get('generated_at')}",
        f"Ledger: `{summary.get('ledger')}`",
        "",
        "## Summary",
        "",
        f"Total items: `{summary.get('total_items')}`",
        f"Applied ledger rows: `{summary.get('applied_ledger_rows')}`",
        f"Pending review rows: `{summary.get('pending_review_rows')}`",
        f"By effective decision: `{summary.get('by_effective_decision')}`",
        "",
        "## Top effective decisions",
        "",
    ]
    for item in top:
        lines += [
            f"### {item.get('effective_decision')} risk={item.get('risk_score')} — `{item.get('display_path')}`",
            "",
            f"Original: `{item.get('original_decision')}`  Operator: `{item.get('operator_decision')}`  Status: `{item.get('review_status')}`",
            f"Review key: `{item.get('review_key')}`",
            f"Labels: `{flatten_labels(item)}`",
            f"Reasons: `{flatten_reason(item)}`",
            "",
        ]
    path.write_text("\n".join(lines), encoding="utf-8")
