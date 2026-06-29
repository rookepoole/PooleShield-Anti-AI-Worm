#!/usr/bin/env python3
"""
PooleShield v3.2 trusted file baseline database.

Defensive purpose:
  Build and apply a local trusted-hash baseline for PooleShield file/folder AV
  scans. This lets an operator remember known-good local helper scripts,
  source/test artifacts, and reviewed files across repeated scans.

Safety boundary:
  This module reads PooleShield metadata reports and writes metadata-only
  baseline/effective decision reports. It does not read scanned file contents,
  execute files, delete files, quarantine files, or modify scanned files.
"""
from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from result_bundler import bundle_output_dir

VERSION = "3.7.0"
REVIEW_DECISIONS = {"REQUIRE_APPROVAL", "BLOCK", "QUARANTINE"}
ALLOW_DECISIONS = {"ALLOW", "ALLOW_LOG"}


class PooleShieldUserError(Exception):
    """User-facing setup/configuration error for CLI commands.

    This is used for correctable operator issues such as a missing trusted
    baseline file. The CLI catches this class and prints a short action-oriented
    message instead of a Python traceback.
    """


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
            clean = dict(row)
            if isinstance(clean.get("labels"), list):
                clean["labels"] = ";".join(str(x) for x in clean.get("labels") or [])
            if isinstance(clean.get("reasons"), list):
                clean["reasons"] = ";".join(str(x) for x in clean.get("reasons") or [])
            writer.writerow(clean)


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


def load_effective_or_report(output_dir: Path, report_path: Optional[str] = None) -> Tuple[str, Dict[str, Any]]:
    if report_path:
        path = Path(report_path)
    else:
        # Prefer the human-reviewed/effective file AV decision report if present.
        path = output_dir / "effective_file_av_decisions.json"
        if not path.exists():
            path = output_dir / "file_av_report.json"
    if not path.exists():
        raise FileNotFoundError(f"file AV report not found: {path}")
    data = read_json(path)
    if not isinstance(data.get("items"), list):
        raise ValueError(f"report has no items list: {path}")
    return str(path), data


def item_effective_decision(item: Dict[str, Any]) -> str:
    return str(item.get("effective_decision") or item.get("decision") or "")


def is_reviewed_allow(item: Dict[str, Any]) -> bool:
    return item_effective_decision(item) in ALLOW_DECISIONS and str(item.get("review_status", "")) == "applied"


def build_baseline_entries(
    items: Sequence[Dict[str, Any]],
    include_decisions: Optional[Sequence[str]] = None,
    include_unreviewed_allowed: bool = False,
) -> List[Dict[str, Any]]:
    include = set(include_decisions or ["ALLOW", "ALLOW_LOG"])
    by_hash: Dict[str, Dict[str, Any]] = {}
    path_hints: Dict[str, List[str]] = defaultdict(list)
    now = utc_now()
    for item in items:
        digest = str(item.get("sha256") or "").strip().lower()
        if not digest or len(digest) < 32:
            continue
        eff = item_effective_decision(item)
        if eff not in include:
            continue
        if not include_unreviewed_allowed and not is_reviewed_allow(item):
            # Baseline should reflect an explicit local trust decision by default.
            continue
        display_path = str(item.get("display_path") or "")
        source_path = str(item.get("source_path") or "")
        if display_path and display_path not in path_hints[digest]:
            path_hints[digest].append(display_path)
        if source_path and source_path not in path_hints[digest]:
            path_hints[digest].append(source_path)
        if digest not in by_hash:
            by_hash[digest] = {
                "sha256": digest,
                "size_bytes": item.get("size_bytes", ""),
                "kind": item.get("kind", ""),
                "trusted_decision": "ALLOW_LOG" if eff == "ALLOW_LOG" else "ALLOW",
                "source_effective_decision": eff,
                "labels": norm_list(item.get("labels")),
                "first_seen": now,
                "last_seen": now,
                "review_key": item.get("review_key", ""),
                "review_notes": item.get("review_notes", ""),
            }
    entries: List[Dict[str, Any]] = []
    for digest, entry in sorted(by_hash.items()):
        e = dict(entry)
        e["path_hints"] = path_hints.get(digest, [])[:20]
        entries.append(e)
    return entries


def write_baseline_md(path: Path, baseline: Dict[str, Any]) -> None:
    summary = baseline.get("summary", {})
    lines = [
        "# PooleShield Trusted File Baseline",
        "",
        f"Version: {baseline.get('version')}",
        f"Generated: {baseline.get('generated_at')}",
        "",
        "## Summary",
        "",
        f"Entries: `{summary.get('entries')}`",
        f"Source report: `{summary.get('source_report')}`",
        "",
        "## Safety boundary",
        "",
        "This is a local metadata-only trusted-hash database. It does not contain scanned file contents and should not be treated as a malware signature database.",
        "",
        "## Entries",
        "",
        "| SHA256 prefix | Decision | Kind | Size | Path hint |",
        "|---|---|---|---:|---|",
    ]
    for entry in baseline.get("entries", [])[:200]:
        hint = (entry.get("path_hints") or [""])[0]
        hint = str(hint).replace("|", "\\|")
        lines.append(f"| `{str(entry.get('sha256',''))[:16]}` | `{entry.get('trusted_decision')}` | `{entry.get('kind')}` | `{entry.get('size_bytes')}` | `{hint}` |")
    path.write_text("\n".join(lines), encoding="utf-8")



def merge_baseline_entry_lists(existing_entries: Sequence[Dict[str, Any]], new_entries: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Merge trusted-baseline entries by SHA, preserving audit-friendly metadata."""
    by_hash: Dict[str, Dict[str, Any]] = {}
    for entry in list(existing_entries or []) + list(new_entries or []):
        digest = str(entry.get("sha256") or "").strip().lower()
        if not digest:
            continue
        clean = dict(entry)
        clean["sha256"] = digest
        clean["labels"] = sorted(set(norm_list(clean.get("labels"))))
        clean["path_hints"] = list(dict.fromkeys(norm_list(clean.get("path_hints"))))[:50]
        if digest not in by_hash:
            by_hash[digest] = clean
            continue
        prev = by_hash[digest]
        # Prefer the more auditable ALLOW_LOG when any source says ALLOW_LOG.
        if clean.get("trusted_decision") == "ALLOW_LOG" or prev.get("trusted_decision") == "ALLOW_LOG":
            prev["trusted_decision"] = "ALLOW_LOG"
        prev["source_effective_decision"] = prev.get("source_effective_decision") or clean.get("source_effective_decision", "")
        prev["kind"] = prev.get("kind") or clean.get("kind", "")
        prev["size_bytes"] = prev.get("size_bytes") or clean.get("size_bytes", "")
        prev["labels"] = sorted(set(norm_list(prev.get("labels")) + norm_list(clean.get("labels"))))
        prev["path_hints"] = list(dict.fromkeys(norm_list(prev.get("path_hints")) + norm_list(clean.get("path_hints"))))[:50]
        prev["review_notes"] = "; ".join([x for x in [prev.get("review_notes", ""), clean.get("review_notes", "")] if x])[:500]
        prev["last_seen"] = clean.get("last_seen") or utc_now()
        if not prev.get("first_seen"):
            prev["first_seen"] = clean.get("first_seen") or utc_now()
    return [by_hash[k] for k in sorted(by_hash)]



def build_file_av_baseline(
    output_dir: str,
    report_path: Optional[str] = None,
    baseline_path: Optional[str] = None,
    include_decision: Optional[Sequence[str]] = None,
    include_unreviewed_allowed: bool = False,
    bundle_output: bool = False,
    bundle_path: Optional[str] = None,
    privacy_bundle: bool = True,
    merge_existing: bool = False,
) -> Dict[str, Any]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    source_report, report = load_effective_or_report(out, report_path)
    entries = build_baseline_entries(report.get("items", []), include_decision, include_unreviewed_allowed)
    baseline_file = Path(baseline_path) if baseline_path else out / "trusted_file_baseline.json"
    if not baseline_file.is_absolute():
        baseline_file = out / baseline_file

    existing_entry_count = 0
    if merge_existing and baseline_file.exists():
        existing = read_json(baseline_file)
        existing_entries = existing.get("entries", []) if isinstance(existing, dict) else []
        existing_entry_count = len(existing_entries)
        entries = merge_baseline_entry_lists(existing_entries, entries)

    baseline_md = baseline_file.with_suffix(".md")
    baseline_csv = baseline_file.with_suffix(".csv")
    summary_json = out / "RUN_SUMMARY_FILE_AV_BASELINE.json"
    summary_md = out / "RUN_SUMMARY_FILE_AV_BASELINE.md"
    baseline = {
        "tool": "PooleShield trusted file baseline",
        "version": VERSION,
        "generated_at": utc_now(),
        "mode": "file-av-build-baseline",
        "summary": {
            "entries": len(entries),
            "source_report": source_report,
            "include_decision": list(include_decision or ["ALLOW", "ALLOW_LOG"]),
            "include_unreviewed_allowed": include_unreviewed_allowed,
            "merge_existing": merge_existing,
            "existing_entry_count": existing_entry_count,
        },
        "entries": entries,
    }
    write_json(baseline_file, baseline)
    write_baseline_md(baseline_md, baseline)
    write_csv(baseline_csv, entries, [
        "sha256", "size_bytes", "kind", "trusted_decision", "source_effective_decision",
        "labels", "first_seen", "last_seen", "review_key", "review_notes", "path_hints",
    ])
    summary: Dict[str, Any] = {
        "tool": "PooleShield trusted file baseline build",
        "version": VERSION,
        "generated_at": utc_now(),
        "mode": "file-av-build-baseline",
        "output_dir": str(out),
        "source_report": source_report,
        "baseline_path": str(baseline_file),
        "baseline_entries": len(entries),
        "include_unreviewed_allowed": include_unreviewed_allowed,
        "merge_existing": merge_existing,
        "existing_entry_count": existing_entry_count,
        "result_bundle": str(out / "pooleshield_results_bundle.zip") if bundle_output else "",
        "bundle_summary": None,
    }
    write_json(summary_json, summary)
    summary_md.write_text(
        "# PooleShield Trusted File Baseline Build Summary\n\n"
        f"Version: {VERSION}\n\n"
        f"Baseline entries: `{len(entries)}`\n"
        f"Merge existing: `{merge_existing}`\n"
        f"Existing entries before merge: `{existing_entry_count}`\n"
        f"Source report: `{source_report}`\n"
        f"Baseline path: `{baseline_file}`\n",
        encoding="utf-8",
    )
    if bundle_output:
        bundle_report = bundle_output_dir(str(out), bundle_path or str(out / "pooleshield_results_bundle.zip"), privacy_mode=privacy_bundle)
        summary["bundle_summary"] = bundle_report
        summary["result_bundle"] = bundle_report.get("bundle_path")
        write_json(summary_json, summary)
        bundle_output_dir(str(out), bundle_path or str(out / "pooleshield_results_bundle.zip"), privacy_mode=privacy_bundle)
    return summary


def load_baseline(path: str) -> Dict[str, Dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        raise PooleShieldUserError(
            "trusted baseline file not found: "
            f"{p}\n"
            "Run file-av-build-baseline first, or pass the absolute path to an existing "
            "trusted_file_baseline.json. Example:\n"
            "  python .\\pooleshield_operator.py file-av-build-baseline "
            "--output-dir <reviewed_file_av_output_dir> "
            "--baseline-path <path_to_trusted_file_baseline.json>\n"
        )
    data = read_json(p)
    entries = data.get("entries") or []
    by_hash: Dict[str, Dict[str, Any]] = {}
    for entry in entries:
        digest = str(entry.get("sha256") or "").strip().lower()
        if digest:
            by_hash[digest] = entry
    return by_hash


def apply_baseline_to_items(items: Sequence[Dict[str, Any]], baseline_by_hash: Dict[str, Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Apply trusted file/archive baseline to file AV items.

    A direct sha256 match trusts that exact item. For archive entries, a trusted
    parent archive hash also allows the entry with audit logging. This lets an
    operator approve a reviewed package archive without weakening default
    archive/script detection for unknown ZIPs.
    """
    effective_items: List[Dict[str, Any]] = []
    matches: List[Dict[str, Any]] = []
    for item in items:
        row = dict(item)
        original = str(item.get("effective_decision") or item.get("decision") or "")
        digest = str(item.get("sha256") or "").strip().lower()
        parent_digest = str(item.get("archive_parent_sha256") or "").strip().lower()
        base = baseline_by_hash.get(digest) if digest else None
        match_type = "direct_hash" if base else ""
        if not base and parent_digest:
            base = baseline_by_hash.get(parent_digest)
            if base:
                match_type = "archive_parent_hash"
        if base:
            row["original_decision"] = original
            row["baseline_status"] = "matched" if match_type == "direct_hash" else "archive_parent_matched"
            row["baseline_match_type"] = match_type
            row["baseline_decision"] = base.get("trusted_decision", "ALLOW_LOG")
            # Keep baseline matches auditable even if the baseline says ALLOW.
            row["effective_decision"] = "ALLOW_LOG"
            labels = norm_list(row.get("labels"))
            label = "baseline_trusted_hash" if match_type == "direct_hash" else "baseline_trusted_archive"
            if label not in labels:
                labels.append(label)
            row["labels"] = labels
            reasons = norm_list(row.get("reasons"))
            if match_type == "direct_hash":
                reasons.append("matched local trusted baseline hash; allow with audit logging")
            else:
                reasons.append("entry belongs to a reviewed trusted archive hash; allow with audit logging")
            row["reasons"] = list(dict.fromkeys(reasons))
            row["review_status"] = "baseline_applied"
            matches.append({
                "display_path": row.get("display_path", ""),
                "sha256": digest,
                "archive_parent_sha256": parent_digest,
                "baseline_match_type": match_type,
                "original_decision": original,
                "effective_decision": row.get("effective_decision"),
                "baseline_decision": base.get("trusted_decision", "ALLOW_LOG"),
            })
        else:
            row["original_decision"] = original
            row["baseline_status"] = "not_matched"
            row["baseline_match_type"] = ""
            row["baseline_decision"] = ""
            row["effective_decision"] = original
            row.setdefault("review_status", "not_in_baseline")
        effective_items.append(row)
    return effective_items, matches


def write_effective_baseline_md(path: Path, items: List[Dict[str, Any]], summary: Dict[str, Any]) -> None:
    top = sorted(items, key=lambda x: float(x.get("risk_score", 0) or 0), reverse=True)[:100]
    lines = [
        "# PooleShield Effective File AV Baseline Decisions",
        "",
        f"Version: {VERSION}",
        f"Generated: {summary.get('generated_at')}",
        f"Baseline: `{summary.get('baseline')}`",
        "",
        "## Summary",
        "",
        f"Total items: `{summary.get('total_items')}`",
        f"Baseline matches: `{summary.get('baseline_matches')}`",
        f"Pending review rows: `{summary.get('pending_review_rows')}`",
        f"By effective decision: `{summary.get('by_effective_decision')}`",
        "",
        "## Top effective decisions",
        "",
    ]
    for item in top:
        labels = ";".join(norm_list(item.get("labels")))
        reasons = ";".join(norm_list(item.get("reasons")))
        lines += [
            f"### {item.get('effective_decision')} risk={item.get('risk_score')} — `{item.get('display_path')}`",
            "",
            f"Original: `{item.get('original_decision')}`  Baseline: `{item.get('baseline_status')}`",
            f"Labels: `{labels}`",
            f"Reasons: `{reasons}`",
            "",
        ]
    path.write_text("\n".join(lines), encoding="utf-8")


def apply_file_av_baseline(
    output_dir: str,
    baseline: str,
    report_path: Optional[str] = None,
    bundle_output: bool = False,
    bundle_path: Optional[str] = None,
    privacy_bundle: bool = True,
) -> Dict[str, Any]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    source_report, report = load_effective_or_report(out, report_path)
    baseline_by_hash = load_baseline(baseline)
    items, matches = apply_baseline_to_items(report.get("items", []), baseline_by_hash)
    by_eff = Counter(str(i.get("effective_decision")) for i in items)
    pending = sum(1 for i in items if i.get("effective_decision") in REVIEW_DECISIONS)
    summary: Dict[str, Any] = {
        "tool": "PooleShield file AV baseline apply",
        "version": VERSION,
        "generated_at": utc_now(),
        "mode": "file-av-apply-baseline",
        "output_dir": str(out),
        "source_report": source_report,
        "baseline": baseline,
        "total_items": len(items),
        "baseline_entries": len(baseline_by_hash),
        "baseline_matches": len(matches),
        "pending_review_rows": pending,
        "by_effective_decision": dict(sorted(by_eff.items())),
        "result_bundle": str(out / "pooleshield_results_bundle.zip") if bundle_output else "",
        "bundle_summary": None,
    }
    effective_json = out / "effective_file_av_baseline_decisions.json"
    effective_csv = out / "effective_file_av_baseline_decisions.csv"
    effective_md = out / "effective_file_av_baseline_decisions.md"
    matches_json = out / "file_av_baseline_matches.json"
    matches_csv = out / "file_av_baseline_matches.csv"
    summary_json = out / "RUN_SUMMARY_FILE_AV_BASELINE_APPLY.json"
    summary_md = out / "RUN_SUMMARY_FILE_AV_BASELINE_APPLY.md"
    write_json(effective_json, {"summary": summary, "items": items})
    csv_rows: List[Dict[str, Any]] = []
    for i in items:
        r = dict(i)
        r["labels"] = ";".join(norm_list(i.get("labels")))
        r["reasons"] = ";".join(norm_list(i.get("reasons")))
        csv_rows.append(r)
    write_csv(effective_csv, csv_rows, [
        "display_path", "source_path", "sha256", "kind", "size_bytes", "risk_score",
        "original_decision", "baseline_status", "baseline_match_type", "baseline_decision", "effective_decision",
        "labels", "reasons", "review_status",
    ])
    write_json(matches_json, {"summary": {"matches": len(matches)}, "items": matches})
    write_csv(matches_csv, matches, ["display_path", "sha256", "archive_parent_sha256", "baseline_match_type", "original_decision", "baseline_decision", "effective_decision"])
    write_json(summary_json, summary)
    write_effective_baseline_md(effective_md, items, summary)
    summary_md.write_text(
        "# PooleShield File AV Baseline Apply Summary\n\n"
        f"Version: {VERSION}\n\n"
        f"Total items: `{summary['total_items']}`\n"
        f"Baseline matches: `{summary['baseline_matches']}`\n"
        f"Pending review rows: `{summary['pending_review_rows']}`\n"
        f"By effective decision: `{summary['by_effective_decision']}`\n",
        encoding="utf-8",
    )
    if bundle_output:
        bundle_report = bundle_output_dir(str(out), bundle_path or str(out / "pooleshield_results_bundle.zip"), privacy_mode=privacy_bundle)
        summary["bundle_summary"] = bundle_report
        summary["result_bundle"] = bundle_report.get("bundle_path")
        write_json(summary_json, summary)
        write_json(effective_json, {"summary": summary, "items": items})
        bundle_output_dir(str(out), bundle_path or str(out / "pooleshield_results_bundle.zip"), privacy_mode=privacy_bundle)
    return summary
