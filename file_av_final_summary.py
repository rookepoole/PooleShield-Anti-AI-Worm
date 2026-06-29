#!/usr/bin/env python3
"""
PooleShield v3.5 final file-AV summary layer.

Creates a single operator-facing summary from file AV decisions, preferring
post-baseline effective decisions when available. Metadata-only: no scanned file
contents are copied or embedded.
"""
from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

VERSION = "5.1.0"
ACTIONABLE = {"REQUIRE_APPROVAL", "BLOCK", "QUARANTINE"}
HIGH_SEVERITY = {"BLOCK", "QUARANTINE"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def write_csv(path: Path, rows: Sequence[Dict[str, Any]], fieldnames: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(fieldnames), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value if str(v)]
    if isinstance(value, str):
        if ";" in value:
            return [p.strip() for p in value.split(";") if p.strip()]
        return [value] if value else []
    return [str(value)]


def _items_from_report(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, dict):
        if isinstance(data.get("items"), list):
            return [dict(x) for x in data.get("items", []) if isinstance(x, dict)]
        if isinstance(data.get("results"), list):
            return [dict(x) for x in data.get("results", []) if isinstance(x, dict)]
    if isinstance(data, list):
        return [dict(x) for x in data if isinstance(x, dict)]
    return []


def _decision(item: Dict[str, Any]) -> str:
    return str(item.get("effective_decision") or item.get("decision") or item.get("original_decision") or "UNKNOWN")


def _original_decision(item: Dict[str, Any]) -> str:
    return str(item.get("original_decision") or item.get("decision") or "UNKNOWN")


def _display_path(item: Dict[str, Any]) -> str:
    return str(item.get("display_path") or item.get("path") or item.get("source_path") or "")


def _risk(item: Dict[str, Any]) -> float:
    try:
        return float(item.get("risk_score") or item.get("risk") or 0.0)
    except Exception:
        return 0.0


def _verdict(counts: Counter) -> str:
    if counts.get("BLOCK", 0) or counts.get("QUARANTINE", 0):
        return "ACTION_REQUIRED"
    if counts.get("REQUIRE_APPROVAL", 0):
        return "REVIEW_REQUIRED"
    return "CLEAN_AFTER_POLICY"


def _headline(verdict: str) -> str:
    if verdict == "CLEAN_AFTER_POLICY":
        return "No effective review/block/quarantine items remain."
    if verdict == "REVIEW_REQUIRED":
        return "Human review is required before opening or trusting some items."
    return "High-severity dry-run items remain; do not open or trust them until reviewed."


def build_final_scan_summary(
    output_dir: str,
    report_path: Optional[str] = None,
    mode: str = "file-av-final-summary",
) -> Dict[str, Any]:
    out = Path(output_dir)
    candidates = []
    if report_path:
        candidates.append(Path(report_path))
    candidates.extend([
        out / "effective_file_av_baseline_decisions.json",
        out / "effective_file_av_decisions.json",
        out / "file_av_report.json",
    ])
    report = None
    for path in candidates:
        if path.exists():
            report = path
            break
    if report is None:
        raise FileNotFoundError(
            f"file AV decision report not found in {out}. Expected effective_file_av_baseline_decisions.json, effective_file_av_decisions.json, or file_av_report.json."
        )

    data = read_json(report)
    items = _items_from_report(data)
    effective_counts = Counter(_decision(item) for item in items)
    original_counts = Counter(_original_decision(item) for item in items)
    actionable = [item for item in items if _decision(item) in ACTIONABLE]
    high = [item for item in items if _decision(item) in HIGH_SEVERITY]
    trusted_statuses = {
        "trusted_hash",
        "trusted_archive_parent",
        "trusted",
        "matched",
        "archive_parent_matched",
        "direct_hash_matched",
    }
    baseline_matches = sum(
        1
        for item in items
        if str(item.get("baseline_status") or "") in trusted_statuses
        or item.get("baseline_match") is True
    )

    top_actionable = sorted(actionable, key=_risk, reverse=True)[:25]
    top_rows: List[Dict[str, Any]] = []
    for item in top_actionable:
        labels = ";".join(_as_list(item.get("labels")))
        reasons = ";".join(_as_list(item.get("reasons")))
        top_rows.append({
            "effective_decision": _decision(item),
            "original_decision": _original_decision(item),
            "risk_score": _risk(item),
            "display_path": _display_path(item),
            "sha256": item.get("sha256", ""),
            "baseline_status": item.get("baseline_status", ""),
            "labels": labels,
            "reason": reasons,
        })

    verdict = _verdict(effective_counts)
    summary = {
        "tool": "PooleShield final file AV scan summary",
        "version": VERSION,
        "generated_at": utc_now(),
        "mode": mode,
        "source_report": str(report),
        "items_scanned": len(items),
        "verdict": verdict,
        "headline": _headline(verdict),
        "actionable_items": len(actionable),
        "high_severity_items": len(high),
        "baseline_matches": baseline_matches,
        "by_effective_decision": dict(sorted(effective_counts.items())),
        "by_original_decision": dict(sorted(original_counts.items())),
        "operator_next_step": "No action needed." if verdict == "CLEAN_AFTER_POLICY" else "Review actionable items locally before opening, trusting, extracting, or executing.",
        "safety_boundary": {
            "read_only": True,
            "dry_run_only": True,
            "executed_files": False,
            "modified_files": False,
            "deleted_files": False,
            "quarantined_files": False,
            "killed_processes": False,
            "installed_hooks_or_drivers": False,
        },
        "top_actionable_items": top_rows,
    }

    write_json(out / "FINAL_SCAN_SUMMARY.json", summary)
    write_csv(out / "FINAL_SCAN_SUMMARY_ACTION_ITEMS.csv", top_rows, [
        "effective_decision", "original_decision", "risk_score", "display_path", "sha256", "baseline_status", "labels", "reason"
    ])
    write_final_summary_md(out / "FINAL_SCAN_SUMMARY.md", summary)
    return summary


def write_final_summary_md(path: Path, summary: Dict[str, Any]) -> None:
    counts = summary.get("by_effective_decision", {}) or {}
    original = summary.get("by_original_decision", {}) or {}
    lines = [
        "# PooleShield Final File AV Scan Summary",
        "",
        f"Version: {summary.get('version')}",
        f"Generated: {summary.get('generated_at')}",
        f"Source report: `{summary.get('source_report')}`",
        "",
        "## Final verdict",
        "",
        f"Verdict: `{summary.get('verdict')}`",
        f"Headline: {summary.get('headline')}",
        f"Items scanned: `{summary.get('items_scanned')}`",
        f"Actionable effective items: `{summary.get('actionable_items')}`",
        f"High-severity effective items: `{summary.get('high_severity_items')}`",
        f"Baseline matches: `{summary.get('baseline_matches')}`",
        "",
        "## Effective decisions",
        "",
        f"ALLOW: `{counts.get('ALLOW', 0)}`",
        f"ALLOW_LOG: `{counts.get('ALLOW_LOG', 0)}`",
        f"REQUIRE_APPROVAL: `{counts.get('REQUIRE_APPROVAL', 0)}`",
        f"BLOCK: `{counts.get('BLOCK', 0)}`",
        f"QUARANTINE: `{counts.get('QUARANTINE', 0)}`",
        "",
        "## Original scan decisions",
        "",
        f"Original ALLOW: `{original.get('ALLOW', 0)}`",
        f"Original ALLOW_LOG: `{original.get('ALLOW_LOG', 0)}`",
        f"Original REQUIRE_APPROVAL: `{original.get('REQUIRE_APPROVAL', 0)}`",
        f"Original BLOCK: `{original.get('BLOCK', 0)}`",
        f"Original QUARANTINE: `{original.get('QUARANTINE', 0)}`",
        "",
        "## Operator next step",
        "",
        str(summary.get("operator_next_step", "")),
        "",
        "## Safety boundary",
        "",
        "This is a read-only dry-run scanner. It did not execute, delete, quarantine, modify, or upload scanned file contents.",
    ]
    top = summary.get("top_actionable_items", []) or []
    if top:
        lines.extend([
            "",
            "## Top action items",
            "",
            "| Effective decision | Risk | Path | Labels |",
            "|---|---:|---|---|",
        ])
        for item in top:
            p = str(item.get("display_path", "")).replace("|", "\\|")
            labels = str(item.get("labels", "")).replace("|", "\\|")
            lines.append(f"| `{item.get('effective_decision')}` | `{item.get('risk_score')}` | `{p}` | `{labels}` |")
    path.write_text("\n".join(lines), encoding="utf-8")
