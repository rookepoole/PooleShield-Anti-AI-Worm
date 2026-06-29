#!/usr/bin/env python3
"""PooleShield local scan history database.

Defensive purpose:
  Store local, privacy-aware scan metadata in SQLite so future UI/dashboard
  workflows can show previous verdicts without committing result bundles,
  baselines, or raw scanned file contents.

Safety boundary:
  This module writes only local metadata chosen from PooleShield reports. It does
  not read raw scanned file contents, execute files, delete files, quarantine
  files, or upload anything.
"""
from __future__ import annotations

import csv
import json
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

VERSION = "5.1.0"

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    tool_version TEXT,
    mode TEXT,
    verdict TEXT,
    headline TEXT,
    scan_profile TEXT,
    risk_profile TEXT,
    output_dir TEXT,
    source_report TEXT,
    paths_json TEXT,
    rule_pack_json TEXT,
    baseline_matches INTEGER DEFAULT 0,
    items_scanned INTEGER DEFAULT 0,
    files_scanned INTEGER DEFAULT 0,
    archive_entries_scanned INTEGER DEFAULT 0,
    actionable_items INTEGER DEFAULT 0,
    high_severity_items INTEGER DEFAULT 0,
    allow_count INTEGER DEFAULT 0,
    allow_log_count INTEGER DEFAULT 0,
    require_approval_count INTEGER DEFAULT 0,
    block_count INTEGER DEFAULT 0,
    quarantine_count INTEGER DEFAULT 0,
    read_only INTEGER DEFAULT 1,
    dry_run_only INTEGER DEFAULT 1,
    privacy_bundle INTEGER DEFAULT 1,
    bundle_path TEXT,
    config_used INTEGER DEFAULT 0,
    config_path TEXT,
    notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans(verdict);
CREATE INDEX IF NOT EXISTS idx_scans_profile ON scans(scan_profile);
"""

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


def init_history_db(history_db: str) -> Dict[str, Any]:
    db = Path(history_db).expanduser()
    db.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db) as conn:
        conn.executescript(SCHEMA_SQL)
        conn.commit()
    return {
        "tool": "PooleShield scan history",
        "version": VERSION,
        "mode": "history-init",
        "history_db": str(db),
        "created_or_verified": True,
        "read_only_scan_engine": True,
    }


def _first_existing(paths: Sequence[Path]) -> Optional[Path]:
    for p in paths:
        if p.exists():
            return p
    return None


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


def _counter_items(items: Sequence[Dict[str, Any]]) -> Counter:
    return Counter(_decision(item) for item in items)


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except Exception:
        return default


def _load_output_reports(output_dir: str) -> Tuple[Path, Dict[str, Any], Dict[str, Any], Dict[str, Any], List[Dict[str, Any]]]:
    out = Path(output_dir)
    if not out.exists() or not out.is_dir():
        raise FileNotFoundError(f"scan output directory not found: {out}")

    run_path = _first_existing([
        out / "RUN_SUMMARY_FILE_AV_BASELINE_SCAN.json",
        out / "RUN_SUMMARY_FILE_AV.json",
    ])
    final_path = _first_existing([out / "FINAL_SCAN_SUMMARY.json"])
    report_path = _first_existing([
        out / "effective_file_av_baseline_decisions.json",
        out / "effective_file_av_decisions.json",
        out / "file_av_report.json",
    ])

    run_summary = read_json(run_path) if run_path else {}
    final_summary = read_json(final_path) if final_path else {}
    report = read_json(report_path) if report_path else {}
    items = _items_from_report(report)
    if not items and isinstance(final_summary, dict):
        items = _items_from_report(final_summary)
    if report_path is None and not final_summary:
        raise FileNotFoundError(f"no file-AV summary/report found in {out}")
    return out, run_summary, final_summary, report, items


def _history_row_from_output(output_dir: str, notes: str = "") -> Dict[str, Any]:
    out, run_summary, final_summary, report, items = _load_output_reports(output_dir)
    raw_report_summary = report.get("summary", {}) if isinstance(report, dict) else {}
    settings = report.get("settings", {}) if isinstance(report, dict) else {}
    counts = Counter(final_summary.get("by_effective_decision", {}) or {}) if final_summary else _counter_items(items)
    original_counts = Counter(final_summary.get("by_original_decision", {}) or {}) if final_summary else Counter()

    verdict = final_summary.get("verdict") if isinstance(final_summary, dict) else None
    if not verdict:
        if counts.get("BLOCK", 0) or counts.get("QUARANTINE", 0):
            verdict = "ACTION_REQUIRED"
        elif counts.get("REQUIRE_APPROVAL", 0):
            verdict = "REVIEW_REQUIRED"
        else:
            verdict = "CLEAN_AFTER_POLICY"

    action_count = _safe_int(final_summary.get("actionable_items") if isinstance(final_summary, dict) else None)
    if not action_count:
        action_count = sum(counts.get(d, 0) for d in ACTIONABLE)
    high_count = _safe_int(final_summary.get("high_severity_items") if isinstance(final_summary, dict) else None)
    if not high_count:
        high_count = sum(counts.get(d, 0) for d in HIGH_SEVERITY)

    paths = report.get("paths") if isinstance(report, dict) else []
    if not paths and isinstance(run_summary, dict):
        paths = run_summary.get("paths") or []

    rule_pack = {}
    if isinstance(run_summary, dict) and isinstance(run_summary.get("rule_pack"), dict):
        rule_pack = run_summary.get("rule_pack") or {}
    elif isinstance(settings, dict) and isinstance(settings.get("rule_pack"), dict):
        rule_pack = settings.get("rule_pack") or {}

    config_summary = run_summary.get("config_summary", {}) if isinstance(run_summary, dict) else {}
    bundle_summary = run_summary.get("bundle_summary", {}) if isinstance(run_summary, dict) else {}
    safety = final_summary.get("safety_boundary", {}) if isinstance(final_summary, dict) else {}

    return {
        "created_at": run_summary.get("generated_at") or final_summary.get("generated_at") or report.get("generated_at") or utc_now(),
        "recorded_at": utc_now(),
        "tool_version": run_summary.get("version") or final_summary.get("version") or report.get("version") or VERSION,
        "mode": run_summary.get("mode") or final_summary.get("mode") or report.get("mode") or "file-av-scan",
        "verdict": verdict,
        "headline": final_summary.get("headline") or "",
        "scan_profile": run_summary.get("scan_profile") or settings.get("scan_profile") or (config_summary.get("scan_profile") or {}).get("name") or "",
        "risk_profile": run_summary.get("risk_profile") or settings.get("risk_profile") or "",
        "output_dir": str(out),
        "source_report": final_summary.get("source_report") or run_summary.get("effective_report_json") or run_summary.get("report_json") or "",
        "paths_json": json.dumps(paths or [], ensure_ascii=False),
        "rule_pack_json": json.dumps(rule_pack or {}, ensure_ascii=False),
        "baseline_matches": _safe_int(final_summary.get("baseline_matches") if isinstance(final_summary, dict) else run_summary.get("baseline_matches")),
        "items_scanned": _safe_int(final_summary.get("items_scanned") if isinstance(final_summary, dict) else raw_report_summary.get("items_scanned")),
        "files_scanned": _safe_int(run_summary.get("files_scanned") or raw_report_summary.get("files_scanned")),
        "archive_entries_scanned": _safe_int(run_summary.get("archive_entries_scanned") or raw_report_summary.get("archive_entries_scanned")),
        "actionable_items": action_count,
        "high_severity_items": high_count,
        "allow_count": _safe_int(counts.get("ALLOW", 0)),
        "allow_log_count": _safe_int(counts.get("ALLOW_LOG", 0)),
        "require_approval_count": _safe_int(counts.get("REQUIRE_APPROVAL", 0)),
        "block_count": _safe_int(counts.get("BLOCK", 0)),
        "quarantine_count": _safe_int(counts.get("QUARANTINE", 0)),
        "read_only": 1 if safety.get("read_only", True) else 0,
        "dry_run_only": 1 if safety.get("dry_run_only", True) else 0,
        "privacy_bundle": 1,
        "bundle_path": (bundle_summary or {}).get("bundle_path") or run_summary.get("result_bundle") or "",
        "config_used": 1 if (config_summary or {}).get("used_config_file") else 0,
        "config_path": (config_summary or {}).get("config_path") or "",
        "notes": notes,
        "by_original_decision": dict(original_counts),
    }


def _insert_row(history_db: str, row: Dict[str, Any]) -> int:
    init_history_db(history_db)
    db = Path(history_db).expanduser()
    columns = [
        "created_at", "recorded_at", "tool_version", "mode", "verdict", "headline",
        "scan_profile", "risk_profile", "output_dir", "source_report", "paths_json",
        "rule_pack_json", "baseline_matches", "items_scanned", "files_scanned",
        "archive_entries_scanned", "actionable_items", "high_severity_items", "allow_count",
        "allow_log_count", "require_approval_count", "block_count", "quarantine_count",
        "read_only", "dry_run_only", "privacy_bundle", "bundle_path", "config_used",
        "config_path", "notes",
    ]
    placeholders = ", ".join("?" for _ in columns)
    with sqlite3.connect(db) as conn:
        cur = conn.execute(
            f"INSERT INTO scans ({', '.join(columns)}) VALUES ({placeholders})",
            [row.get(c) for c in columns],
        )
        conn.commit()
        return int(cur.lastrowid)


def record_scan_output(output_dir: str, history_db: str, notes: str = "") -> Dict[str, Any]:
    row = _history_row_from_output(output_dir, notes=notes)
    scan_id = _insert_row(history_db, row)
    summary = {
        "tool": "PooleShield scan history",
        "version": VERSION,
        "mode": "history-record",
        "history_db": str(Path(history_db).expanduser()),
        "scan_id": scan_id,
        "recorded_at": row["recorded_at"],
        "output_dir": row["output_dir"],
        "verdict": row["verdict"],
        "scan_profile": row["scan_profile"],
        "risk_profile": row["risk_profile"],
        "items_scanned": row["items_scanned"],
        "baseline_matches": row["baseline_matches"],
        "actionable_items": row["actionable_items"],
        "high_severity_items": row["high_severity_items"],
        "by_effective_decision": {
            "ALLOW": row["allow_count"],
            "ALLOW_LOG": row["allow_log_count"],
            "REQUIRE_APPROVAL": row["require_approval_count"],
            "BLOCK": row["block_count"],
            "QUARANTINE": row["quarantine_count"],
        },
        "safety_boundary": {
            "metadata_only": True,
            "raw_scanned_file_contents_stored": False,
            "baseline_json_stored": False,
            "read_only_scan_engine": True,
            "dry_run_only": True,
        },
    }
    out = Path(output_dir)
    write_json(out / "SCAN_HISTORY_RECORD.json", summary)
    write_history_record_md(out / "SCAN_HISTORY_RECORD.md", summary)
    return summary


def row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    data = dict(row)
    for key in ("paths_json", "rule_pack_json"):
        try:
            data[key.replace("_json", "")] = json.loads(data.get(key) or "[]")
        except Exception:
            data[key.replace("_json", "")] = data.get(key)
    data.pop("paths_json", None)
    data.pop("rule_pack_json", None)
    data["read_only"] = bool(data.get("read_only"))
    data["dry_run_only"] = bool(data.get("dry_run_only"))
    data["privacy_bundle"] = bool(data.get("privacy_bundle"))
    data["config_used"] = bool(data.get("config_used"))
    return data


def list_history(history_db: str, limit: int = 10) -> Dict[str, Any]:
    init_history_db(history_db)
    db = Path(history_db).expanduser()
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY scan_id DESC LIMIT ?",
            (int(limit),),
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) AS n FROM scans").fetchone()["n"]
    scans = [row_to_dict(row) for row in rows]
    return {
        "tool": "PooleShield scan history",
        "version": VERSION,
        "mode": "history-list",
        "history_db": str(db),
        "total_scans": int(total),
        "returned_scans": len(scans),
        "scans": scans,
    }


def show_history_scan(history_db: str, scan_id: int) -> Dict[str, Any]:
    init_history_db(history_db)
    db = Path(history_db).expanduser()
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (int(scan_id),)).fetchone()
    if row is None:
        raise FileNotFoundError(f"scan_id not found in history: {scan_id}")
    return {
        "tool": "PooleShield scan history",
        "version": VERSION,
        "mode": "history-show",
        "history_db": str(db),
        "scan": row_to_dict(row),
    }


def write_history_record_md(path: Path, summary: Dict[str, Any]) -> None:
    counts = summary.get("by_effective_decision", {}) or {}
    lines = [
        "# PooleShield Scan History Record",
        "",
        f"Version: {summary.get('version')}",
        f"Scan ID: `{summary.get('scan_id')}`",
        f"History DB: `{summary.get('history_db')}`",
        f"Recorded: `{summary.get('recorded_at')}`",
        "",
        "## Final verdict",
        "",
        f"Verdict: `{summary.get('verdict')}`",
        f"Scan profile: `{summary.get('scan_profile')}`",
        f"Risk profile: `{summary.get('risk_profile')}`",
        f"Items scanned: `{summary.get('items_scanned')}`",
        f"Baseline matches: `{summary.get('baseline_matches')}`",
        f"Actionable items: `{summary.get('actionable_items')}`",
        f"High-severity items: `{summary.get('high_severity_items')}`",
        "",
        "## Effective decisions",
        "",
        f"ALLOW: `{counts.get('ALLOW', 0)}`",
        f"ALLOW_LOG: `{counts.get('ALLOW_LOG', 0)}`",
        f"REQUIRE_APPROVAL: `{counts.get('REQUIRE_APPROVAL', 0)}`",
        f"BLOCK: `{counts.get('BLOCK', 0)}`",
        f"QUARANTINE: `{counts.get('QUARANTINE', 0)}`",
        "",
        "## Privacy note",
        "",
        "The local history database stores metadata only. It does not store raw scanned file contents, decoded DAT text, baseline JSON, or result bundles.",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def write_history_list_reports(output_dir: str, history: Dict[str, Any]) -> Dict[str, Any]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / "SCAN_HISTORY_LIST.json"
    csv_path = out / "SCAN_HISTORY_LIST.csv"
    md_path = out / "SCAN_HISTORY_LIST.md"
    write_json(json_path, history)
    rows = history.get("scans", []) or []
    fieldnames = [
        "scan_id", "created_at", "verdict", "scan_profile", "risk_profile",
        "items_scanned", "baseline_matches", "actionable_items", "high_severity_items",
        "allow_count", "allow_log_count", "require_approval_count", "block_count", "quarantine_count",
        "output_dir",
    ]
    write_csv(csv_path, rows, fieldnames)
    lines = [
        "# PooleShield Scan History",
        "",
        f"Version: {history.get('version')}",
        f"History DB: `{history.get('history_db')}`",
        f"Total scans: `{history.get('total_scans')}`",
        f"Returned scans: `{history.get('returned_scans')}`",
        "",
        "| Scan ID | Created | Verdict | Profile | Items | Baseline matches | Action items |",
        "|---:|---|---|---|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| `{row.get('scan_id')}` | `{row.get('created_at')}` | `{row.get('verdict')}` | "
            f"`{row.get('scan_profile')}` | `{row.get('items_scanned')}` | "
            f"`{row.get('baseline_matches')}` | `{row.get('actionable_items')}` |"
        )
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return {
        "json": str(json_path),
        "csv": str(csv_path),
        "md": str(md_path),
    }
