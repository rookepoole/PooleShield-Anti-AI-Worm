#!/usr/bin/env python3
"""
PooleShield v1.8 review ledger.

Defensive purpose:
  Convert human review outcomes into repeatable audit knowledge: pending items,
  one-time approvals, durable allow-log rules, denials, and quarantine decisions.

Safety boundary:
  This module does not approve, block, quarantine, delete, execute, or modify any
  real system. It only reads PooleShield reports and writes audit artifacts that
  a human or a separate production controller may inspect.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from approval_queue import normalize_list

VERSION = "2.0"

VALID_OPERATOR_DECISIONS = {
    "PENDING",
    "APPROVE_ONCE",
    "APPROVE_ALWAYS",
    "ALLOW_LOG",
    "FALSE_POSITIVE",
    "DENY",
    "BLOCK",
    "QUARANTINE",
    "KEEP_ORIGINAL",
}

APPROVE_DECISIONS = {"APPROVE_ONCE", "APPROVE_ALWAYS", "ALLOW_LOG", "FALSE_POSITIVE"}
DENY_DECISIONS = {"DENY", "BLOCK"}
QUARANTINE_DECISIONS = {"QUARANTINE"}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return data


def write_json(path: str, data: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def normalize_operator_decision(value: Any) -> str:
    s = str(value or "PENDING").strip().upper().replace(" ", "_")
    if s in {"APPROVE", "ALLOW", "ACCEPT"}:
        return "APPROVE_ONCE"
    if s in {"ALLOW_ALWAYS", "APPROVE_PERMANENT", "APPROVED_ALWAYS"}:
        return "APPROVE_ALWAYS"
    if s in {"FP", "FALSEPOSITIVE"}:
        return "FALSE_POSITIVE"
    if s in {"REJECT", "DECLINE"}:
        return "DENY"
    if s not in VALID_OPERATOR_DECISIONS:
        return "PENDING"
    return s


def queue_items(queue_path: str) -> List[Dict[str, Any]]:
    data = load_json(queue_path)
    return [x for x in data.get("items", []) or [] if isinstance(x, dict)]


def item_content_hash(item: Dict[str, Any]) -> str:
    evidence = item.get("evidence") or {}
    if isinstance(evidence, dict):
        return str(evidence.get("content_hash") or "")
    return ""


def build_review_template(
    queue_path: str,
    output_csv: str = "cycle7_review_ledger_template.csv",
    output_json: str = "cycle7_review_ledger_template.json",
    md_path: Optional[str] = "cycle7_review_ledger_template.md",
) -> Dict[str, Any]:
    items = queue_items(queue_path)
    rows: List[Dict[str, Any]] = []
    for item in items:
        rows.append({
            "review_key": item.get("review_key", ""),
            "review_id": item.get("review_id", ""),
            "event_id": item.get("event_id", ""),
            "priority": item.get("priority", ""),
            "node_id": item.get("node_id", ""),
            "source": item.get("source", ""),
            "source_path": item.get("source_path", ""),
            "content_hash": item_content_hash(item),
            "risk_score": item.get("risk_score", 0.0),
            "level": item.get("level", ""),
            "original_decision": item.get("decision", ""),
            "safe_default": item.get("safe_default", ""),
            "operator_decision": "PENDING",
            "scope": "CONTENT_HASH",
            "operator": "",
            "reason": "",
            "expires_at": "",
            "notes": "",
        })
    fields = [
        "review_key", "review_id", "event_id", "priority", "node_id", "source",
        "source_path", "content_hash", "risk_score", "level", "original_decision",
        "safe_default", "operator_decision", "scope", "operator", "reason",
        "expires_at", "notes",
    ]
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    report = {
        "tool": "PooleShield review ledger template",
        "version": VERSION,
        "generated_at": utc_now(),
        "queue_path": queue_path,
        "summary": {
            "total_rows": len(rows),
            "by_priority": dict(sorted(Counter(r["priority"] for r in rows).items())),
            "by_original_decision": dict(sorted(Counter(r["original_decision"] for r in rows).items())),
        },
        "rows": rows,
    }
    write_json(output_json, report)
    if md_path:
        write_template_md(md_path, report)
    return report


def write_template_md(path: str, report: Dict[str, Any]) -> None:
    lines = [
        "# PooleShield Review Ledger Template",
        "",
        f"Version: {report.get('version')}",
        f"Generated: {report.get('generated_at')}",
        f"Queue: `{report.get('queue_path')}`",
        "",
        "## Summary",
        "",
        f"Rows: {report['summary']['total_rows']}",
        f"By priority: `{report['summary']['by_priority']}`",
        f"By original decision: `{report['summary']['by_original_decision']}`",
        "",
        "## How to review",
        "",
        "Edit `operator_decision` in the CSV. Valid values: `PENDING`, `APPROVE_ONCE`, `APPROVE_ALWAYS`, `ALLOW_LOG`, `FALSE_POSITIVE`, `DENY`, `BLOCK`, `QUARANTINE`, `KEEP_ORIGINAL`.",
        "",
    ]
    for row in report.get("rows", []):
        lines.append(f"## {row.get('priority')} {row.get('original_decision')} risk={row.get('risk_score')} — {row.get('node_id')}")
        lines.append(f"Review key: `{row.get('review_key')}`")
        lines.append(f"Review ID: `{row.get('review_id')}`")
        lines.append(f"Source path: `{row.get('source_path')}`")
        lines.append(f"Safe default: **{row.get('safe_default')}**")
        lines.append("")
    Path(path).write_text("\n".join(lines), encoding="utf-8")


def write_demo_decisions_from_queue(
    queue_path: str,
    output_csv: str = "cycle7_review_decisions_demo.csv",
) -> List[Dict[str, Any]]:
    """Create a deterministic non-enforcing demo ledger for the bundled fixture."""
    rows: List[Dict[str, Any]] = []
    for item in queue_items(queue_path):
        labels = set(normalize_list(item.get("matched_labels")))
        decision = "PENDING"
        reason = "needs operator review"
        if labels & {"instruction_override", "persistent_write", "tool_use_instruction"}:
            decision = "QUARANTINE"
            reason = "demo: untrusted content attempted persistent/tool-use behavior"
        elif labels & {"fanout_anomaly", "untrusted_to_dangerous_action"}:
            decision = "DENY"
            reason = "demo: untrusted fanout/tool action denied"
        elif labels & {"secret_interest", "sensitive_access"}:
            decision = "APPROVE_ALWAYS"
            reason = "demo: expected security rotation note; allow-log only"
        rows.append({
            "review_key": item.get("review_key", ""),
            "review_id": item.get("review_id", ""),
            "event_id": item.get("event_id", ""),
            "operator_decision": decision,
            "scope": "CONTENT_HASH",
            "operator": "demo_operator",
            "reason": reason,
            "expires_at": "",
            "notes": "generated by --demo-review-decisions; does not enforce anything",
        })
    fields = ["review_key", "review_id", "event_id", "operator_decision", "scope", "operator", "reason", "expires_at", "notes"]
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return rows


def read_ledger_csv(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        rows = []
        for raw in reader:
            row = {str(k or "").strip(): str(v or "").strip() for k, v in raw.items()}
            row["operator_decision"] = normalize_operator_decision(row.get("operator_decision"))
            rows.append(row)
        return rows


def ledger_indexes(rows: Iterable[Dict[str, Any]]) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    by_key: Dict[str, Dict[str, Any]] = {}
    by_review_id: Dict[str, Dict[str, Any]] = {}
    by_event_id: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        if row.get("review_key"):
            by_key[row["review_key"]] = row
        if row.get("review_id"):
            by_review_id[row["review_id"]] = row
        if row.get("event_id"):
            by_event_id[row["event_id"]] = row
    return by_key, by_review_id, by_event_id


def queue_indexes(queue_path: str) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    by_event: Dict[str, Dict[str, Any]] = {}
    by_key: Dict[str, Dict[str, Any]] = {}
    for item in queue_items(queue_path):
        if item.get("event_id"):
            by_event[str(item["event_id"])] = item
        if item.get("review_key"):
            by_key[str(item["review_key"])] = item
    return by_event, by_key


def effective_decision(original: str, operator_decision: str) -> str:
    op = normalize_operator_decision(operator_decision)
    if op in {"PENDING", "KEEP_ORIGINAL"}:
        return original
    if op in APPROVE_DECISIONS:
        return "ALLOW_LOG"
    if op == "DENY":
        return "BLOCK"
    if op == "BLOCK":
        return "BLOCK"
    if op in QUARANTINE_DECISIONS:
        return "QUARANTINE"
    return original


def ledger_containment(operator_decision: str, original_actions: Iterable[str]) -> List[str]:
    op = normalize_operator_decision(operator_decision)
    actions = set(normalize_list(list(original_actions)))
    if op in APPROVE_DECISIONS:
        actions.update({"allow_with_audit_log", "preserve_review_ledger_entry"})
    elif op in DENY_DECISIONS:
        actions.update({"block_autonomous_action", "write_audit_log", "preserve_review_ledger_entry"})
    elif op in QUARANTINE_DECISIONS:
        actions.update({"quarantine_artifact_or_context", "block_autonomous_action", "write_audit_log", "preserve_review_ledger_entry"})
    elif op == "PENDING":
        actions.update({"use_safe_default_until_review", "write_audit_log"})
    return sorted(actions)


def apply_review_ledger(
    policy_report_path: str,
    queue_path: str,
    ledger_csv: str,
    output_path: str = "cycle7_effective_policy_decisions.json",
    csv_path: Optional[str] = "cycle7_effective_policy_decisions.csv",
    md_path: Optional[str] = "cycle7_effective_policy_decisions.md",
    allowlist_path: Optional[str] = "cycle7_allowlist.json",
    denylist_path: Optional[str] = "cycle7_denylist.json",
) -> Dict[str, Any]:
    policy = load_json(policy_report_path)
    ledger_rows = read_ledger_csv(ledger_csv)
    by_key, by_review_id, by_event_id = ledger_indexes(ledger_rows)
    queue_by_event, queue_by_key = queue_indexes(queue_path)
    effective_rows: List[Dict[str, Any]] = []
    allowlist: List[Dict[str, Any]] = []
    denylist: List[Dict[str, Any]] = []
    now = utc_now()

    for d in policy.get("decisions", []) or []:
        if not isinstance(d, dict):
            continue
        event_id = str(d.get("event_id") or "")
        qitem = queue_by_event.get(event_id, {})
        review_key = str(qitem.get("review_key") or "")
        review_id = str(qitem.get("review_id") or "")
        ledger = None
        if review_key and review_key in by_key:
            ledger = by_key[review_key]
        elif review_id and review_id in by_review_id:
            ledger = by_review_id[review_id]
        elif event_id and event_id in by_event_id:
            ledger = by_event_id[event_id]
        op = normalize_operator_decision((ledger or {}).get("operator_decision")) if ledger else "PENDING"
        original = str(d.get("decision") or "ALLOW")
        eff = effective_decision(original, op)
        labels = normalize_list(d.get("matched_labels"))
        evidence = qitem.get("evidence") if isinstance(qitem.get("evidence"), dict) else {}
        content_hash = str((evidence or {}).get("content_hash") or "")
        row = dict(d)
        row.update({
            "review_key": review_key,
            "review_id": review_id,
            "original_decision": original,
            "operator_decision": op,
            "effective_decision": eff,
            "ledger_status": "applied" if ledger and op not in {"PENDING", "KEEP_ORIGINAL"} else ("pending" if qitem else "not_in_queue"),
            "operator": (ledger or {}).get("operator", ""),
            "operator_reason": (ledger or {}).get("reason", ""),
            "ledger_scope": (ledger or {}).get("scope", ""),
            "expires_at": (ledger or {}).get("expires_at", ""),
            "content_hash": content_hash,
            "containment_actions": ledger_containment(op, d.get("containment_actions", [])),
        })
        effective_rows.append(row)
        list_entry = {
            "created_at": now,
            "review_key": review_key,
            "review_id": review_id,
            "event_id": event_id,
            "node_id": d.get("node_id", ""),
            "source": d.get("source", ""),
            "source_path": d.get("source_path", ""),
            "content_hash": content_hash,
            "labels": labels,
            "operator_decision": op,
            "operator": (ledger or {}).get("operator", ""),
            "reason": (ledger or {}).get("reason", ""),
            "expires_at": (ledger or {}).get("expires_at", ""),
        }
        if op in {"APPROVE_ALWAYS", "FALSE_POSITIVE"}:
            allowlist.append(list_entry)
        if op in DENY_DECISIONS | QUARANTINE_DECISIONS:
            denylist.append(list_entry)

    summary = {
        "total_decisions": len(effective_rows),
        "ledger_rows": len(ledger_rows),
        "applied_ledger_rows": sum(1 for r in effective_rows if r.get("ledger_status") == "applied"),
        "pending_review_rows": sum(1 for r in effective_rows if r.get("ledger_status") == "pending"),
        "by_effective_decision": dict(sorted(Counter(str(r.get("effective_decision")) for r in effective_rows).items())),
        "by_operator_decision": dict(sorted(Counter(str(r.get("operator_decision")) for r in effective_rows).items())),
        "allowlist_entries": len(allowlist),
        "denylist_entries": len(denylist),
    }
    report = {
        "tool": "PooleShield effective policy decisions",
        "version": VERSION,
        "generated_at": now,
        "policy_report": policy_report_path,
        "queue_path": queue_path,
        "ledger_csv": ledger_csv,
        "summary": summary,
        "decisions": effective_rows,
    }
    write_json(output_path, report)
    if csv_path:
        write_effective_csv(csv_path, effective_rows)
    if md_path:
        write_effective_md(md_path, report)
    if allowlist_path:
        write_json(allowlist_path, {"tool": "PooleShield allowlist", "version": VERSION, "generated_at": now, "entries": allowlist})
    if denylist_path:
        write_json(denylist_path, {"tool": "PooleShield denylist", "version": VERSION, "generated_at": now, "entries": denylist})
    return report


def write_effective_csv(path: str, rows: Sequence[Dict[str, Any]]) -> None:
    fields = [
        "review_key", "review_id", "event_id", "node_id", "source", "source_path",
        "risk_score", "level", "original_decision", "operator_decision", "effective_decision",
        "ledger_status", "operator", "operator_reason", "content_hash", "matched_labels", "containment_actions",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            out = dict(row)
            for k in ["matched_labels", "containment_actions"]:
                out[k] = ";".join(normalize_list(out.get(k)))
            writer.writerow({k: out.get(k, "") for k in fields})


def write_effective_md(path: str, report: Dict[str, Any]) -> None:
    lines = [
        "# PooleShield Effective Policy Decisions",
        "",
        f"Version: {report.get('version')}",
        f"Generated: {report.get('generated_at')}",
        f"Ledger: `{report.get('ledger_csv')}`",
        "",
        "## Summary",
        "",
        f"Total decisions: {report['summary']['total_decisions']}",
        f"Applied ledger rows: {report['summary']['applied_ledger_rows']}",
        f"By effective decision: `{report['summary']['by_effective_decision']}`",
        f"Allowlist entries: {report['summary']['allowlist_entries']}",
        f"Denylist entries: {report['summary']['denylist_entries']}",
        "",
    ]
    for row in report.get("decisions", []):
        lines.append(f"## {row.get('effective_decision')} risk={row.get('risk_score')} — {row.get('node_id')}")
        lines.append(f"Original: `{row.get('original_decision')}`  Operator: `{row.get('operator_decision')}`  Status: `{row.get('ledger_status')}`")
        lines.append(f"Review key: `{row.get('review_key')}`")
        if row.get("source_path"):
            lines.append(f"Source path: `{row.get('source_path')}`")
        if row.get("operator_reason"):
            lines.append(f"Reason: {row.get('operator_reason')}")
        lines.append(f"Containment: {', '.join(normalize_list(row.get('containment_actions'))) or 'none'}")
        lines.append("")
    Path(path).write_text("\n".join(lines), encoding="utf-8")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="PooleShield v1.8 review ledger")
    sub = parser.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("template", help="Build an editable review-ledger CSV template from an approval queue")
    t.add_argument("--queue", required=True)
    t.add_argument("--csv", default="cycle7_review_ledger_template.csv")
    t.add_argument("--json", default="cycle7_review_ledger_template.json")
    t.add_argument("--md", default="cycle7_review_ledger_template.md")
    d = sub.add_parser("demo-decisions", help="Build a deterministic demo decision CSV from an approval queue")
    d.add_argument("--queue", required=True)
    d.add_argument("--csv", default="cycle7_review_decisions_demo.csv")
    a = sub.add_parser("apply", help="Apply a review-ledger CSV to a policy report")
    a.add_argument("--policy-report", required=True)
    a.add_argument("--queue", required=True)
    a.add_argument("--ledger", required=True)
    a.add_argument("--output", default="cycle7_effective_policy_decisions.json")
    a.add_argument("--csv", default="cycle7_effective_policy_decisions.csv")
    a.add_argument("--md", default="cycle7_effective_policy_decisions.md")
    a.add_argument("--allowlist", default="cycle7_allowlist.json")
    a.add_argument("--denylist", default="cycle7_denylist.json")
    args = parser.parse_args(argv)

    if args.cmd == "template":
        report = build_review_template(args.queue, args.csv, args.json, args.md)
        print(json.dumps(report["summary"], indent=2, ensure_ascii=False))
        for p in [args.csv, args.json, args.md]:
            print(f"Wrote: {p}")
    elif args.cmd == "demo-decisions":
        rows = write_demo_decisions_from_queue(args.queue, args.csv)
        print(json.dumps({"demo_rows": len(rows)}, indent=2, ensure_ascii=False))
        print(f"Wrote: {args.csv}")
    elif args.cmd == "apply":
        report = apply_review_ledger(args.policy_report, args.queue, args.ledger, args.output, args.csv, args.md, args.allowlist, args.denylist)
        print(json.dumps(report["summary"], indent=2, ensure_ascii=False))
        for p in [args.output, args.csv, args.md, args.allowlist, args.denylist]:
            print(f"Wrote: {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
