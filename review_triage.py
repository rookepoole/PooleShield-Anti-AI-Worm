#!/usr/bin/env python3
"""
PooleShield v1.8 review triage.

Defensive purpose:
  Summarize large approval queues into review groups and create an optional
  suggestion ledger that operators can inspect before applying.

Safety boundary:
  This module reads PooleShield report metadata only. It does not read
  normalized event text, decoded DAT text, or source files. Suggestions are
  advisory and never enforced unless an operator explicitly applies a ledger.
"""
from __future__ import annotations

import csv
import datetime as dt
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from approval_queue import normalize_list
from result_bundler import bundle_output_dir

VERSION = "2.0"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return data


def write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def write_csv(path: Path, rows: List[Dict[str, Any]], fields: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            w.writerow(row)


def queue_items(queue: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [x for x in queue.get("items", []) or [] if isinstance(x, dict)]


def evidence(item: Dict[str, Any]) -> Dict[str, Any]:
    ev = item.get("evidence") or {}
    return ev if isinstance(ev, dict) else {}


def content_hash(item: Dict[str, Any]) -> str:
    return str(evidence(item).get("content_hash") or "")


def tool_calls(item: Dict[str, Any]) -> List[str]:
    return normalize_list(evidence(item).get("tool_calls"))


def labels(item: Dict[str, Any]) -> List[str]:
    return normalize_list(item.get("matched_labels"))


def source_group(item: Dict[str, Any]) -> str:
    node = str(item.get("node_id") or "")
    if ":chunk" in node:
        return node.split(":chunk", 1)[0]
    return node


def label_signature(item: Dict[str, Any]) -> str:
    return ";".join(sorted(labels(item))) or "none"


def tool_signature(item: Dict[str, Any]) -> str:
    return ";".join(sorted(tool_calls(item))) or "none"


def suggest_decision(item: Dict[str, Any], preset: str) -> Tuple[str, str, str]:
    """Return (operator_decision, confidence, reason)."""
    lab = set(labels(item))
    calls = set(tool_calls(item))
    original = str(item.get("decision") or "")
    level = str(item.get("level") or "")
    risk = float(item.get("risk_score") or 0.0)

    if preset == "strict":
        return "KEEP_ORIGINAL", "high", "strict preset keeps every policy decision for manual/operator review"

    if preset != "archived-chat-readonly":
        return "KEEP_ORIGINAL", "low", f"unknown preset {preset}; keep original decision"

    # Archived static chat logs are not live agent instructions by themselves.
    # Still keep high-severity and tool/fanout-related cases in the queue.
    if original in {"BLOCK", "QUARANTINE"} or level in {"RESTRICT", "QUARANTINE"} or risk >= 0.4:
        return "KEEP_ORIGINAL", "high", "high-severity item; inspect locally before overriding"

    if lab == {"persistent_write"} and not calls:
        return "ALLOW_LOG", "medium", "archived read-only text with persistent-write wording only; log rather than block if not feeding to autonomous memory/RAG"

    if "persistent_write" in lab and not (lab & {"dangerous_tool_call", "untrusted_to_dangerous_action", "fanout_anomaly"}) and not calls:
        return "ALLOW_LOG", "medium", "archived read-only text with persistence label and no tool/fanout signal"

    if lab & {"dangerous_tool_call", "untrusted_to_dangerous_action", "fanout_anomaly"}:
        return "KEEP_ORIGINAL", "medium", "tool/fanout-related archived text; review locally before approving"

    return "KEEP_ORIGINAL", "low", "no specific triage rule matched; keep original policy decision"


def build_triage(
    output_dir: str,
    queue_path: Optional[str] = None,
    preset: str = "archived-chat-readonly",
    bundle_output: bool = False,
    bundle_path: Optional[str] = None,
    privacy_bundle: bool = True,
) -> Dict[str, Any]:
    out = Path(output_dir)
    queue_file = Path(queue_path) if queue_path else out / "approval_queue.json"
    if not queue_file.exists():
        raise FileNotFoundError(f"Approval queue not found: {queue_file}")
    queue = load_json(queue_file)
    items = queue_items(queue)

    generated_at = utc_now()
    triage_rows: List[Dict[str, Any]] = []
    group_map: Dict[Tuple[str, str, str, str, str], Dict[str, Any]] = {}
    source_counts: Counter[str] = Counter()
    label_counts: Counter[str] = Counter()
    suggestion_counts: Counter[str] = Counter()
    confidence_counts: Counter[str] = Counter()

    for item in items:
        lab = labels(item)
        calls = tool_calls(item)
        sg = source_group(item)
        source_counts[sg] += 1
        label_counts.update(lab)
        suggested, confidence, reason = suggest_decision(item, preset)
        suggestion_counts[suggested] += 1
        confidence_counts[confidence] += 1
        key = (
            str(item.get("priority") or ""),
            str(item.get("decision") or ""),
            str(item.get("level") or ""),
            label_signature(item),
            tool_signature(item),
        )
        g = group_map.setdefault(key, {
            "priority": key[0],
            "original_decision": key[1],
            "level": key[2],
            "labels": key[3],
            "tool_calls": key[4],
            "count": 0,
            "max_risk_score": 0.0,
            "suggested_operator_decision_counts": Counter(),
            "source_group_examples": [],
        })
        g["count"] += 1
        g["max_risk_score"] = max(float(g["max_risk_score"]), float(item.get("risk_score") or 0.0))
        g["suggested_operator_decision_counts"][suggested] += 1
        if sg and sg not in g["source_group_examples"] and len(g["source_group_examples"]) < 5:
            g["source_group_examples"].append(sg)

        triage_rows.append({
            "review_key": item.get("review_key", ""),
            "review_id": item.get("review_id", ""),
            "event_id": item.get("event_id", ""),
            "priority": item.get("priority", ""),
            "node_id": item.get("node_id", ""),
            "source": item.get("source", ""),
            "source_path": item.get("source_path", ""),
            "content_hash": content_hash(item),
            "risk_score": item.get("risk_score", 0.0),
            "level": item.get("level", ""),
            "original_decision": item.get("decision", ""),
            "safe_default": item.get("safe_default", ""),
            "operator_decision": suggested,
            "scope": "CONTENT_HASH",
            "operator": "",
            "reason": reason,
            "expires_at": "",
            "notes": f"triage_preset={preset}; suggestion_confidence={confidence}; inspect source locally before applying",
            "suggestion_confidence": confidence,
            "matched_labels": ";".join(lab),
            "tool_calls": ";".join(calls),
            "source_group": sg,
        })

    group_rows: List[Dict[str, Any]] = []
    for g in group_map.values():
        counts = g.pop("suggested_operator_decision_counts")
        g["suggested_operator_decisions"] = dict(sorted(counts.items()))
        g["source_group_examples"] = "; ".join(g["source_group_examples"])
        group_rows.append(g)
    group_rows.sort(key=lambda r: (-int(r["count"]), r["priority"], r["labels"]))
    triage_rows.sort(key=lambda r: (r["priority"], -float(r["risk_score"] or 0.0), r["node_id"]))

    summary = {
        "total_items": len(items),
        "by_priority": dict(sorted(Counter(str(i.get("priority") or "") for i in items).items())),
        "by_original_decision": dict(sorted(Counter(str(i.get("decision") or "") for i in items).items())),
        "by_level": dict(sorted(Counter(str(i.get("level") or "") for i in items).items())),
        "by_suggested_operator_decision": dict(sorted(suggestion_counts.items())),
        "by_suggestion_confidence": dict(sorted(confidence_counts.items())),
        "label_counts": dict(sorted(label_counts.items())),
        "source_group_count": len(source_counts),
        "top_source_groups": [{"source_group": k, "count": v} for k, v in source_counts.most_common(10)],
        "group_count": len(group_rows),
    }

    report = {
        "tool": "PooleShield review triage",
        "version": VERSION,
        "generated_at": generated_at,
        "queue_path": str(queue_file),
        "preset": preset,
        "privacy_note": "No normalized event text or decoded DAT text was read. This report uses queue metadata only.",
        "summary": summary,
        "groups": group_rows,
        "suggested_ledger_rows": triage_rows,
    }

    report_json = out / "review_triage_report.json"
    report_md = out / "review_triage_report.md"
    groups_csv = out / "review_groups.csv"
    suggested_csv = out / "suggested_review_ledger.csv"
    write_json(report_json, report)
    write_csv(groups_csv, group_rows, [
        "priority", "original_decision", "level", "labels", "tool_calls", "count", "max_risk_score", "suggested_operator_decisions", "source_group_examples"
    ])
    write_csv(suggested_csv, triage_rows, [
        "review_key", "review_id", "event_id", "priority", "node_id", "source", "source_path", "content_hash",
        "risk_score", "level", "original_decision", "safe_default", "operator_decision", "scope", "operator",
        "reason", "expires_at", "notes", "suggestion_confidence", "matched_labels", "tool_calls", "source_group"
    ])
    write_triage_md(report_md, report, suggested_csv, groups_csv)

    bundle_summary = None
    if bundle_output:
        bundle_summary = bundle_output_dir(str(out), bundle_path, privacy_mode=privacy_bundle)

    run_summary = {
        "tool": "PooleShield operator",
        "version": VERSION,
        "mode": "review-triage",
        "output_dir": str(out),
        "queue_path": str(queue_file),
        "preset": preset,
        "summary": summary,
        "review_triage_report": str(report_json),
        "review_triage_report_md": str(report_md),
        "review_groups_csv": str(groups_csv),
        "suggested_review_ledger_csv": str(suggested_csv),
        "result_bundle": bundle_summary.get("bundle_path") if bundle_summary else "",
        "bundle_summary": bundle_summary,
    }
    write_json(out / "RUN_SUMMARY_TRIAGE.json", run_summary)
    write_triage_summary_md(out / "RUN_SUMMARY_TRIAGE.md", run_summary)
    if bundle_output:
        # Rebundle so RUN_SUMMARY_TRIAGE is included too.
        bundle_summary = bundle_output_dir(str(out), bundle_path, privacy_mode=privacy_bundle)
        run_summary["bundle_summary"] = bundle_summary
        run_summary["result_bundle"] = bundle_summary.get("bundle_path")
        write_json(out / "RUN_SUMMARY_TRIAGE.json", run_summary)
        write_triage_summary_md(out / "RUN_SUMMARY_TRIAGE.md", run_summary)
    return run_summary


def write_triage_md(path: Path, report: Dict[str, Any], suggested_csv: Path, groups_csv: Path) -> None:
    summary = report.get("summary", {})
    lines = [
        "# PooleShield Review Triage Report",
        "",
        f"Version: {report.get('version')}",
        f"Generated: {report.get('generated_at')}",
        f"Preset: `{report.get('preset')}`",
        "",
        "## Privacy boundary",
        "",
        str(report.get("privacy_note")),
        "",
        "## Summary",
        "",
        f"Total review items: `{summary.get('total_items')}`",
        f"By priority: `{summary.get('by_priority')}`",
        f"By original decision: `{summary.get('by_original_decision')}`",
        f"By level: `{summary.get('by_level')}`",
        f"Suggested operator decisions: `{summary.get('by_suggested_operator_decision')}`",
        f"Suggestion confidence: `{summary.get('by_suggestion_confidence')}`",
        f"Label counts: `{summary.get('label_counts')}`",
        "",
        "## Files written",
        "",
        f"- Suggested ledger: `{suggested_csv}`",
        f"- Review groups: `{groups_csv}`",
        "",
        "## Top groups",
        "",
    ]
    for g in report.get("groups", [])[:10]:
        lines.append(f"- count `{g.get('count')}`, priority `{g.get('priority')}`, decision `{g.get('original_decision')}`, level `{g.get('level')}`, labels `{g.get('labels')}`, tools `{g.get('tool_calls')}`, suggestions `{g.get('suggested_operator_decisions')}`")
    lines += [
        "",
        "## Operator caution",
        "",
        "Do not apply `suggested_review_ledger.csv` blindly. It is a privacy-safe triage aid for archived/read-only chat logs. Inspect high-severity and tool/fanout-related rows locally before applying.",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def write_triage_summary_md(path: Path, summary: Dict[str, Any]) -> None:
    s = summary.get("summary", {})
    lines = [
        "# PooleShield Review Triage Run Summary",
        "",
        f"Version: {summary.get('version')}",
        f"Mode: `{summary.get('mode')}`",
        f"Preset: `{summary.get('preset')}`",
        "",
        f"Total review items: `{s.get('total_items')}`",
        f"Suggested decisions: `{s.get('by_suggested_operator_decision')}`",
        f"Groups: `{s.get('group_count')}`",
        "",
        "## Next step",
        "",
        "Open `review_triage_report.md` and `suggested_review_ledger.csv`. If the suggestions match your intent, apply the ledger with `apply-ledger`. Otherwise edit the CSV first.",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":  # pragma: no cover
    import argparse
    p = argparse.ArgumentParser(description="Group and suggest review ledger actions for a PooleShield approval queue")
    p.add_argument("--output-dir", required=True)
    p.add_argument("--queue", default=None)
    p.add_argument("--preset", choices=["archived-chat-readonly", "strict"], default="archived-chat-readonly")
    p.add_argument("--bundle-output", action="store_true")
    p.add_argument("--bundle-path", default=None)
    p.add_argument("--privacy-bundle", action="store_true", default=True)
    args = p.parse_args()
    print(json.dumps(build_triage(args.output_dir, args.queue, args.preset, args.bundle_output, args.bundle_path, args.privacy_bundle), indent=2, ensure_ascii=False))
