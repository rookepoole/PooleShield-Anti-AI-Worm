#!/usr/bin/env python3
"""
PooleShield v1.8 approval queue.

Defensive purpose:
  Convert policy-gate decisions into a compact human-review queue. This is the
  handoff layer between detection/policy scoring and a real operator who decides
  whether an AI agent may proceed.

Safety boundary:
  This module does not approve, block, execute, delete, quarantine, or modify
  real systems. It emits review packets only. By default it does not reproduce
  suspicious content verbatim; it stores hashes and metadata so analysts can
  inspect the original source separately.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    from pooleshield import Event, stable_hash
except Exception:  # pragma: no cover - only for unusual import contexts
    Event = None  # type: ignore
    def stable_hash(text: str, n: int = 16) -> str:  # type: ignore
        return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:n]

VERSION = "2.0"

DECISION_RANK = {
    "ALLOW": 0,
    "ALLOW_LOG": 1,
    "REQUIRE_APPROVAL": 2,
    "BLOCK": 3,
    "QUARANTINE": 4,
}

PRIORITY_RANK = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}

SENSITIVE_RE = re.compile(
    r"(?i)(sk-[a-z0-9_-]{8,}|api[_ -]?key\s*[:=]\s*\S+|token\s*[:=]\s*\S+|password\s*[:=]\s*\S+|credential\s*[:=]\s*\S+)"
)

@dataclass
class ApprovalItem:
    review_id: str
    review_key: str
    event_id: str
    node_id: str
    source: str
    source_path: str
    risk_score: float
    level: str
    decision: str
    priority: str
    safe_default: str
    reasons: List[str]
    containment_actions: List[str]
    matched_labels: List[str]
    recommended_actions: List[str]
    review_questions: List[str]
    evidence: Dict[str, Any]


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return data


def normalize_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x) for x in value]
    if isinstance(value, tuple):
        return [str(x) for x in value]
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return []
        if ";" in value:
            return [x.strip() for x in value.split(";") if x.strip()]
        if "," in value and len(value) < 1000:
            return [x.strip() for x in value.split(",") if x.strip()]
        return [value]
    return [str(value)]


def load_normalized_events(path: Optional[str]) -> Dict[str, Dict[str, Any]]:
    """Map detector event_id -> metadata from normalized JSONL events."""
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        return {}
    by_event_id: Dict[str, Dict[str, Any]] = {}
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(raw, dict):
            continue
        try:
            if Event is not None:
                e = Event.from_dict(raw)  # type: ignore[attr-defined]
                event_id = stable_hash(f"{e.timestamp}|{e.node_id}|{e.source}|{e.content_hash}", 18)
                content = e.content
            else:
                content = str(raw.get("content") or "")
                event_id = stable_hash(str(raw.get("timestamp")) + str(raw.get("node_id")) + str(raw.get("source")) + stable_hash(content), 18)
        except Exception:
            content = str(raw.get("content") or "")
            event_id = stable_hash(json.dumps(raw, sort_keys=True), 18)
        by_event_id[event_id] = {
            "content_hash": hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest(),
            "content_chars": len(content),
            "tool_calls": normalize_list(raw.get("tool_calls")),
            "inbound_count": len(normalize_list(raw.get("inbound_from"))),
            "outbound_count": len(normalize_list(raw.get("outbound_to"))),
            "trust": str(raw.get("trust") or "unknown"),
            "notes": str(raw.get("notes") or ""),
            "redacted_preview": redact_preview(content),
        }
    return by_event_id


def redact_preview(text: str, max_chars: int = 220) -> str:
    """Return a short, non-executable preview with obvious secrets redacted."""
    cleaned = SENSITIVE_RE.sub("[REDACTED_SECRET]", text or "")
    cleaned = cleaned.replace("\r", " ").replace("\n", " ")
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if len(cleaned) > max_chars:
        cleaned = cleaned[: max_chars - 3].rstrip() + "..."
    return cleaned


def load_manifest_paths(path: Optional[str]) -> Dict[str, str]:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        return {}
    try:
        data = load_json(str(p))
    except Exception:
        return {}
    out: Dict[str, str] = {}
    for e in data.get("entries", []) or []:
        if isinstance(e, dict) and e.get("event_id"):
            out[str(e["event_id"])] = str(e.get("source_path") or "")
    return out


def priority_for(decision: str, level: str, labels: Iterable[str]) -> str:
    labels = set(labels)
    if decision in {"QUARANTINE", "BLOCK"} or level in {"QUARANTINE", "ISOLATE", "RESTRICT"}:
        return "P1"
    if labels & {"cross_context_replication", "worm_geometry", "instruction_override", "persistent_write", "untrusted_to_dangerous_action"}:
        return "P2"
    if labels & {"secret_interest", "sensitive_access"}:
        return "P3"
    if decision == "REQUIRE_APPROVAL":
        return "P3"
    return "P4"


def safe_default_for(decision: str, labels: Iterable[str]) -> str:
    label_set = set(labels)
    if decision in {"QUARANTINE", "BLOCK"}:
        return "DENY_UNTIL_REVIEW"
    if label_set & {"cross_context_replication", "worm_geometry", "instruction_override", "persistent_write", "untrusted_to_dangerous_action"}:
        return "DENY_OR_QUARANTINE_UNTIL_REVIEW"
    if label_set & {"secret_interest", "sensitive_access"}:
        return "VERIFY_EXPECTED_SECRET_ROTATION_THEN_ALLOW_LOG"
    if decision == "ALLOW_LOG":
        return "ALLOW_WITH_AUDIT_LOG"
    return "REQUIRE_MANUAL_APPROVAL"


def stable_review_key(decision_row: Dict[str, Any], evidence: Optional[Dict[str, Any]] = None) -> str:
    """Return a stable review key that survives event_id/timestamp changes.

    Event IDs can legitimately change across scans when text files are chunked
    with a current timestamp. For a useful review ledger, operator decisions
    need to attach to stable evidence: source, node, content hash, and label
    shape. Source paths are intentionally excluded because Windows/Linux paths
    and extracted folder names vary across machines.
    """
    evidence = evidence or {}
    labels = sorted(set(normalize_list(decision_row.get("matched_labels"))))
    content_hash = str(evidence.get("content_hash") or decision_row.get("content_hash") or "")
    if not content_hash:
        # Fallback keeps the function usable for reports that lack normalized
        # evidence, but normal Cycle 7 runs provide normalized event hashes.
        content_hash = str(decision_row.get("event_id") or "")
    payload = "|".join([
        str(decision_row.get("node_id") or "unknown-node"),
        str(decision_row.get("source") or "unknown"),
        content_hash,
        ";".join(labels),
    ])
    return stable_hash(payload, 24)


def questions_for(labels: Iterable[str], decision: str) -> List[str]:
    label_set = set(labels)
    questions: List[str] = [
        "Was this action explicitly requested by a trusted human/operator?",
        "Should this event be allowed to trigger autonomous tool use?",
    ]
    if label_set & {"instruction_override", "tool_use_instruction"}:
        questions.append("Is untrusted content trying to change the agent's goal or call tools?")
    if label_set & {"persistent_write", "persistence_intent"}:
        questions.append("Should this content be allowed to write to memory, RAG, config, or future context?")
    if label_set & {"fanout_anomaly", "worm_geometry", "cross_context_replication", "replication_intent"}:
        questions.append("Is there fan-out, replication, or cross-context spread beyond the intended workflow?")
    if label_set & {"secret_interest", "sensitive_access"}:
        questions.append("Are secret/token references expected, redacted, and limited to a trusted security workflow?")
    if decision in {"BLOCK", "QUARANTINE"}:
        questions.append("Should temporary containment remain in place until lineage is reviewed?")
    return questions


def should_include(decision: str, include_allowed: bool) -> bool:
    if include_allowed:
        return True
    return DECISION_RANK.get(decision, 0) >= DECISION_RANK["ALLOW_LOG"]


def build_queue(
    policy_report_path: str,
    output_path: str,
    csv_path: Optional[str] = None,
    md_path: Optional[str] = None,
    normalized_path: Optional[str] = None,
    manifest_path: Optional[str] = None,
    include_allowed: bool = False,
    include_redacted_preview: bool = False,
) -> Dict[str, Any]:
    policy_report = load_json(policy_report_path)
    normalized = load_normalized_events(normalized_path)
    manifest_paths = load_manifest_paths(manifest_path)

    items: List[ApprovalItem] = []
    for d in policy_report.get("decisions", []) or []:
        if not isinstance(d, dict):
            continue
        decision = str(d.get("decision") or "ALLOW")
        if not should_include(decision, include_allowed):
            continue
        event_id = str(d.get("event_id") or "")
        labels = sorted(set(normalize_list(d.get("matched_labels"))))
        actions = sorted(set(normalize_list(d.get("recommended_actions"))))
        containment = sorted(set(normalize_list(d.get("containment_actions"))))
        evidence = dict(normalized.get(event_id, {}))
        if evidence and not include_redacted_preview:
            evidence.pop("redacted_preview", None)
        source_path = str(d.get("source_path") or manifest_paths.get(event_id, ""))
        review_key = stable_review_key(d, evidence)
        review_id = "PSR-" + stable_hash(review_key, 12).upper()
        item = ApprovalItem(
            review_id=review_id,
            review_key=review_key,
            event_id=event_id,
            node_id=str(d.get("node_id") or "unknown-node"),
            source=str(d.get("source") or "unknown"),
            source_path=source_path,
            risk_score=round(float(d.get("risk_score") or 0.0), 4),
            level=str(d.get("level") or "NORMAL"),
            decision=decision,
            priority=priority_for(decision, str(d.get("level") or "NORMAL"), labels),
            safe_default=safe_default_for(decision, labels),
            reasons=sorted(set(normalize_list(d.get("reasons")))),
            containment_actions=containment,
            matched_labels=labels,
            recommended_actions=actions,
            review_questions=questions_for(labels, decision),
            evidence=evidence,
        )
        items.append(item)

    items.sort(key=lambda x: (PRIORITY_RANK.get(x.priority, 9), -DECISION_RANK.get(x.decision, 0), -x.risk_score, x.node_id))
    by_priority: Dict[str, int] = {}
    by_decision: Dict[str, int] = {}
    for item in items:
        by_priority[item.priority] = by_priority.get(item.priority, 0) + 1
        by_decision[item.decision] = by_decision.get(item.decision, 0) + 1

    report = {
        "tool": "PooleShield approval queue",
        "version": VERSION,
        "generated_at": utc_now(),
        "policy_report": policy_report_path,
        "normalized_path": normalized_path or "",
        "manifest_path": manifest_path or "",
        "include_allowed": include_allowed,
        "summary": {
            "total_items": len(items),
            "by_priority": dict(sorted(by_priority.items())),
            "by_decision": dict(sorted(by_decision.items())),
            "max_risk_score": max((i.risk_score for i in items), default=0.0),
        },
        "items": [asdict(i) for i in items],
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    if csv_path:
        write_queue_csv(csv_path, items)
    if md_path:
        write_queue_md(md_path, report)
    return report


def write_queue_csv(path: str, items: Sequence[ApprovalItem]) -> None:
    fields = [
        "review_id", "review_key", "priority", "decision", "safe_default", "risk_score", "level",
        "node_id", "source", "source_path", "event_id", "matched_labels",
        "containment_actions", "review_questions",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for item in items:
            row = asdict(item)
            for k in ["matched_labels", "containment_actions", "review_questions"]:
                row[k] = ";".join(row.get(k) or [])
            writer.writerow({k: row.get(k, "") for k in fields})


def write_queue_md(path: str, report: Dict[str, Any]) -> None:
    lines = [
        "# PooleShield Approval Queue",
        "",
        f"Version: {report.get('version')}",
        f"Generated: {report.get('generated_at')}",
        f"Policy report: `{report.get('policy_report')}`",
        "",
        "## Summary",
        "",
        f"Total items: {report['summary']['total_items']}",
        f"By priority: `{report['summary']['by_priority']}`",
        f"By decision: `{report['summary']['by_decision']}`",
        "",
    ]
    for item in report.get("items", []):
        lines.append(f"## {item['priority']} {item['decision']} risk={item['risk_score']} — {item['node_id']}")
        lines.append(f"Review ID: `{item['review_id']}`  Review key: `{item.get('review_key','')}`")
        lines.append(f"Event: `{item['event_id']}`  Source: `{item['source']}`")
        if item.get("source_path"):
            lines.append(f"Source path: `{item['source_path']}`")
        lines.append(f"Safe default: **{item['safe_default']}**")
        lines.append(f"Labels: {', '.join(item.get('matched_labels', [])) or 'none'}")
        lines.append(f"Containment: {', '.join(item.get('containment_actions', [])) or 'none'}")
        lines.append("Review questions:")
        for q in item.get("review_questions", []):
            lines.append(f"- {q}")
        ev = item.get("evidence") or {}
        if ev:
            lines.append("Evidence metadata:")
            for key in ["trust", "content_hash", "content_chars", "inbound_count", "outbound_count", "tool_calls"]:
                if key in ev:
                    lines.append(f"- {key}: `{ev[key]}`")
            if "redacted_preview" in ev:
                lines.append(f"- redacted_preview: `{ev['redacted_preview']}`")
        lines.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="PooleShield v1.8 approval-queue builder")
    parser.add_argument("--policy-report", required=True, help="Policy decision JSON from policy_gate.py")
    parser.add_argument("--output", default="cycle7_approval_queue.json", help="Approval queue JSON")
    parser.add_argument("--csv", default="cycle7_approval_queue.csv", help="Approval queue CSV")
    parser.add_argument("--md", default="cycle7_approval_queue.md", help="Approval queue Markdown")
    parser.add_argument("--normalized", default=None, help="Optional normalized JSONL events for evidence metadata")
    parser.add_argument("--manifest", default=None, help="Optional quarantine manifest for source-path enrichment")
    parser.add_argument("--include-allowed", action="store_true", help="Include ALLOW decisions in the review queue")
    parser.add_argument("--include-redacted-preview", action="store_true", help="Include short redacted content previews in queue output")
    args = parser.parse_args(argv)

    report = build_queue(
        policy_report_path=args.policy_report,
        output_path=args.output,
        csv_path=args.csv,
        md_path=args.md,
        normalized_path=args.normalized,
        manifest_path=args.manifest,
        include_allowed=args.include_allowed,
        include_redacted_preview=args.include_redacted_preview,
    )
    print(json.dumps(report["summary"], indent=2, ensure_ascii=False))
    for p in [args.output, args.csv, args.md]:
        print(f"Wrote: {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
