#!/usr/bin/env python3
"""
PooleShield v1.8 policy gate.

Defensive purpose:
  Convert PooleShield risk reports into practical allow / log / approval / block /
  quarantine decisions for AI-agent tool use, RAG writes, email sends, and other
  autonomous workflow actions.

Safety boundary:
  This module does not execute actions, block real services, call APIs, modify
  system policy, or touch user data beyond reading supplied PooleShield reports.
  It emits auditable decisions that a human or a separate production system can
  review before enforcement.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

VERSION = "2.0"

LEVEL_RANK = {
    "NORMAL": 0,
    "WATCH": 1,
    "RESTRICT": 2,
    "QUARANTINE": 3,
    "ISOLATE": 4,
}

DECISION_RANK = {
    "ALLOW": 0,
    "ALLOW_LOG": 1,
    "REQUIRE_APPROVAL": 2,
    "BLOCK": 3,
    "QUARANTINE": 4,
}

DEFAULT_POLICY: Dict[str, Any] = {
    "alert_threshold": 0.25,
    "approval_min_level": "WATCH",
    "block_min_level": "RESTRICT",
    "quarantine_min_level": "QUARANTINE",
    "allow_log_risk": 0.10,
    "quarantine_labels": [
        "cross_context_replication",
        "worm_geometry",
    ],
    "quarantine_actions": [
        "isolate_node_from_agent_mesh",
        "disable_agent_until_review",
    ],
    "block_actions": [
        "block_auto_send_forward_delete_execute",
    ],
    "approval_actions": [
        "require_human_approval_for_dangerous_tools",
        "quarantine_untrusted_memory_or_rag_write",
        "temporarily_limit_outbound_fanout",
    ],
    "approval_labels": [
        "dangerous_tool_call",
        "untrusted_to_dangerous_action",
        "persistent_write",
        "fanout_anomaly",
        "secret_interest",
        "sensitive_access",
        "instruction_override",
        "tool_use_instruction",
    ],
    "sensitive_labels": [
        "secret_interest",
        "sensitive_access",
    ],
    # Strict default: mentions of secrets/tokens require approval even when
    # the raw risk score is low. Balanced profiles can set this false so
    # normal, expected security-maintenance notes become ALLOW_LOG instead
    # of REQUIRE_APPROVAL.
    "sensitive_requires_approval": True,
}


@dataclass
class PolicyDecision:
    event_id: str
    node_id: str
    source: str
    source_path: str
    risk_score: float
    level: str
    decision: str
    decision_rank: int
    reasons: List[str]
    containment_actions: List[str]
    matched_labels: List[str]
    recommended_actions: List[str]


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def rank_level(level: str) -> int:
    return LEVEL_RANK.get(str(level or "NORMAL").upper(), 0)


def normalize_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x) for x in value]
    if isinstance(value, tuple):
        return [str(x) for x in value]
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return []
        # Accept semicolon/comma joined CSV fields from prior reports.
        if ";" in s:
            return [x.strip() for x in s.split(";") if x.strip()]
        if "," in s and len(s) < 1000:
            return [x.strip() for x in s.split(",") if x.strip()]
        return [s]
    return [str(value)]


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return data


def load_policy(path: Optional[str]) -> Dict[str, Any]:
    policy = dict(DEFAULT_POLICY)
    if not path:
        return policy
    user_policy = load_json(path)
    for k, v in user_policy.items():
        policy[k] = v
    return policy


def extract_entries(report_or_manifest: Dict[str, Any], path_by_event_id: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    """Accept a PooleShield scan report, raw detector report, or manifest."""
    path_by_event_id = path_by_event_id or {}
    if "entries" in report_or_manifest:
        entries = list(report_or_manifest.get("entries") or [])
        return entries
    if "events" in report_or_manifest:
        events = list(report_or_manifest.get("events") or [])
        normalized = []
        for e in events:
            if not isinstance(e, dict):
                continue
            item = dict(e)
            item["labels"] = item.get("labels") or item.get("matched_labels") or []
            item["recommended_actions"] = item.get("recommended_actions") or item.get("actions") or []
            item["source_path"] = item.get("source_path") or path_by_event_id.get(str(item.get("event_id")), "")
            normalized.append(item)
        return normalized
    raise ValueError("Input must contain either 'events' or 'entries'.")


def decision_max(current: str, candidate: str) -> str:
    return candidate if DECISION_RANK[candidate] > DECISION_RANK[current] else current


def decide_one(entry: Dict[str, Any], policy: Dict[str, Any]) -> PolicyDecision:
    event_id = str(entry.get("event_id") or "")
    node_id = str(entry.get("node_id") or "unknown-node")
    source = str(entry.get("source") or "unknown")
    source_path = str(entry.get("source_path") or entry.get("path") or "")
    risk = float(entry.get("risk_score") or 0.0)
    level = str(entry.get("level") or "NORMAL").upper()
    labels = sorted(set(normalize_list(entry.get("labels") or entry.get("matched_labels"))))
    actions = sorted(set(normalize_list(entry.get("recommended_actions") or entry.get("actions"))))

    label_set = set(labels)
    action_set = set(actions)
    significant_action_set = action_set - {"log_only"}
    reasons: List[str] = []
    containment: List[str] = []
    decision = "ALLOW"

    if risk >= float(policy.get("allow_log_risk", 0.10)) or labels or significant_action_set:
        decision = decision_max(decision, "ALLOW_LOG")
        reasons.append("audit_log_due_to_nonzero_risk_or_labels")
        containment.append("write_audit_log")

    if risk >= float(policy.get("alert_threshold", 0.25)):
        decision = decision_max(decision, "REQUIRE_APPROVAL")
        reasons.append("risk_at_or_above_alert_threshold")
        containment.append("require_human_review_before_autonomous_action")

    if rank_level(level) >= rank_level(str(policy.get("approval_min_level", "WATCH"))):
        decision = decision_max(decision, "REQUIRE_APPROVAL")
        reasons.append(f"level_at_or_above_{policy.get('approval_min_level', 'WATCH')}")
        containment.append("require_human_review_before_autonomous_action")

    approval_labels = set(normalize_list(policy.get("approval_labels")))
    if label_set & approval_labels:
        decision = decision_max(decision, "REQUIRE_APPROVAL")
        reasons.append("approval_label_present:" + ",".join(sorted(label_set & approval_labels)))
        containment.append("require_human_review_before_autonomous_action")

    sensitive_labels = set(normalize_list(policy.get("sensitive_labels")))
    if label_set & sensitive_labels:
        if bool(policy.get("sensitive_requires_approval", True)):
            decision = decision_max(decision, "REQUIRE_APPROVAL")
            reasons.append("sensitive_access_or_secret_interest")
            containment.append("review_secret_or_token_exposure")
        else:
            # Balanced policy mode: still audit sensitive/security-maintenance
            # references, but do not require approval unless another risk
            # trigger is present. This reduces noise for expected token-rotation
            # notes while preserving visibility.
            decision = decision_max(decision, "ALLOW_LOG")
            reasons.append("sensitive_reference_audit_only")
            containment.append("review_secret_or_token_exposure_if_unexpected")

    approval_actions = set(normalize_list(policy.get("approval_actions")))
    if significant_action_set & approval_actions:
        decision = decision_max(decision, "REQUIRE_APPROVAL")
        reasons.append("approval_action_recommended:" + ",".join(sorted(significant_action_set & approval_actions)))
        containment.extend(sorted(significant_action_set & approval_actions))

    if rank_level(level) >= rank_level(str(policy.get("block_min_level", "RESTRICT"))):
        decision = decision_max(decision, "BLOCK")
        reasons.append(f"level_at_or_above_{policy.get('block_min_level', 'RESTRICT')}")
        containment.append("block_autonomous_dangerous_action")

    block_actions = set(normalize_list(policy.get("block_actions")))
    if significant_action_set & block_actions:
        decision = decision_max(decision, "BLOCK")
        reasons.append("block_action_recommended:" + ",".join(sorted(significant_action_set & block_actions)))
        containment.extend(sorted(significant_action_set & block_actions))

    if rank_level(level) >= rank_level(str(policy.get("quarantine_min_level", "QUARANTINE"))):
        decision = decision_max(decision, "QUARANTINE")
        reasons.append(f"level_at_or_above_{policy.get('quarantine_min_level', 'QUARANTINE')}")
        containment.append("quarantine_node_or_input_until_review")

    quarantine_actions = set(normalize_list(policy.get("quarantine_actions")))
    if significant_action_set & quarantine_actions:
        decision = decision_max(decision, "QUARANTINE")
        reasons.append("quarantine_action_recommended:" + ",".join(sorted(significant_action_set & quarantine_actions)))
        containment.extend(sorted(significant_action_set & quarantine_actions))

    quarantine_labels = set(normalize_list(policy.get("quarantine_labels")))
    if label_set & quarantine_labels and rank_level(level) >= rank_level("WATCH"):
        # Cycle 5 boundary: worm-geometry labels in WATCH get treated as quarantine
        # candidates because propagation geometry is more important than a raw score.
        decision = decision_max(decision, "QUARANTINE")
        reasons.append("worm_geometry_or_replication_label_present")
        containment.append("snapshot_event_lineage")
        containment.append("temporarily_limit_outbound_fanout")

    if not reasons:
        reasons.append("no_policy_trigger")
        containment.append("allow")

    # Deduplicate while preserving sorted stable output for reports.
    containment = sorted(set(containment))
    return PolicyDecision(
        event_id=event_id,
        node_id=node_id,
        source=source,
        source_path=source_path,
        risk_score=round(risk, 4),
        level=level,
        decision=decision,
        decision_rank=DECISION_RANK[decision],
        reasons=sorted(set(reasons)),
        containment_actions=containment,
        matched_labels=labels,
        recommended_actions=actions,
    )


def build_policy_report(
    report_path: str,
    output_path: str,
    csv_path: Optional[str] = None,
    md_path: Optional[str] = None,
    policy_path: Optional[str] = None,
    path_by_event_id: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    policy = load_policy(policy_path)
    raw = load_json(report_path)
    entries = extract_entries(raw, path_by_event_id=path_by_event_id)
    decisions = [decide_one(e, policy) for e in entries]

    by_decision: Dict[str, int] = {}
    by_level: Dict[str, int] = {}
    for d in decisions:
        by_decision[d.decision] = by_decision.get(d.decision, 0) + 1
        by_level[d.level] = by_level.get(d.level, 0) + 1

    report = {
        "tool": "PooleShield policy gate",
        "version": VERSION,
        "generated_at": utc_now(),
        "input_report": report_path,
        "policy_path": policy_path or "default_policy",
        "policy_summary": {
            "alert_threshold": policy.get("alert_threshold"),
            "approval_min_level": policy.get("approval_min_level"),
            "block_min_level": policy.get("block_min_level"),
            "quarantine_min_level": policy.get("quarantine_min_level"),
        },
        "summary": {
            "total_decisions": len(decisions),
            "by_decision": dict(sorted(by_decision.items())),
            "by_level": dict(sorted(by_level.items())),
            "max_decision_rank": max((d.decision_rank for d in decisions), default=0),
            "max_risk_score": max((d.risk_score for d in decisions), default=0.0),
        },
        "decisions": [asdict(d) for d in sorted(decisions, key=lambda x: (x.decision_rank, x.risk_score), reverse=True)],
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    if csv_path:
        write_policy_csv(csv_path, decisions)
    if md_path:
        write_policy_md(md_path, report)
    return report


def write_policy_csv(path: str, decisions: Sequence[PolicyDecision]) -> None:
    fields = [
        "event_id", "node_id", "source", "source_path", "risk_score", "level",
        "decision", "reasons", "containment_actions", "matched_labels", "recommended_actions",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for d in sorted(decisions, key=lambda x: (x.decision_rank, x.risk_score), reverse=True):
            row = asdict(d)
            for k in ["reasons", "containment_actions", "matched_labels", "recommended_actions"]:
                row[k] = ";".join(row.get(k) or [])
            writer.writerow({k: row.get(k, "") for k in fields})


def write_policy_md(path: str, report: Dict[str, Any]) -> None:
    lines = [
        "# PooleShield Policy Decisions",
        "",
        f"Version: {report.get('version')}",
        f"Generated: {report.get('generated_at')}",
        f"Input report: `{report.get('input_report')}`",
        "",
        "## Summary",
        "",
        f"Total decisions: {report['summary']['total_decisions']}",
        f"By decision: `{report['summary']['by_decision']}`",
        f"By level: `{report['summary']['by_level']}`",
        "",
        "## Decisions",
        "",
    ]
    for d in report.get("decisions", []):
        lines.append(f"### {d['decision']} risk={d['risk_score']} level={d['level']} — {d['node_id']}")
        if d.get("source_path"):
            lines.append(f"Source path: `{d['source_path']}`")
        lines.append(f"Event: `{d['event_id']}`  Source: `{d['source']}`")
        lines.append(f"Reasons: {', '.join(d.get('reasons', [])) or 'none'}")
        lines.append(f"Containment: {', '.join(d.get('containment_actions', [])) or 'none'}")
        lines.append(f"Labels: {', '.join(d.get('matched_labels', [])) or 'none'}")
        lines.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def write_default_policy(path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(DEFAULT_POLICY, f, indent=2, ensure_ascii=False)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="PooleShield v1.8 policy gate")
    parser.add_argument("--report", required=True, help="PooleShield scan/report JSON or quarantine manifest JSON")
    parser.add_argument("--output", default="cycle5_policy_decisions.json", help="JSON policy-decision report")
    parser.add_argument("--csv", default="cycle5_policy_decisions.csv", help="CSV policy-decision report")
    parser.add_argument("--md", default="cycle5_policy_decisions.md", help="Markdown policy-decision report")
    parser.add_argument("--policy", default=None, help="Optional policy_config.json override")
    parser.add_argument("--write-default-policy", default=None, help="Write the default policy config to this path and exit")
    args = parser.parse_args(argv)

    if args.write_default_policy:
        write_default_policy(args.write_default_policy)
        print(f"Wrote default policy: {args.write_default_policy}")
        return 0

    report = build_policy_report(args.report, args.output, args.csv, args.md, args.policy)
    print(json.dumps(report["summary"], indent=2, ensure_ascii=False))
    print(f"\nWrote: {args.output}")
    print(f"Wrote: {args.csv}")
    print(f"Wrote: {args.md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
