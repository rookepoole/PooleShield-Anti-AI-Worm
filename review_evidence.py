#!/usr/bin/env python3
"""
PooleShield v2.0 local review evidence viewer.

Defensive purpose:
  Inspect only the remaining pending approval items on the operator's machine,
  show local redacted evidence for why each item was flagged, and create a
  suggested ledger that an operator can inspect before applying.

Safety boundary:
  This module reads local text files referenced by PooleShield reports and writes
  reports only. It does not execute, call tools, send, delete, quarantine, or
  modify scanned content. The local evidence report may contain redacted context
  and is treated as content-bearing; privacy bundles exclude it by default.
"""
from __future__ import annotations

import csv
import datetime as dt
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from corpus_scanner import chunk_text, safe_read_text
from result_bundler import bundle_output_dir

VERSION = "2.0"

PENDING_DECISIONS = {"REQUIRE_APPROVAL", "BLOCK", "QUARANTINE"}

KEYWORD_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("prompt_override", re.compile(r"\b(ignore\s+(all\s+)?previous|ignore\s+prior|system\s+prompt|developer\s+message|override\s+instructions|jailbreak|you\s+are\s+now)\b", re.I)),
    ("dangerous_tool", re.compile(r"\b(send_email|forward_email|send_message|post_message|delete_email|delete_file|archive_email|execute_code|run_shell|powershell|cmd|bash|terminal|ssh|download_file|install_package|modify_permissions|create_api_key|read_secret|write_secret|write_memory|write_rag|write_config|change_config|schedule_task|cron_write|read_email|read_file|web_search|browser|retrieve_rag)\b", re.I)),
    ("tool_phrase", re.compile(r"\b(send\s+(an\s+)?email|forward\s+(this|the)\s+email|run\s+(a\s+)?shell|execute\s+(this|the)?\s*(command|code|script)|open\s+(a\s+)?terminal|call\s+(the\s+)?tool|use\s+(the\s+)?tool)\b", re.I)),
    ("memory_write", re.compile(r"\b(write|save|store|append|insert|persist|remember|index|commit)\b.{0,80}\b(memory|rag|vector|knowledge\s+base|embedding|index|config|system\s+prompt)\b", re.I)),
    ("fanout", re.compile(r"\b(agent[-_ ]?[a-z0-9]+|assistant[-_ ]?[a-z0-9]+|bot[-_ ]?[a-z0-9]+|multiple\s+(contacts|recipients|agents)|fan[- ]?out|broadcast|send\s+to\s+all)\b", re.I)),
    ("secret", re.compile(r"\b(secret|api[_ -]?key|token|credential|password|passwd|private[_ -]?key|\.env)\b", re.I)),
    ("latex_exec", re.compile(r"\\(write18|input|include)\b|shell-escape", re.I)),
]

LIVE_ACTION_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("direct_tool_execution", re.compile(r"\b(run|execute|launch|invoke|call|use)\b.{0,80}\b(bash|cmd|powershell|terminal|shell|send_email|forward_email|delete_email|read_secret|create_api_key|tool)\b", re.I)),
    ("dangerous_send_or_delete", re.compile(r"\b(send|forward|delete|archive|exfiltrate|upload|post)\b.{0,100}\b(secret|api[_ -]?key|token|credential|password|email|message|file|all\s+contacts|recipients)\b", re.I)),
    ("prompt_injection", re.compile(r"\b(ignore\s+(all\s+)?previous|override\s+instructions|system\s+prompt|developer\s+message|jailbreak)\b", re.I)),
    ("latex_shell_escape", re.compile(r"\\write18\b|shell-escape", re.I)),
]

SENSITIVE_REDACTIONS: List[Tuple[re.Pattern[str], str]] = [
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "<EMAIL>"),
    (re.compile(r"https?://\S+"), "<URL>"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"), "<API_KEY>"),
    (re.compile(r"\b[A-Za-z0-9_\-]{32,}\b"), "<LONG_TOKEN>"),
]

LEDGER_FIELDS = [
    "review_key", "review_id", "event_id", "priority", "node_id", "source", "source_path",
    "content_hash", "risk_score", "level", "original_decision", "safe_default", "operator_decision",
    "scope", "operator", "reason", "expires_at", "notes",
]

SUMMARY_FIELDS = [
    "review_key", "review_id", "node_id", "source_path", "effective_decision", "risk_score", "level",
    "matched_labels", "keyword_hits", "live_action_hits", "source_found", "chunk_found", "suggested_operator_decision",
    "suggestion_confidence", "reason",
]


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
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def normalize_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x) for x in value if str(x).strip()]
    if isinstance(value, tuple):
        return [str(x) for x in value if str(x).strip()]
    text = str(value).strip()
    if not text:
        return []
    if ";" in text:
        return [x.strip() for x in text.split(";") if x.strip()]
    if "," in text:
        return [x.strip() for x in text.split(",") if x.strip()]
    return [text]


def selected_decisions(effective: Dict[str, Any], include_decisions: Optional[Sequence[str]] = None) -> List[Dict[str, Any]]:
    wanted = {x.strip().upper() for x in include_decisions} if include_decisions else PENDING_DECISIONS
    rows = []
    for item in effective.get("decisions", []) or []:
        if not isinstance(item, dict):
            continue
        dec = str(item.get("effective_decision") or item.get("decision") or "").strip().upper()
        status = str(item.get("ledger_status") or "").strip().lower()
        if dec in wanted or (status == "pending" and dec not in {"ALLOW", "ALLOW_LOG"}):
            rows.append(item)
    rows.sort(key=lambda r: (-float(r.get("risk_score") or 0.0), str(r.get("node_id") or "")))
    return rows


def chunk_index_from_node(node_id: str) -> Optional[int]:
    m = re.search(r":chunk-(\d+)\b", node_id or "")
    if not m:
        return None
    try:
        return int(m.group(1))
    except Exception:
        return None


def stable_short_hash(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="replace")).hexdigest()[:16]


def split_lines(text: str) -> List[str]:
    return text.replace("\r\n", "\n").replace("\r", "\n").split("\n")


def classify_source_text(text: str, path: str) -> Dict[str, Any]:
    head = text[:5000]
    lower_path = path.lower()
    is_latex = "\\documentclass" in head or "\\begin{document}" in head or lower_path.endswith(".tex")
    is_markdown_doc = lower_path.endswith((".md", ".markdown")) or head.lstrip().startswith("#")
    is_jsonish = head.lstrip().startswith(("{", "["))
    has_code_fence = "```" in head
    return {
        "is_latex_manuscript": is_latex,
        "is_markdown_doc": is_markdown_doc,
        "is_jsonish": is_jsonish,
        "has_code_fence": has_code_fence,
        "looks_static_document": bool(is_latex or is_markdown_doc or re.search(r"\\section\{|#\s+|abstract|references|bibliography", head, re.I)),
    }


def redact_line(line: str, max_len: int = 260) -> str:
    redacted = line.replace("\t", "    ")
    for pattern, repl in SENSITIVE_REDACTIONS:
        redacted = pattern.sub(repl, redacted)
    redacted = redacted.strip()
    if len(redacted) > max_len:
        redacted = redacted[:max_len] + " …"
    return redacted


def find_pattern_hits(text: str, patterns: Sequence[Tuple[str, re.Pattern[str]]]) -> Dict[str, int]:
    hits: Dict[str, int] = {}
    for name, pattern in patterns:
        count = len(list(pattern.finditer(text or "")))
        if count:
            hits[name] = count
    return hits


def local_snippets(text: str, max_snippets: int = 8, context_lines: int = 2) -> List[Dict[str, Any]]:
    lines = split_lines(text)
    snippets: List[Dict[str, Any]] = []
    seen_windows = set()
    for i, line in enumerate(lines):
        matched_names = []
        for name, pattern in KEYWORD_PATTERNS:
            if pattern.search(line):
                matched_names.append(name)
        if not matched_names:
            continue
        start = max(0, i - context_lines)
        end = min(len(lines), i + context_lines + 1)
        key = (start, end)
        if key in seen_windows:
            continue
        seen_windows.add(key)
        rendered = []
        for n in range(start, end):
            prefix = ">>" if n == i else "  "
            rendered.append({"line": n + 1, "text": f"{prefix} {redact_line(lines[n])}"})
        snippets.append({"line": i + 1, "matched": sorted(set(matched_names)), "context": rendered})
        if len(snippets) >= max_snippets:
            break
    return snippets


def read_source_chunk(source_path: str, node_id: str, max_chars_per_event: int = 8000) -> Tuple[str, Dict[str, Any]]:
    info: Dict[str, Any] = {
        "source_path": source_path,
        "source_found": False,
        "read_error": "",
        "chunk_index": chunk_index_from_node(node_id),
        "chunk_found": False,
        "chunk_count": 0,
        "source_sha256_16": "",
    }
    if not source_path:
        info["read_error"] = "missing_source_path"
        return "", info
    path = Path(source_path)
    if not path.exists():
        info["read_error"] = "source_path_not_found"
        return "", info
    info["source_found"] = True
    text, err = safe_read_text(path, max_bytes=20 * 1024 * 1024)
    if err:
        info["read_error"] = err
    info["source_sha256_16"] = stable_short_hash(text)
    chunks = chunk_text(text, max_chars=max_chars_per_event)
    info["chunk_count"] = len(chunks)
    idx = info["chunk_index"]
    if idx is None:
        info["chunk_found"] = True
        return text, info
    if 0 <= idx < len(chunks):
        info["chunk_found"] = True
        return chunks[idx], info
    info["read_error"] = f"chunk_index_out_of_range:{idx}:chunks={len(chunks)}"
    return "", info


def suggest_from_evidence(item: Dict[str, Any], text: str, read_info: Dict[str, Any], keyword_hits: Dict[str, int], live_hits: Dict[str, int], source_class: Dict[str, Any]) -> Tuple[str, str, str]:
    labels = set(normalize_list(item.get("matched_labels")))
    effective = str(item.get("effective_decision") or item.get("decision") or "")
    risk = float(item.get("risk_score") or 0.0)

    if not read_info.get("source_found") or not read_info.get("chunk_found"):
        return "KEEP_ORIGINAL", "low", "source/chunk was not available locally; keep original review requirement"

    # LaTeX manuscripts often mention tools/commands/configs in prose and can trigger
    # false positives. Treat them as static read-only documents unless they contain
    # an explicit shell-escape, prompt-injection, or exfiltration/send/delete pattern.
    if source_class.get("is_latex_manuscript"):
        severe_live = {"latex_shell_escape", "prompt_injection", "dangerous_send_or_delete"}
        if not (set(live_hits) & severe_live):
            return "ALLOW_LOG", "high", "static LaTeX manuscript; no shell-escape/prompt-injection/exfiltration pattern in reviewed chunk"

    if live_hits:
        return "KEEP_ORIGINAL", "high", "local evidence contains live-action/prompt-injection style pattern(s); keep human approval requirement"

    if source_class.get("looks_static_document") and risk < 0.4:
        return "ALLOW_LOG", "medium", "static archived document text; matched wording is not a live agent action"

    # Archived extracted DAT text may contain prior instructions or tool words as history.
    # If it has no strong live-action hit, allow logging rather than approval-blocking.
    if "extracted_dat_text" in str(item.get("source_path") or "").replace("\\", "/").lower() and not live_hits and risk < 0.35:
        return "ALLOW_LOG", "medium", "archived DAT text with no live-action evidence in reviewed chunk; log rather than require approval"

    if keyword_hits and not live_hits and labels <= {"fanout_anomaly", "persistent_write", "dangerous_tool_call", "untrusted_to_dangerous_action"} and risk < 0.35:
        return "ALLOW_LOG", "low", "keyword-only archived text signal; inspect local snippets before applying"

    return "KEEP_ORIGINAL", "medium", "evidence remains ambiguous; keep original review requirement"


def evidence_for_item(item: Dict[str, Any], max_snippets: int = 8, context_lines: int = 2) -> Dict[str, Any]:
    text, read_info = read_source_chunk(str(item.get("source_path") or ""), str(item.get("node_id") or ""))
    keyword_hits = find_pattern_hits(text, KEYWORD_PATTERNS)
    live_hits = find_pattern_hits(text, LIVE_ACTION_PATTERNS)
    source_class = classify_source_text(text, str(item.get("source_path") or ""))
    snippets = local_snippets(text, max_snippets=max_snippets, context_lines=context_lines)
    decision, confidence, reason = suggest_from_evidence(item, text, read_info, keyword_hits, live_hits, source_class)
    return {
        "review_key": item.get("review_key", ""),
        "review_id": item.get("review_id", ""),
        "event_id": item.get("event_id", ""),
        "node_id": item.get("node_id", ""),
        "source": item.get("source", ""),
        "source_path": item.get("source_path", ""),
        "content_hash": item.get("content_hash", ""),
        "risk_score": item.get("risk_score", 0.0),
        "level": item.get("level", ""),
        "original_decision": item.get("original_decision", item.get("decision", "")),
        "effective_decision": item.get("effective_decision", item.get("decision", "")),
        "safe_default": item.get("safe_default", ""),
        "matched_labels": normalize_list(item.get("matched_labels")),
        "read_info": read_info,
        "source_class": source_class,
        "keyword_hits": keyword_hits,
        "live_action_hits": live_hits,
        "snippets": snippets,
        "suggested_operator_decision": decision,
        "suggestion_confidence": confidence,
        "reason": reason,
    }


def ledger_row_from_evidence(row: Dict[str, Any], operator: str) -> Dict[str, Any]:
    decision = row.get("suggested_operator_decision", "KEEP_ORIGINAL")
    return {
        "review_key": row.get("review_key", ""),
        "review_id": row.get("review_id", ""),
        "event_id": row.get("event_id", ""),
        "priority": "",
        "node_id": row.get("node_id", ""),
        "source": row.get("source", ""),
        "source_path": row.get("source_path", ""),
        "content_hash": row.get("content_hash", ""),
        "risk_score": row.get("risk_score", 0.0),
        "level": row.get("level", ""),
        "original_decision": row.get("original_decision", ""),
        "safe_default": row.get("safe_default", ""),
        "operator_decision": decision,
        "scope": "CONTENT_HASH",
        "operator": operator if decision != "KEEP_ORIGINAL" else "",
        "reason": row.get("reason", ""),
        "expires_at": "",
        "notes": f"v2.0 local evidence; confidence={row.get('suggestion_confidence','')}; raw evidence retained locally only",
    }


def summary_row_from_evidence(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "review_key": row.get("review_key", ""),
        "review_id": row.get("review_id", ""),
        "node_id": row.get("node_id", ""),
        "source_path": row.get("source_path", ""),
        "effective_decision": row.get("effective_decision", ""),
        "risk_score": row.get("risk_score", 0.0),
        "level": row.get("level", ""),
        "matched_labels": ";".join(row.get("matched_labels", [])),
        "keyword_hits": json.dumps(row.get("keyword_hits", {}), sort_keys=True),
        "live_action_hits": json.dumps(row.get("live_action_hits", {}), sort_keys=True),
        "source_found": row.get("read_info", {}).get("source_found", False),
        "chunk_found": row.get("read_info", {}).get("chunk_found", False),
        "suggested_operator_decision": row.get("suggested_operator_decision", ""),
        "suggestion_confidence": row.get("suggestion_confidence", ""),
        "reason": row.get("reason", ""),
    }


def write_local_evidence_md(path: Path, report: Dict[str, Any]) -> None:
    lines: List[str] = [
        "# PooleShield Local Review Evidence",
        "",
        f"Version: {report.get('version')}",
        f"Generated: {report.get('generated_at')}",
        "",
        "This file is content-bearing. It may contain redacted snippets from local extracted chat/DAT text.",
        "Do not upload it unless you intentionally want to share reviewed local context.",
        "",
        "## Summary",
        "",
        f"Reviewed items: `{report.get('summary', {}).get('reviewed_items')}`",
        f"Suggested decisions: `{report.get('summary', {}).get('by_suggested_operator_decision')}`",
        f"Live-action pattern items: `{report.get('summary', {}).get('items_with_live_action_hits')}`",
        f"Missing source/chunk items: `{report.get('summary', {}).get('items_missing_source_or_chunk')}`",
        "",
    ]
    for item in report.get("items", []):
        lines += [
            f"## {item.get('suggested_operator_decision')} risk={item.get('risk_score')} — {item.get('node_id')}",
            f"Review key: `{item.get('review_key')}`",
            f"Source path: `{item.get('source_path')}`",
            f"Matched labels: `{';'.join(item.get('matched_labels', []))}`",
            f"Keyword hits: `{item.get('keyword_hits')}`",
            f"Live-action hits: `{item.get('live_action_hits')}`",
            f"Source class: `{item.get('source_class')}`",
            f"Reason: {item.get('reason')}",
            "",
            "### Redacted matched context",
            "",
        ]
        snippets = item.get("snippets") or []
        if not snippets:
            lines.append("No matched context snippet found in the reviewed chunk.")
            lines.append("")
            continue
        for snip in snippets:
            lines.append(f"Matched near local chunk line `{snip.get('line')}`: `{';'.join(snip.get('matched', []))}`")
            lines.append("```text")
            for ctx in snip.get("context", []):
                lines.append(f"{ctx.get('line')}: {ctx.get('text')}")
            lines.append("```")
            lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def write_summary_md(path: Path, report: Dict[str, Any]) -> None:
    lines = [
        "# PooleShield Review Evidence Summary",
        "",
        f"Version: {report.get('version')}",
        f"Generated: {report.get('generated_at')}",
        f"Effective decisions: `{report.get('effective_path')}`",
        "",
        "## Summary",
        "",
        f"Reviewed items: `{report.get('summary', {}).get('reviewed_items')}`",
        f"Suggested decisions: `{report.get('summary', {}).get('by_suggested_operator_decision')}`",
        f"Suggestion confidence: `{report.get('summary', {}).get('by_suggestion_confidence')}`",
        f"Items with live-action hits: `{report.get('summary', {}).get('items_with_live_action_hits')}`",
        f"Missing source/chunk items: `{report.get('summary', {}).get('items_missing_source_or_chunk')}`",
        "",
        "## Outputs",
        "",
        "- `review_evidence_summary.csv`: safe metadata summary",
        "- `review_evidence_suggested_ledger.csv`: suggested review ledger; inspect before applying",
        "- `review_evidence_local.md`: local redacted evidence; excluded from privacy bundles",
        "- `review_evidence_report.json`: full local evidence JSON; excluded from privacy bundles",
        "",
        "## Next step",
        "",
        "Open `review_evidence_local.md` locally and inspect the redacted snippets. Apply `review_evidence_suggested_ledger.csv` only if the suggestions match what you see.",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def build_review_evidence(
    output_dir: str,
    effective_path: Optional[str] = None,
    include_decision: Optional[Sequence[str]] = None,
    operator: str = "local_review",
    max_items: int = 200,
    max_snippets: int = 8,
    context_lines: int = 2,
    bundle_output: bool = False,
    bundle_path: Optional[str] = None,
    privacy_bundle: bool = True,
) -> Dict[str, Any]:
    out = Path(output_dir)
    effective_file = Path(effective_path) if effective_path else out / "effective_policy_decisions.json"
    if not effective_file.exists():
        raise FileNotFoundError(f"Effective decisions not found: {effective_file}")
    effective = load_json(effective_file)
    selected = selected_decisions(effective, include_decisions=include_decision)[:max_items]

    evidence_rows = [evidence_for_item(item, max_snippets=max_snippets, context_lines=context_lines) for item in selected]
    ledger_rows = [ledger_row_from_evidence(row, operator=operator) for row in evidence_rows]
    summary_rows = [summary_row_from_evidence(row) for row in evidence_rows]

    suggestion_counts = Counter(row.get("suggested_operator_decision") for row in evidence_rows)
    confidence_counts = Counter(row.get("suggestion_confidence") for row in evidence_rows)
    live_count = sum(1 for row in evidence_rows if row.get("live_action_hits"))
    missing_count = sum(1 for row in evidence_rows if not row.get("read_info", {}).get("source_found") or not row.get("read_info", {}).get("chunk_found"))
    summary = {
        "reviewed_items": len(evidence_rows),
        "by_suggested_operator_decision": dict(sorted(suggestion_counts.items())),
        "by_suggestion_confidence": dict(sorted(confidence_counts.items())),
        "items_with_live_action_hits": live_count,
        "items_missing_source_or_chunk": missing_count,
        "selected_effective_decisions": sorted({str(row.get("effective_decision") or "") for row in evidence_rows}),
    }
    report = {
        "tool": "PooleShield local review evidence",
        "version": VERSION,
        "generated_at": utc_now(),
        "output_dir": str(out),
        "effective_path": str(effective_file),
        "privacy_note": "review_evidence_local.md and review_evidence_report.json are content-bearing and excluded from privacy bundles by result_bundler.",
        "summary": summary,
        "items": evidence_rows,
    }

    report_json = out / "review_evidence_report.json"
    summary_csv = out / "review_evidence_summary.csv"
    suggested_ledger = out / "review_evidence_suggested_ledger.csv"
    summary_md = out / "RUN_SUMMARY_EVIDENCE.md"
    summary_json = out / "RUN_SUMMARY_EVIDENCE.json"
    local_md = out / "review_evidence_local.md"

    write_json(report_json, report)
    write_csv(summary_csv, summary_rows, SUMMARY_FIELDS)
    write_csv(suggested_ledger, ledger_rows, LEDGER_FIELDS)
    write_local_evidence_md(local_md, report)
    run_summary = {
        "tool": "PooleShield operator",
        "version": VERSION,
        "mode": "review-evidence",
        "output_dir": str(out),
        "effective_path": str(effective_file),
        "summary": summary,
        "review_evidence_report": str(report_json),
        "review_evidence_summary_csv": str(summary_csv),
        "review_evidence_suggested_ledger": str(suggested_ledger),
        "review_evidence_local_md": str(local_md),
        "result_bundle": str(out / "pooleshield_results_bundle.zip") if bundle_output else "",
        "bundle_summary": None,
    }
    write_json(summary_json, run_summary)
    write_summary_md(summary_md, report)
    if bundle_output:
        bundle_report = bundle_output_dir(str(out), bundle_path, privacy_mode=privacy_bundle)
        run_summary["bundle_summary"] = {
            "bundle_path": bundle_report.get("bundle_path"),
            "bundle_size_bytes": bundle_report.get("bundle_size_bytes"),
            "file_count": bundle_report.get("file_count"),
            "manifest_name": bundle_report.get("manifest_name"),
            "privacy_mode": bundle_report.get("privacy_mode"),
            "excluded_content_files": bundle_report.get("excluded_content_files"),
        }
        run_summary["result_bundle"] = run_summary["bundle_summary"].get("bundle_path")
        write_json(summary_json, run_summary)
    return run_summary


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Build local redacted evidence for pending PooleShield review items")
    parser.add_argument("--output-dir", default="out/dat_chat_scan")
    parser.add_argument("--effective", default=None)
    parser.add_argument("--include-decision", action="append", default=None, help="Effective decision to inspect; repeatable. Default: REQUIRE_APPROVAL/BLOCK/QUARANTINE")
    parser.add_argument("--operator", default="local_review")
    parser.add_argument("--max-items", type=int, default=200)
    parser.add_argument("--max-snippets", type=int, default=8)
    parser.add_argument("--context-lines", type=int, default=2)
    parser.add_argument("--bundle-output", action="store_true")
    parser.add_argument("--bundle-path", default=None)
    parser.add_argument("--privacy-bundle", action="store_true", default=True)
    args = parser.parse_args()
    result = build_review_evidence(
        output_dir=args.output_dir,
        effective_path=args.effective,
        include_decision=args.include_decision,
        operator=args.operator,
        max_items=args.max_items,
        max_snippets=args.max_snippets,
        context_lines=args.context_lines,
        bundle_output=args.bundle_output,
        bundle_path=args.bundle_path,
        privacy_bundle=args.privacy_bundle,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
