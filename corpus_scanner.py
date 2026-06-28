#!/usr/bin/env python3
"""
PooleShield v1.8 corpus scanner.

Defensive purpose:
  Safely scan exported AI-agent logs, RAG/document folders, text notes, and
  JSON/JSONL/CSV traces for PooleShield local-defect risk signals.

Safety boundary:
  This scanner does not execute files, follow links, call APIs, or modify the
  scanned corpus. It only reads text-like files and writes reports.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from adapter_tool_logs import load_records, normalize_record, write_jsonl, MEMORY_WRITE_RE, CONFIG_WRITE_RE
from adapter_chat_export import normalize_chat_file as normalize_chat_export_file, messages_from_transcript_text
from pooleshield import Event, PooleShieldDetector, ScoreBreakdown, stable_hash, summarize, write_csv_report

VERSION = "2.0"

TEXT_EXTENSIONS = {
    ".txt", ".md", ".markdown", ".log", ".jsonl", ".json", ".csv", ".html", ".htm",
    ".xml", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".eml", ".msg",
}
STRUCTURED_EXTENSIONS = {".jsonl", ".json", ".csv"}
DEFAULT_SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "node_modules", ".mypy_cache",
    ".pytest_cache", "dist", "build",
}
TOOL_HINT_RE = re.compile(
    r"\b(send_email|forward_email|send_message|post_message|delete_email|delete_file|archive_email|"
    r"execute_code|run_shell|powershell|cmd|bash|terminal|ssh|download_file|install_package|"
    r"modify_permissions|create_api_key|read_secret|write_secret|write_memory|write_rag|write_config|"
    r"change_config|schedule_task|cron_write|read_email|read_file|web_search|browser|retrieve_rag)\b",
    re.I,
)
AGENT_MENTION_RE = re.compile(r"\b(agent[-_ ]?[a-z0-9]+|assistant[-_ ]?[a-z0-9]+|bot[-_ ]?[a-z0-9]+)\b", re.I)
SENSITIVE_HINT_RE = re.compile(r"\b(secret|api[_ -]?key|token|credential|password|passwd|private[_ -]?key|\.env)\b", re.I)
RAG_PATH_RE = re.compile(r"\b(rag|retrieval|vector|embedding|knowledge|kb|docs?|chunks?)\b", re.I)
EMAIL_PATH_RE = re.compile(r"\b(email|gmail|mail|inbox|eml|mbox)\b", re.I)
WEB_PATH_RE = re.compile(r"\b(web|browser|crawl|scrape|html|htm|url)\b", re.I)
TOOL_PATH_RE = re.compile(r"\b(tool|tools|agent|trace|run|workflow|function|action|operation|log)\b", re.I)
CHAT_PATH_RE = re.compile(r"(chat|conversation|transcript|messages?|chatgpt|codex|claude|assistant[_-]?export)", re.I)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def is_probably_text(path: Path, sample_size: int = 4096) -> bool:
    if path.suffix.lower() in TEXT_EXTENSIONS:
        return True
    try:
        data = path.read_bytes()[:sample_size]
    except Exception:
        return False
    if b"\x00" in data:
        return False
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def iter_files(paths: Sequence[str], recursive: bool = True, include_hidden: bool = False) -> Iterator[Path]:
    for raw in paths:
        root = Path(raw).expanduser().resolve()
        if not root.exists():
            raise FileNotFoundError(f"Input path not found: {root}")
        if root.is_file():
            yield root
            continue
        if not root.is_dir():
            continue
        walker = root.rglob("*") if recursive else root.glob("*")
        for p in walker:
            if not p.is_file():
                continue
            parts = set(p.parts)
            if not include_hidden:
                if any(part.startswith(".") for part in p.parts if part not in {str(p.anchor), ""}):
                    continue
            if parts & DEFAULT_SKIP_DIRS:
                continue
            yield p


def inspect_input_paths(paths: Sequence[str], recursive: bool = True, include_hidden: bool = False) -> Dict[str, Any]:
    """Return non-invasive diagnostics about what a scan path contains.

    This helps operators distinguish a true clean scan from an empty folder,
    unsupported binary-only folder, hidden/skipped directory issue, or typo.
    """
    diagnostics: Dict[str, Any] = {
        "input_paths": [],
        "total_visible_files": 0,
        "supported_extension_files": 0,
        "text_like_files": 0,
        "unsupported_extension_files": 0,
        "sample_visible_files": [],
        "supported_extensions": sorted(TEXT_EXTENSIONS),
        "notes": [],
    }
    sample_limit = 20
    for raw in paths:
        entry: Dict[str, Any] = {"path": raw, "exists": False, "kind": "missing", "visible_files": 0, "supported_extension_files": 0, "text_like_files": 0}
        root = Path(raw).expanduser().resolve()
        entry["resolved_path"] = str(root)
        if not root.exists():
            diagnostics["notes"].append(f"missing_path:{root}")
            diagnostics["input_paths"].append(entry)
            continue
        entry["exists"] = True
        entry["kind"] = "file" if root.is_file() else "directory" if root.is_dir() else "other"
        try:
            files = list(iter_files([str(root)], recursive=recursive, include_hidden=include_hidden)) if root.is_dir() else [root]
        except Exception as exc:
            entry["error"] = str(exc)
            diagnostics["notes"].append(f"inspect_error:{root}:{exc}")
            diagnostics["input_paths"].append(entry)
            continue
        entry["visible_files"] = len(files)
        diagnostics["total_visible_files"] += len(files)
        for f in files:
            suffix = f.suffix.lower()
            supported_ext = suffix in TEXT_EXTENSIONS
            if supported_ext:
                entry["supported_extension_files"] += 1
                diagnostics["supported_extension_files"] += 1
            else:
                diagnostics["unsupported_extension_files"] += 1
            text_like = is_probably_text(f)
            if text_like:
                entry["text_like_files"] += 1
                diagnostics["text_like_files"] += 1
            if len(diagnostics["sample_visible_files"]) < sample_limit:
                diagnostics["sample_visible_files"].append({
                    "path": str(f),
                    "suffix": suffix,
                    "supported_extension": supported_ext,
                    "text_like": text_like,
                })
        diagnostics["input_paths"].append(entry)
    if diagnostics["total_visible_files"] == 0:
        diagnostics["notes"].append("no_visible_files_found; add .txt/.md/.jsonl/.json/.csv/.log files or choose a different folder")
    elif diagnostics["text_like_files"] == 0:
        diagnostics["notes"].append("visible_files_found_but_none_text_like; scan a text/log/export folder, not binaries/media only")
    return diagnostics


def safe_read_text(path: Path, max_bytes: int) -> Tuple[str, Optional[str]]:
    try:
        data = path.read_bytes()[:max_bytes]
    except Exception as exc:
        return "", f"read_error:{exc}"
    for enc in ("utf-8", "utf-8-sig", "cp1252", "latin-1"):
        try:
            return data.decode(enc, errors="strict"), None
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace"), "decode_replacement_used"


def infer_source_from_path(path: Path, content: str = "") -> str:
    blob = f"{path.as_posix()}\n{content[:1000]}"
    if EMAIL_PATH_RE.search(blob):
        return "email"
    if WEB_PATH_RE.search(blob):
        return "web"
    if RAG_PATH_RE.search(blob):
        return "rag"
    if TOOL_PATH_RE.search(blob):
        return "tool"
    return "file"


def infer_tools_from_text(content: str) -> List[str]:
    found = []
    seen = set()
    for match in TOOL_HINT_RE.finditer(content or ""):
        name = match.group(1).lower()
        if name not in seen:
            seen.add(name)
            found.append(name)
    phrase_aliases = [
        (r"\bsend\s+(an\s+)?email\b", "send_email"),
        (r"\bforward\s+(this|the)\s+email\b", "forward_email"),
        (r"\bwrite\s+(this|it)\s+to\s+memory\b", "write_memory"),
        (r"\bwrite\s+(this|it)\s+to\s+(rag|knowledge\s+base|vector\s+store)\b", "write_rag"),
        (r"\bread\s+(the\s+)?secret\b", "read_secret"),
        (r"\brun\s+(a\s+)?shell\b", "run_shell"),
    ]
    for pattern, alias in phrase_aliases:
        if re.search(pattern, content or "", re.I) and alias not in seen:
            seen.add(alias)
            found.append(alias)
    return found


def infer_neighbors_from_text(content: str, max_neighbors: int = 12) -> List[str]:
    out: List[str] = []
    seen = set()
    for match in AGENT_MENTION_RE.finditer(content or ""):
        n = re.sub(r"\s+", "-", match.group(1).lower())
        if n not in seen:
            seen.add(n)
            out.append(n)
        if len(out) >= max_neighbors:
            break
    return out


def chunk_text(text: str, max_chars: int) -> List[str]:
    text = text or ""
    if len(text) <= max_chars:
        return [text]
    chunks: List[str] = []
    start = 0
    while start < len(text):
        end = min(len(text), start + max_chars)
        boundary = text.rfind("\n", start, end)
        if boundary > start + int(max_chars * 0.55):
            end = boundary
        chunks.append(text[start:end])
        start = end
    return chunks


def event_id_for(event: Event) -> str:
    return stable_hash(f"{event.timestamp}|{event.node_id}|{event.source}|{event.content_hash}", 18)


def normalize_structured_file(path: Path, base_time: dt.datetime, default_trust: str, max_records: int) -> List[Dict[str, Any]]:
    # v1.8: if the file is clearly a chat/conversation export, preserve message
    # turns using the chat adapter instead of flattening through generic tool-log
    # records. Generic agent/tool JSONL files still use adapter_tool_logs.
    if CHAT_PATH_RE.search(path.as_posix()):
        chat_events = normalize_chat_export_file(path, base_time=base_time, default_trust=default_trust, max_records=max_records)
        if chat_events:
            return chat_events

    records = load_records(str(path))
    normalized: List[Dict[str, Any]] = []
    for i, raw in enumerate(records[:max_records]):
        event = normalize_record(raw, i)
        event.setdefault("timestamp", (base_time + dt.timedelta(seconds=i)).isoformat().replace("+00:00", "Z"))
        event["notes"] = (event.get("notes", "") + f" source_path={path.as_posix()} record_index={i}").strip()
        if not event.get("trust") or str(event.get("trust")).lower() == "unknown":
            event["trust"] = default_trust
        normalized.append(event)
    return normalized


def normalize_text_file(path: Path, text: str, base_time: dt.datetime, default_trust: str, max_chars: int) -> List[Dict[str, Any]]:
    # v1.8: detect speaker-labeled transcripts such as:
    # User: ...
    # Assistant: ...
    transcript_rows = messages_from_transcript_text(text)
    if len(transcript_rows) >= 2:
        chat_events = normalize_chat_export_file(path, base_time=base_time, default_trust=default_trust, max_records=1000)
        if chat_events:
            return chat_events

    source = infer_source_from_path(path, text)
    chunks = chunk_text(text, max_chars=max_chars)
    normalized: List[Dict[str, Any]] = []
    for i, chunk in enumerate(chunks):
        tool_calls = infer_tools_from_text(chunk)
        outbound = infer_neighbors_from_text(chunk)
        note = f"source_path={path.as_posix()} chunk_index={i} chunks_total={len(chunks)}"
        normalized.append({
            "timestamp": (base_time + dt.timedelta(seconds=i)).isoformat().replace("+00:00", "Z"),
            "node_id": f"file:{path.name}" if len(chunks) == 1 else f"file:{path.name}:chunk-{i}",
            "source": source,
            "trust": default_trust,
            "content": chunk,
            "inbound_from": [f"folder:{path.parent.name or 'root'}"],
            "outbound_to": outbound,
            "tool_calls": tool_calls,
            "writes_memory": bool(re.search(r"\b(memory|remember|saved memory)\b", chunk, re.I) and MEMORY_WRITE_RE.search(chunk)),
            "writes_rag": bool(re.search(r"\b(rag|vector|knowledge|embedding|index)\b", chunk, re.I) and MEMORY_WRITE_RE.search(chunk)),
            "writes_config": bool(CONFIG_WRITE_RE.search(chunk)),
            "sensitive_access": bool(SENSITIVE_HINT_RE.search(chunk)),
            "notes": note,
        })
    return normalized


def normalize_scan_paths(
    paths: Sequence[str],
    normalized_path: Optional[str] = None,
    default_trust: str = "untrusted",
    recursive: bool = True,
    include_hidden: bool = False,
    max_bytes: int = 1_000_000,
    max_chars_per_event: int = 8000,
    max_records_per_file: int = 500,
) -> Tuple[List[Dict[str, Any]], Dict[str, str], List[Dict[str, Any]]]:
    normalized: List[Dict[str, Any]] = []
    path_by_event_id: Dict[str, str] = {}
    skipped: List[Dict[str, Any]] = []
    base_time = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    event_clock = 0

    for path in iter_files(paths, recursive=recursive, include_hidden=include_hidden):
        rel_path = path.as_posix()
        try:
            size = path.stat().st_size
        except Exception:
            size = -1
        if size > max_bytes and path.suffix.lower() not in STRUCTURED_EXTENSIONS:
            skipped.append({"path": rel_path, "reason": f"larger_than_max_bytes:{size}"})
            continue
        if not is_probably_text(path):
            skipped.append({"path": rel_path, "reason": "not_text_like"})
            continue
        file_base_time = base_time + dt.timedelta(minutes=event_clock)
        event_clock += 1
        try:
            if path.suffix.lower() in STRUCTURED_EXTENSIONS:
                events = normalize_structured_file(path, file_base_time, default_trust, max_records_per_file)
            else:
                text, warning = safe_read_text(path, max_bytes=max_bytes)
                if warning:
                    skipped.append({"path": rel_path, "reason": warning})
                events = normalize_text_file(path, text, file_base_time, default_trust, max_chars=max_chars_per_event)
        except Exception as exc:
            skipped.append({"path": rel_path, "reason": f"normalization_error:{exc}"})
            continue
        for event in events:
            e = Event.from_dict(event)
            eid = event_id_for(e)
            path_by_event_id[eid] = rel_path
            normalized.append(event)
    if normalized_path:
        write_jsonl(normalized_path, normalized)
    return normalized, path_by_event_id, skipped


def write_json_report(
    path: str,
    results: Sequence[ScoreBreakdown],
    scan_meta: Dict[str, Any],
    path_by_event_id: Optional[Dict[str, str]] = None,
) -> None:
    """Write a scanner report and preserve source_path when available.

    Cycle 7 change: policy decisions and approval queues are much more useful
    when every event carries its originating file/log path, not just quarantine
    manifest entries.
    """
    path_by_event_id = path_by_event_id or {}
    events = []
    for r in results:
        row = asdict(r)
        row["source_path"] = path_by_event_id.get(r.event_id, "")
        events.append(row)
    report = {
        "tool": "PooleShield corpus scanner",
        "version": VERSION,
        "generated_at": utc_now(),
        "scan": scan_meta,
        "summary": summarize(results),
        "events": events,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


def build_quarantine_manifest(
    results: Sequence[ScoreBreakdown],
    path_by_event_id: Dict[str, str],
    threshold: float = 0.25,
) -> Dict[str, Any]:
    entries = []
    for r in sorted(results, key=lambda x: x.risk_score, reverse=True):
        if r.risk_score < threshold and r.level == "NORMAL":
            continue
        entries.append({
            "event_id": r.event_id,
            "source_path": path_by_event_id.get(r.event_id, "unknown"),
            "node_id": r.node_id,
            "source": r.source,
            "risk_score": r.risk_score,
            "level": r.level,
            "labels": r.matched_labels,
            "recommended_actions": r.recommended_actions,
        })
    by_level: Dict[str, int] = {}
    for e in entries:
        by_level[e["level"]] = by_level.get(e["level"], 0) + 1
    return {
        "tool": "PooleShield quarantine manifest",
        "version": VERSION,
        "generated_at": utc_now(),
        "threshold": threshold,
        "total_manifest_entries": len(entries),
        "by_level": dict(sorted(by_level.items())),
        "entries": entries,
    }


def write_manifest_json(path: str, manifest: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)


def write_manifest_md(path: str, manifest: Dict[str, Any]) -> None:
    lines = [
        "# PooleShield Quarantine Manifest",
        "",
        f"Version: {manifest.get('version')}",
        f"Generated: {manifest.get('generated_at')}",
        f"Threshold: {manifest.get('threshold')}",
        f"Entries: {manifest.get('total_manifest_entries')}",
        "",
    ]
    for e in manifest.get("entries", []):
        lines.append(f"## {e['level']} risk={e['risk_score']} — {e['source_path']}")
        lines.append(f"Node: `{e['node_id']}`  Source: `{e['source']}`  Event: `{e['event_id']}`")
        lines.append(f"Labels: {', '.join(e.get('labels', [])) or 'none'}")
        lines.append(f"Recommended actions: {', '.join(e.get('recommended_actions', [])) or 'none'}")
        lines.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def scan_and_report(
    paths: Sequence[str],
    normalized_path: str,
    output_path: str,
    csv_path: str,
    manifest_path: str,
    manifest_md_path: Optional[str] = None,
    threshold: float = 0.25,
    default_trust: str = "untrusted",
    recursive: bool = True,
    include_hidden: bool = False,
    max_bytes: int = 1_000_000,
    max_chars_per_event: int = 8000,
    max_records_per_file: int = 500,
) -> Dict[str, Any]:
    input_diagnostics = inspect_input_paths(paths, recursive=recursive, include_hidden=include_hidden)
    normalized, path_by_event_id, skipped = normalize_scan_paths(
        paths=paths,
        normalized_path=normalized_path,
        default_trust=default_trust,
        recursive=recursive,
        include_hidden=include_hidden,
        max_bytes=max_bytes,
        max_chars_per_event=max_chars_per_event,
        max_records_per_file=max_records_per_file,
    )
    events = [Event.from_dict(e) for e in normalized]
    detector = PooleShieldDetector()
    results = detector.analyze(events)
    scan_meta = {
        "input_paths": list(paths),
        "normalized_path": normalized_path,
        "event_count": len(normalized),
        "skipped_count": len(skipped),
        "skipped": skipped[:100],
        "default_trust": default_trust,
        "threshold": threshold,
        "recursive": recursive,
        "input_diagnostics": input_diagnostics,
        "empty_scan_warning": "No events were normalized from the selected path(s). Add supported text/log/export files or run `doctor --write-sample-files` on a test folder." if len(normalized) == 0 else "",
    }
    write_json_report(output_path, results, scan_meta, path_by_event_id=path_by_event_id)
    write_csv_report(csv_path, results)
    manifest = build_quarantine_manifest(results, path_by_event_id, threshold=threshold)
    write_manifest_json(manifest_path, manifest)
    if manifest_md_path:
        write_manifest_md(manifest_md_path, manifest)
    return {
        "scan": scan_meta,
        "summary": summarize(results),
        "manifest_summary": {
            "total_manifest_entries": manifest["total_manifest_entries"],
            "by_level": manifest["by_level"],
        },
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="PooleShield v1.8 safe corpus scanner")
    parser.add_argument("--path", "-p", nargs="+", required=True, help="File/folder path(s) to scan")
    parser.add_argument("--normalized", default="cycle4_normalized_events.jsonl", help="Write normalized events here")
    parser.add_argument("--output", "-o", default="cycle4_scan_report.json", help="JSON scan report")
    parser.add_argument("--csv", default="cycle4_scan_report.csv", help="CSV scan report")
    parser.add_argument("--manifest", default="cycle4_quarantine_manifest.json", help="JSON quarantine manifest")
    parser.add_argument("--manifest-md", default="cycle4_quarantine_manifest.md", help="Markdown quarantine manifest")
    parser.add_argument("--threshold", type=float, default=0.25, help="Manifest/alert threshold")
    parser.add_argument("--trust", default="untrusted", choices=["trusted", "untrusted", "unknown"], help="Default trust for scanned text")
    parser.add_argument("--no-recursive", action="store_true", help="Only scan top-level files")
    parser.add_argument("--include-hidden", action="store_true", help="Include hidden files/folders")
    parser.add_argument("--max-bytes", type=int, default=1_000_000, help="Max bytes read per text file")
    parser.add_argument("--max-chars-per-event", type=int, default=8000, help="Chunk long text files at this size")
    parser.add_argument("--max-records-per-file", type=int, default=500, help="Max structured records normalized per file")
    args = parser.parse_args(argv)

    summary = scan_and_report(
        paths=args.path,
        normalized_path=args.normalized,
        output_path=args.output,
        csv_path=args.csv,
        manifest_path=args.manifest,
        manifest_md_path=args.manifest_md,
        threshold=args.threshold,
        default_trust=args.trust,
        recursive=not args.no_recursive,
        include_hidden=args.include_hidden,
        max_bytes=args.max_bytes,
        max_chars_per_event=args.max_chars_per_event,
        max_records_per_file=args.max_records_per_file,
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"\nWrote: {args.normalized}")
    print(f"Wrote: {args.output}")
    print(f"Wrote: {args.csv}")
    print(f"Wrote: {args.manifest}")
    if args.manifest_md:
        print(f"Wrote: {args.manifest_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
