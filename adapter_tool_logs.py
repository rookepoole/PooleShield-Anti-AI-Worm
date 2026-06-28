#!/usr/bin/env python3
"""
PooleShield v1.8 adapter: normalize common AI-agent/tool-call traces into
PooleShield's defensive JSONL event schema.

This adapter is intentionally defensive. It does not execute tools, follow links,
connect to services, or reproduce malicious behavior. It only maps logs into a
standard analysis format for pooleshield.py.

Supported input shapes:
  - JSONL: one JSON object per line
  - JSON: a list of objects, or an object with events/items/records/traces/logs
  - CSV: one event per row

Usage:
  python adapter_tool_logs.py --input examples/agent_tool_trace.jsonl --output normalized_agent_events.jsonl
  python pooleshield.py --input normalized_agent_events.jsonl --output report.json --csv report.csv
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

VERSION = "1.8.0"

TIME_FIELDS = [
    "timestamp", "created_at", "time", "datetime", "event_time", "created", "ts"
]
NODE_FIELDS = [
    "node_id", "agent_id", "agent", "actor", "assistant_id", "session_id", "run_id",
    "thread_id", "process_id", "account_id", "user_id"
]
SOURCE_FIELDS = ["source", "source_type", "channel", "event_source", "modality"]
TRUST_FIELDS = ["trust", "trust_level", "origin_trust"]
CONTENT_FIELDS = [
    "content", "text", "message", "prompt", "input", "output", "response", "arguments",
    "args", "params", "parameters", "query", "document", "chunk", "body", "subject",
]
TOOL_FIELDS = [
    "tool_calls", "tools", "actions", "tool", "tool_name", "function", "function_name",
    "name", "operation", "method"
]
INBOUND_FIELDS = ["inbound_from", "from", "sender", "source_node", "parent", "previous_agent", "caller"]
OUTBOUND_FIELDS = ["outbound_to", "to", "recipient", "recipients", "targets", "target", "next_agents"]

SENSITIVE_RE = re.compile(r"\b(secret|api[_ -]?key|token|credential|password|passwd|private[_ -]?key|\.env)\b", re.I)
MEMORY_WRITE_RE = re.compile(r"\b(write|save|store|upsert|insert|add|update|persist).*\b(memory|rag|vector|embedding|knowledge|kb|index)\b|\b(memory|rag|vectorstore|knowledge_base)\.(add|write|upsert|insert|update)\b", re.I)
CONFIG_WRITE_RE = re.compile(r"\b(write|modify|update|change|set).*\b(config|policy|permission|startup|cron|schedule)\b", re.I)

SOURCE_HINTS = {
    "email": ["email", "gmail", "mail", "inbox"],
    "web": ["web", "browser", "url", "http", "crawl", "scrape"],
    "rag": ["rag", "retrieval", "vector", "embedding", "knowledge", "chunk"],
    "tool": ["tool", "function", "action", "operation"],
    "file": ["file", "drive", "document", "pdf"],
    "api": ["api", "http_request", "request"],
    "chat": ["chat", "message", "slack", "teams", "discord"],
}

UNTRUSTED_SOURCE_HINTS = ["email", "web", "internet", "browser", "external", "url", "http", "chat", "rag"]


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return list(value)
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return []
        # Split common list-ish cells, but keep natural sentences intact.
        if ";" in s:
            return [x.strip() for x in s.split(";") if x.strip()]
        if "," in s and len(s) < 250:
            return [x.strip() for x in s.split(",") if x.strip()]
        return [s]
    return [value]


def get_path(obj: Any, path: str) -> Any:
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def first_present(raw: Dict[str, Any], fields: Sequence[str]) -> Any:
    for f in fields:
        v = get_path(raw, f)
        if v not in (None, "", [], {}):
            return v
    return None


def flatten_text(value: Any, max_chars: int = 6000, _depth: int = 0) -> str:
    """Extract text from nested values without exploding giant logs."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value[:max_chars]
    if isinstance(value, (int, float, bool)):
        return str(value)
    if _depth > 4:
        try:
            return json.dumps(value, ensure_ascii=False)[:max_chars]
        except Exception:
            return str(value)[:max_chars]
    parts: List[str] = []
    if isinstance(value, list):
        for item in value[:30]:
            t = flatten_text(item, max_chars=max_chars, _depth=_depth + 1)
            if t:
                parts.append(t)
    elif isinstance(value, dict):
        # Prefer human-content fields first, then include compact key context.
        for key in CONTENT_FIELDS + ["role", "type", "event_type", "tool_name", "name"]:
            if key in value:
                t = flatten_text(value[key], max_chars=max_chars, _depth=_depth + 1)
                if t:
                    parts.append(f"{key}: {t}")
        if not parts:
            try:
                parts.append(json.dumps(value, ensure_ascii=False)[:max_chars])
            except Exception:
                parts.append(str(value)[:max_chars])
    else:
        parts.append(str(value))
    joined = "\n".join(parts)
    return joined[:max_chars]


def collect_content(raw: Dict[str, Any]) -> str:
    parts: List[str] = []
    for field in CONTENT_FIELDS:
        v = get_path(raw, field)
        if v not in (None, "", [], {}):
            txt = flatten_text(v)
            if txt:
                parts.append(txt)
    # Common nested message formats.
    for field in ["messages", "chat_messages", "events", "trace", "metadata", "data"]:
        v = get_path(raw, field)
        if v not in (None, "", [], {}):
            txt = flatten_text(v)
            if txt:
                parts.append(txt)
    if not parts:
        parts.append(flatten_text(raw))
    # Deduplicate exact chunks while preserving order.
    seen = set()
    clean: List[str] = []
    for p in parts:
        key = p.strip()
        if key and key not in seen:
            seen.add(key)
            clean.append(key)
    return "\n".join(clean)[:8000]


def tool_name_from_value(value: Any) -> List[str]:
    names: List[str] = []
    if value is None:
        return names
    if isinstance(value, str):
        if value.strip():
            names.extend(as_list(value))
        return names
    if isinstance(value, list):
        for item in value:
            names.extend(tool_name_from_value(item))
        return names
    if isinstance(value, dict):
        candidates = [
            value.get("name"), value.get("tool_name"), value.get("function_name"),
            get_path(value, "function.name"), value.get("type"), value.get("operation"),
            value.get("method"), value.get("action"), value.get("tool"),
        ]
        for c in candidates:
            if isinstance(c, str) and c.strip():
                names.append(c.strip())
        return names
    return names


def normalize_tool_name(name: str) -> str:
    n = str(name).strip().lower()
    n = re.sub(r"[^a-z0-9_.-]+", "_", n)
    n = re.sub(r"_+", "_", n).strip("_")
    # Map common descriptive names into PooleShield core tool buckets.
    alias = {
        "send": "send_message", "email_send": "send_email", "gmail_send": "send_email",
        "forward": "forward_email", "run": "execute_code", "shell": "run_shell",
        "terminal": "run_shell", "read_secret": "read_secret", "secret_read": "read_secret",
        "memory_write": "write_memory", "rag_write": "write_rag", "vectorstore_upsert": "write_rag",
        "config_write": "write_config", "permission_update": "modify_permissions",
        "file_delete": "delete_file", "email_delete": "delete_email",
    }
    return alias.get(n, n)


def collect_tools(raw: Dict[str, Any]) -> List[str]:
    names: List[str] = []
    for field in TOOL_FIELDS:
        v = get_path(raw, field)
        if v not in (None, "", [], {}):
            names.extend(tool_name_from_value(v))
    # Event type often identifies a tool call even when the tool is nested.
    et = str(raw.get("event_type") or raw.get("type") or "").strip()
    if et and any(word in et.lower() for word in ["tool", "function", "action", "operation"]):
        if raw.get("name"):
            names.append(str(raw.get("name")))
    normalized = []
    seen = set()
    for n in names:
        nn = normalize_tool_name(n)
        if nn and nn not in seen:
            seen.add(nn)
            normalized.append(nn)
    return normalized


def infer_source(raw: Dict[str, Any], tools: Sequence[str]) -> str:
    explicit = first_present(raw, SOURCE_FIELDS)
    explicit_text = str(explicit or "").strip().lower()
    # Prefer an explicit source/channel over tool-name hints. Otherwise a tool named
    # send_email would incorrectly convert a generic tool event into an email event.
    if explicit_text:
        for source, hints in SOURCE_HINTS.items():
            if explicit_text == source or any(h == explicit_text or h in explicit_text for h in hints):
                return source

    text = " ".join(str(x).lower() for x in [raw.get("event_type"), raw.get("type"), *tools])
    for source, hints in SOURCE_HINTS.items():
        if any(h in text for h in hints):
            return source
    return "tool" if tools else "unknown"


def infer_trust(raw: Dict[str, Any], source: str) -> str:
    explicit = first_present(raw, TRUST_FIELDS)
    if explicit not in (None, "", [], {}):
        return str(explicit).lower()
    origin = " ".join(str(x).lower() for x in [source, raw.get("origin"), raw.get("url"), raw.get("sender"), raw.get("from")])
    if any(h in origin for h in UNTRUSTED_SOURCE_HINTS):
        return "untrusted"
    return "unknown"


def infer_node_id(raw: Dict[str, Any]) -> str:
    v = first_present(raw, NODE_FIELDS)
    if isinstance(v, dict):
        v = first_present(v, ["id", "name", "email", "username"])
    if v not in (None, "", [], {}):
        return str(v)
    # Last-resort stable-ish label for logs that omit agent id.
    return "agent-unknown"


def infer_time(raw: Dict[str, Any]) -> str:
    v = first_present(raw, TIME_FIELDS)
    if v not in (None, "", [], {}):
        if isinstance(v, (int, float)):
            try:
                # Treat plausible UNIX epoch seconds/milliseconds.
                if v > 10_000_000_000:
                    v = v / 1000.0
                return dt.datetime.fromtimestamp(float(v), tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")
            except Exception:
                pass
        return str(v)
    return utc_now()


def collect_edges(raw: Dict[str, Any], fields: Sequence[str]) -> List[str]:
    vals: List[str] = []
    for f in fields:
        v = get_path(raw, f)
        for item in as_list(v):
            if isinstance(item, dict):
                item = first_present(item, ["id", "name", "email", "node_id", "agent_id"])
            if item not in (None, "", [], {}):
                vals.append(str(item))
    seen = set(); out=[]
    for v in vals:
        if v and v not in seen:
            seen.add(v); out.append(v)
    return out


def infer_write_flags(raw: Dict[str, Any], tools: Sequence[str], content: str) -> Tuple[bool, bool, bool]:
    joined = " ".join(list(tools) + [content])
    wm = bool(raw.get("writes_memory", False)) or bool(re.search(r"\b(write_memory|memory\.add|save_memory|store_memory)\b", joined, re.I))
    wr = bool(raw.get("writes_rag", False)) or bool(re.search(r"\b(write_rag|rag\.add|vectorstore|upsert|embedding|knowledge_base)\b", joined, re.I))
    wc = bool(raw.get("writes_config", False)) or bool(CONFIG_WRITE_RE.search(joined))
    # Generic memory write expression may mean either memory or RAG; keep memory true, RAG false unless explicitly vector/RAG.
    if MEMORY_WRITE_RE.search(joined):
        wm = True
    return wm, wr, wc


def infer_sensitive(raw: Dict[str, Any], tools: Sequence[str], content: str) -> bool:
    if bool(raw.get("sensitive_access", False)):
        return True
    joined = " ".join(list(tools) + [content])
    return bool(SENSITIVE_RE.search(joined))


def normalize_record(raw: Dict[str, Any], index: int = 0) -> Dict[str, Any]:
    tools = collect_tools(raw)
    source = infer_source(raw, tools)
    content = collect_content(raw)
    writes_memory, writes_rag, writes_config = infer_write_flags(raw, tools, content)
    event = {
        "timestamp": infer_time(raw),
        "node_id": infer_node_id(raw),
        "source": source,
        "trust": infer_trust(raw, source),
        "content": content,
        "inbound_from": collect_edges(raw, INBOUND_FIELDS),
        "outbound_to": collect_edges(raw, OUTBOUND_FIELDS),
        "tool_calls": tools,
        "writes_memory": writes_memory,
        "writes_rag": writes_rag,
        "writes_config": writes_config,
        "sensitive_access": infer_sensitive(raw, tools, content),
        "notes": str(raw.get("notes") or raw.get("note") or f"normalized_by_pooleshield_adapter_v{VERSION}; raw_index={index}"),
    }

    # Cycle 3: preserve optional analyst labels for calibration. These fields
    # are metadata only; Event.from_dict ignores them during scoring.
    for key in [
        "case_id", "expected_alert", "expected_min_level", "expected_level",
        "expected_tags", "expected_family", "ground_truth", "label"
    ]:
        if key in raw:
            event[key] = raw[key]
    return event


def load_json(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in ["events", "items", "records", "traces", "logs", "data"]:
            if isinstance(data.get(key), list):
                return [x for x in data[key] if isinstance(x, dict)]
        return [data]
    raise ValueError("JSON input must be an object, list of objects, or object containing events/items/records/traces/logs/data.")


def load_jsonl(path: str) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            obj = json.loads(s)
            if not isinstance(obj, dict):
                raise ValueError(f"JSONL line {line_no} is not an object")
            records.append(obj)
    return records


def load_csv(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8", newline="") as f:
        return [dict(row) for row in csv.DictReader(f)]


def load_records(path: str) -> List[Dict[str, Any]]:
    ext = os.path.splitext(path.lower())[1]
    if ext == ".jsonl":
        return load_jsonl(path)
    if ext == ".json":
        return load_json(path)
    if ext == ".csv":
        return load_csv(path)
    # Try JSONL first, then JSON.
    try:
        return load_jsonl(path)
    except Exception:
        return load_json(path)


def write_jsonl(path: str, events: Sequence[Dict[str, Any]]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")


def summarize(events: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    by_source: Dict[str, int] = {}
    by_trust: Dict[str, int] = {}
    tool_events = 0
    for e in events:
        by_source[e["source"]] = by_source.get(e["source"], 0) + 1
        by_trust[e["trust"]] = by_trust.get(e["trust"], 0) + 1
        if e.get("tool_calls"):
            tool_events += 1
    return {
        "normalized_events": len(events),
        "by_source": dict(sorted(by_source.items())),
        "by_trust": dict(sorted(by_trust.items())),
        "events_with_tools": tool_events,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Normalize AI-agent/tool-call traces into PooleShield JSONL")
    parser.add_argument("--input", "-i", required=True, help="Input JSONL, JSON, or CSV trace file")
    parser.add_argument("--output", "-o", default="normalized_agent_events.jsonl", help="Output PooleShield JSONL path")
    parser.add_argument("--pretty-summary", action="store_true", help="Print normalized sample events as JSON")
    args = parser.parse_args(argv)

    records = load_records(args.input)
    events = [normalize_record(r, i) for i, r in enumerate(records)]
    write_jsonl(args.output, events)
    print(json.dumps(summarize(events), indent=2))
    print(f"Wrote normalized PooleShield JSONL: {args.output}")
    if args.pretty_summary:
        print(json.dumps(events[:3], indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
