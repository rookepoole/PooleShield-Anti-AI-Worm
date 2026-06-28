#!/usr/bin/env python3
"""
PooleShield v1.8 adapter: normalize chat/conversation exports into
PooleShield's defensive event schema.

Defensive purpose:
  Ingest real-world chat transcripts, ChatGPT-style JSON exports, generic
  conversation JSON, and simple tool-call JSONL traces without manually
  reshaping them first.

Safety boundary:
  This adapter only reads text/JSON files and writes normalized JSONL. It does
  not execute tools, follow links, call APIs, or reproduce malicious behavior.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

VERSION = "1.8.0"

ROLE_FIELDS = ["role", "speaker", "author", "from", "sender", "actor", "name"]
CONTENT_FIELDS = [
    "content", "text", "message", "body", "prompt", "response", "output",
    "input", "args", "arguments", "parameters", "query", "document", "chunk",
]
TIME_FIELDS = ["timestamp", "created_at", "time", "datetime", "create_time", "created", "ts"]
ID_FIELDS = ["id", "message_id", "event_id", "node_id", "run_id", "turn_id"]

SENSITIVE_RE = re.compile(r"\b(secret|api[_ -]?key|token|credential|password|passwd|private[_ -]?key|\.env)\b", re.I)
MEMORY_WRITE_RE = re.compile(
    r"\b(write|save|store|upsert|insert|add|update|persist).*\b(memory|rag|vector|embedding|knowledge|kb|index)\b|"
    r"\b(memory|rag|vectorstore|knowledge_base)\.(add|write|upsert|insert|update)\b",
    re.I,
)
CONFIG_WRITE_RE = re.compile(r"\b(write|modify|update|change|set).*\b(config|policy|permission|startup|cron|schedule)\b", re.I)
TOOL_HINT_RE = re.compile(
    r"\b(send_email|forward_email|send_message|post_message|delete_email|delete_file|archive_email|"
    r"execute_code|run_shell|powershell|cmd|bash|terminal|ssh|download_file|install_package|"
    r"modify_permissions|create_api_key|read_secret|write_secret|write_memory|write_rag|write_config|"
    r"change_config|schedule_task|cron_write|read_email|read_file|web_search|browser|retrieve_rag)\b",
    re.I,
)
SPEAKER_RE = re.compile(
    r"^\s*(user|human|assistant|system|developer|tool|browser|web|agent[-_ ]?[a-z0-9]+|bot[-_ ]?[a-z0-9]+|codex|github|terminal|shell)\s*:\s*(.*)$",
    re.I,
)
AGENT_MENTION_RE = re.compile(r"\b(agent[-_ ]?[a-z0-9]+|assistant[-_ ]?[a-z0-9]+|bot[-_ ]?[a-z0-9]+)\b", re.I)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def iso_from_timestamp(value: Any, fallback: dt.datetime) -> str:
    if value is None or value == "":
        return fallback.isoformat().replace("+00:00", "Z")
    if isinstance(value, (int, float)):
        # ChatGPT exports commonly use unix seconds.
        try:
            if value > 10_000_000_000:
                value = value / 1000.0
            return dt.datetime.fromtimestamp(float(value), tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")
        except Exception:
            return fallback.isoformat().replace("+00:00", "Z")
    s = str(value).strip()
    if not s:
        return fallback.isoformat().replace("+00:00", "Z")
    try:
        if s.endswith("Z"):
            return s
        parsed = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        return fallback.isoformat().replace("+00:00", "Z")


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
        if ";" in s:
            return [x.strip() for x in s.split(";") if x.strip()]
        if "," in s and len(s) < 250:
            return [x.strip() for x in s.split(",") if x.strip()]
        return [s]
    return [value]


def stable_hash(text: str, n: int = 16) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:n]


def safe_json_text(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except Exception:
        return str(value)


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
        if v is not None and v != "":
            return v
    return None


def stringify_content(value: Any) -> str:
    """Extract message text from common chat export content shapes."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, list):
        parts: List[str] = []
        for item in value:
            s = stringify_content(item)
            if s:
                parts.append(s)
        return "\n".join(parts)
    if isinstance(value, dict):
        # ChatGPT export style: {"content_type":"text","parts":["..."]}
        if "parts" in value:
            return stringify_content(value.get("parts"))
        if "text" in value:
            return stringify_content(value.get("text"))
        if "result" in value:
            return stringify_content(value.get("result"))
        if "value" in value:
            return stringify_content(value.get("value"))
        if "content" in value:
            return stringify_content(value.get("content"))
        # Multimodal/export leftovers: preserve a compact JSON view as data.
        return safe_json_text(value)
    return str(value)


def extract_role(raw: Dict[str, Any], default: str = "unknown") -> str:
    role = first_present(raw, ROLE_FIELDS)
    if isinstance(role, dict):
        role = role.get("role") or role.get("name") or role.get("type")
    if role is None:
        author = raw.get("author")
        if isinstance(author, dict):
            role = author.get("role") or author.get("name")
    return str(role or default).strip().lower()


def normalize_role(role: str) -> str:
    r = (role or "unknown").strip().lower()
    if r in {"human"}:
        return "user"
    if r in {"bot", "ai"}:
        return "assistant"
    if "assistant" in r:
        return "assistant"
    if "agent" in r:
        return r.replace(" ", "-")
    return r


def trust_for_role(role: str, default_trust: str = "untrusted") -> str:
    r = normalize_role(role)
    if r in {"system", "developer"}:
        return "trusted"
    if r in {"assistant"} or r.startswith("agent"):
        return "unknown"
    if r in {"tool", "browser", "web", "terminal", "shell", "codex", "github"}:
        return "untrusted"
    if r in {"user", "human", "unknown"}:
        return default_trust
    return default_trust


def source_for_role(role: str, content: str = "", tool_calls: Optional[List[str]] = None) -> str:
    r = normalize_role(role)
    blob = f"{r}\n{content[:1000]}".lower()
    if r in {"tool", "terminal", "shell", "codex", "github"} or tool_calls:
        return "tool"
    if r in {"browser", "web"} or "http://" in blob or "https://" in blob:
        return "web"
    if re.search(r"\b(rag|vector|knowledge\s+base|retrieval|embedding)\b", blob):
        return "rag"
    if re.search(r"\b(email|gmail|mail|inbox)\b", blob):
        return "email"
    return "chat"


def infer_tools(content: str, raw: Optional[Dict[str, Any]] = None) -> List[str]:
    seen = set()
    found: List[str] = []
    raw = raw or {}

    def add(name: Any) -> None:
        if isinstance(name, dict):
            name = name.get("name") or name.get("tool") or name.get("function") or name.get("function_name") or name.get("type")
        s = str(name or "").strip()
        if not s:
            return
        s = re.sub(r"[^a-zA-Z0-9_.-]+", "_", s).strip("_").lower()
        if s and s not in seen:
            seen.add(s)
            found.append(s)

    for key in ["tool_calls", "tools", "actions", "tool", "tool_name", "function", "function_name", "recipient"]:
        value = raw.get(key)
        if key == "recipient" and value in (None, "", "all", "assistant"):
            continue
        for item in as_list(value):
            add(item)

    for match in TOOL_HINT_RE.finditer(content or ""):
        add(match.group(1))

    phrase_aliases = [
        (r"\bsend\s+(an\s+)?email\b", "send_email"),
        (r"\bforward\s+(this|the)\s+email\b", "forward_email"),
        (r"\bwrite\s+(this|it)\s+to\s+memory\b", "write_memory"),
        (r"\bwrite\s+(this|it)\s+to\s+(rag|knowledge\s+base|vector\s+store)\b", "write_rag"),
        (r"\bread\s+(the\s+)?secret\b", "read_secret"),
        (r"\brun\s+(a\s+)?shell\b|\bexecute\s+(code|command|shell)\b", "run_shell"),
    ]
    for pattern, alias in phrase_aliases:
        if re.search(pattern, content or "", re.I):
            add(alias)
    return found


def infer_outbound(content: str, raw: Optional[Dict[str, Any]] = None, max_neighbors: int = 12) -> List[str]:
    raw = raw or {}
    out: List[str] = []
    seen = set()

    def add(x: Any) -> None:
        s = str(x or "").strip()
        if not s:
            return
        s = re.sub(r"\s+", "-", s.lower())
        if s not in seen:
            seen.add(s)
            out.append(s)

    for key in ["outbound_to", "to", "recipient", "recipients", "targets", "target", "next_agents"]:
        for item in as_list(raw.get(key)):
            if isinstance(item, dict):
                item = item.get("id") or item.get("email") or item.get("name") or safe_json_text(item)
            add(item)
            if len(out) >= max_neighbors:
                return out

    for match in AGENT_MENTION_RE.finditer(content or ""):
        add(match.group(1))
        if len(out) >= max_neighbors:
            break
    return out


def extract_content_from_raw(raw: Dict[str, Any]) -> str:
    for key in CONTENT_FIELDS:
        v = get_path(raw, key)
        if v is not None and v != "":
            return stringify_content(v)
    return stringify_content(raw)


def make_event(
    *,
    source_path: Path,
    session_id: str,
    index: int,
    role: str,
    content: str,
    timestamp: str,
    raw: Optional[Dict[str, Any]] = None,
    default_trust: str = "untrusted",
    previous_node: str = "",
) -> Dict[str, Any]:
    raw = raw or {}
    role_norm = normalize_role(role)
    tool_calls = infer_tools(content, raw)
    source = source_for_role(role_norm, content, tool_calls)
    node_seed = str(first_present(raw, ID_FIELDS) or f"{role_norm}-{index}")
    node_id = f"chat:{session_id}:{role_norm}:{stable_hash(node_seed, 8)}"
    inbound = []
    if previous_node:
        inbound.append(previous_node)
    else:
        inbound.append(f"chat_session:{session_id}")
    notes = f"source_path={source_path.as_posix()} chat_session={session_id} message_index={index} role={role_norm}"
    return {
        "timestamp": timestamp,
        "node_id": node_id,
        "source": source,
        "trust": trust_for_role(role_norm, default_trust),
        "content": content,
        "inbound_from": inbound,
        "outbound_to": infer_outbound(content, raw),
        "tool_calls": tool_calls,
        "writes_memory": bool(re.search(r"\b(memory|remember|saved memory)\b", content or "", re.I) and MEMORY_WRITE_RE.search(content or "")),
        "writes_rag": bool(re.search(r"\b(rag|vector|knowledge|embedding|index)\b", content or "", re.I) and MEMORY_WRITE_RE.search(content or "")),
        "writes_config": bool(CONFIG_WRITE_RE.search(content or "")),
        "sensitive_access": bool(SENSITIVE_RE.search(content or "")) or bool(raw.get("sensitive_access")),
        "notes": notes,
    }


def messages_from_chatgpt_mapping(obj: Dict[str, Any]) -> List[Dict[str, Any]]:
    mapping = obj.get("mapping") or {}
    session_id = str(obj.get("id") or obj.get("conversation_id") or obj.get("title") or "chatgpt_export")
    rows: List[Dict[str, Any]] = []
    for node_id, node in mapping.items():
        if not isinstance(node, dict):
            continue
        msg = node.get("message")
        if not isinstance(msg, dict):
            continue
        author = msg.get("author") or {}
        role = author.get("role") if isinstance(author, dict) else "unknown"
        content = stringify_content(msg.get("content"))
        if not content and not msg.get("recipient"):
            continue
        raw = dict(msg)
        raw["id"] = msg.get("id") or node_id
        raw["conversation_id"] = session_id
        raw["role"] = role or "unknown"
        raw["content"] = content
        raw["parent"] = node.get("parent")
        raw["children"] = node.get("children")
        rows.append(raw)
    rows.sort(key=lambda r: (r.get("create_time") is None, r.get("create_time") or 0, str(r.get("id") or "")))
    return rows


def messages_from_generic_json(obj: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if isinstance(obj, list):
        for item in obj:
            if isinstance(item, dict) and "mapping" in item:
                rows.extend(messages_from_chatgpt_mapping(item))
            elif isinstance(item, dict) and any(k in item for k in ("messages", "items", "events", "records", "traces", "logs")):
                rows.extend(messages_from_generic_json(item))
            elif isinstance(item, dict):
                rows.append(item)
        return rows

    if not isinstance(obj, dict):
        return rows

    if "mapping" in obj:
        return messages_from_chatgpt_mapping(obj)

    for key in ["messages", "conversation", "items", "events", "records", "traces", "logs", "data"]:
        value = obj.get(key)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    item = dict(item)
                    # Preserve top-level conversation id/title when available.
                    item.setdefault("conversation_id", obj.get("id") or obj.get("conversation_id") or obj.get("title"))
                    rows.append(item)
            if rows:
                return rows
    # Single message/event object
    if any(k in obj for k in CONTENT_FIELDS + ROLE_FIELDS):
        return [obj]
    return rows


def messages_from_transcript_text(text: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    current_role: Optional[str] = None
    current_lines: List[str] = []

    def flush() -> None:
        nonlocal current_role, current_lines
        if current_role is None:
            return
        content = "\n".join(current_lines).strip()
        if content:
            rows.append({"role": current_role, "content": content})
        current_role = None
        current_lines = []

    for line in (text or "").splitlines():
        m = SPEAKER_RE.match(line)
        if m:
            flush()
            current_role = m.group(1).strip()
            first = m.group(2).strip()
            current_lines = [first] if first else []
        else:
            if current_role is not None:
                current_lines.append(line)
    flush()
    return rows


def load_chat_rows(path: str) -> List[Dict[str, Any]]:
    p = Path(path)
    suffix = p.suffix.lower()
    if suffix == ".jsonl":
        rows: List[Dict[str, Any]] = []
        with p.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    rows.append({"role": "unknown", "content": line})
                    continue
                if isinstance(item, dict):
                    rows.extend(messages_from_generic_json(item))
        return rows
    if suffix == ".json":
        with p.open("r", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
        return messages_from_generic_json(obj)

    text = p.read_text(encoding="utf-8", errors="replace")
    transcript_rows = messages_from_transcript_text(text)
    if transcript_rows:
        return transcript_rows
    return []


def normalize_chat_file(
    path: str | Path,
    base_time: Optional[dt.datetime] = None,
    default_trust: str = "untrusted",
    max_records: int = 1000,
) -> List[Dict[str, Any]]:
    p = Path(path)
    base_time = base_time or dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    rows = load_chat_rows(str(p))[:max_records]
    session_id = stable_hash(p.as_posix(), 10)
    events: List[Dict[str, Any]] = []
    prev_node = ""
    for i, raw in enumerate(rows):
        if not isinstance(raw, dict):
            raw = {"role": "unknown", "content": stringify_content(raw)}
        content = extract_content_from_raw(raw)
        if not content and not raw.get("tool_calls") and not raw.get("recipient"):
            continue
        role = extract_role(raw, default="unknown")
        timestamp = iso_from_timestamp(first_present(raw, TIME_FIELDS), base_time + dt.timedelta(seconds=i))
        event = make_event(
            source_path=p,
            session_id=str(raw.get("conversation_id") or raw.get("session_id") or session_id),
            index=i,
            role=role,
            content=content,
            timestamp=timestamp,
            raw=raw,
            default_trust=default_trust,
            previous_node=prev_node,
        )
        prev_node = event["node_id"]
        events.append(event)
    return events


def iter_input_files(paths: Sequence[str], recursive: bool = True) -> Iterator[Path]:
    for raw in paths:
        root = Path(raw).expanduser().resolve()
        if not root.exists():
            raise FileNotFoundError(f"Input path not found: {root}")
        if root.is_file():
            yield root
        elif root.is_dir():
            walker = root.rglob("*") if recursive else root.glob("*")
            for p in walker:
                if p.is_file() and p.suffix.lower() in {".json", ".jsonl", ".txt", ".md", ".markdown", ".log"}:
                    yield p


def normalize_chat_paths(
    paths: Sequence[str],
    output_path: Optional[str] = None,
    default_trust: str = "untrusted",
    recursive: bool = True,
    max_records_per_file: int = 1000,
) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    base = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    file_index = 0
    for p in iter_input_files(paths, recursive=recursive):
        file_base = base + dt.timedelta(minutes=file_index)
        file_index += 1
        events.extend(normalize_chat_file(p, base_time=file_base, default_trust=default_trust, max_records=max_records_per_file))
    if output_path:
        write_jsonl(output_path, events)
    return events


def write_jsonl(path: str, events: Sequence[Dict[str, Any]]) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize chat/conversation exports into PooleShield JSONL events")
    parser.add_argument("--input", "-i", nargs="+", required=True, help="Chat export file/folder path(s)")
    parser.add_argument("--output", "-o", required=True, help="Output normalized JSONL path")
    parser.add_argument("--trust", choices=["trusted", "untrusted", "unknown"], default="untrusted")
    parser.add_argument("--no-recursive", action="store_true")
    parser.add_argument("--max-records-per-file", type=int, default=1000)
    args = parser.parse_args()
    events = normalize_chat_paths(
        args.input,
        output_path=args.output,
        default_trust=args.trust,
        recursive=not args.no_recursive,
        max_records_per_file=args.max_records_per_file,
    )
    print(json.dumps({
        "tool": "PooleShield chat export adapter",
        "version": VERSION,
        "input": args.input,
        "output": args.output,
        "event_count": len(events),
    }, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
