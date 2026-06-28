# PooleShield Chat Export Adapter Guide — v1.8

## Purpose

`adapter_chat_export.py` normalizes real-world chat/conversation exports into PooleShield JSONL events.

It is defensive and non-executing. It only reads text/JSON export files and writes normalized events/reports.

## Supported inputs

- Speaker-labeled `.txt` / `.md` transcripts such as `User:` / `Assistant:` / `Tool:`
- Generic JSON conversation files with `messages`, `events`, `records`, `traces`, or `logs`
- ChatGPT-style JSON exports with `mapping` and nested `message` objects
- JSONL message/tool traces where each line is a JSON object

## Standalone adapter command

```powershell
python .\adapter_chat_export.py --input ".\examples\chat_export_fixture" --output ".\out\chat_norm.jsonl"
```

## Operator command

```powershell
python .\pooleshield_operator.py chat-scan --path ".\examples\chat_export_fixture" --output-dir ".\out\chat_scan" --clean-output --policy-profile balanced --bundle-output
```

## Safety boundary

The adapter does not execute tools, call APIs, follow links, send messages, modify files, or reproduce exploit behavior.

It only extracts message turns and metadata into the normal PooleShield event schema:

```json
{
  "timestamp": "...",
  "node_id": "...",
  "source": "chat|tool|rag|web|email",
  "trust": "trusted|untrusted|unknown",
  "content": "...",
  "inbound_from": ["..."],
  "outbound_to": ["..."],
  "tool_calls": ["..."],
  "writes_memory": false,
  "writes_rag": false,
  "writes_config": false,
  "sensitive_access": false,
  "notes": "source_path=..."
}
```

## Next validation target

Run `chat-scan` on a small real export folder first. Do not point it at a whole drive or large archive.
