# PooleShield v0.2 Adapter Schema

The Cycle 2 adapter converts common AI-agent/tool-call traces into the PooleShield event schema.
It is defensive-only: it reads logs and writes normalized JSONL. It does not execute tools, connect to services, or follow links.

## Canonical PooleShield event

```json
{
  "timestamp": "2026-06-28T13:00:00Z",
  "node_id": "agent-alpha",
  "source": "email|web|rag|tool|file|chat|api|unknown",
  "trust": "trusted|untrusted|external|unknown",
  "content": "observed prompt/message/log content",
  "inbound_from": ["sender-or-prior-node"],
  "outbound_to": ["recipient-or-next-node"],
  "tool_calls": ["read_email", "send_email"],
  "writes_memory": false,
  "writes_rag": false,
  "writes_config": false,
  "sensitive_access": false,
  "notes": "optional analyst note"
}
```

## Accepted raw fields

The adapter tries to infer the canonical event from fields commonly found in AI-agent traces:

- Time: `timestamp`, `created_at`, `time`, `datetime`, `event_time`, `created`, `ts`
- Node: `node_id`, `agent_id`, `agent`, `actor`, `assistant_id`, `session_id`, `run_id`, `thread_id`, `process_id`, `account_id`, `user_id`
- Source: `source`, `source_type`, `channel`, `event_source`, `modality`, plus hints from `event_type` and tool names
- Content: `content`, `text`, `message`, `prompt`, `input`, `output`, `response`, `arguments`, `args`, `params`, `query`, `document`, `chunk`, `body`, `subject`
- Tool calls: `tool_calls`, `tools`, `actions`, `tool`, `tool_name`, `function`, `function_name`, `name`, `operation`, `method`
- Edges: `from`, `sender`, `parent`, `caller`, `to`, `recipient`, `recipients`, `targets`, `target`, `next_agents`

## Cycle 2 command

```powershell
python .\pooleshield_cycle2.py --input .\examples\agent_tool_trace.jsonl --normalized .\normalized_agent_events.jsonl --output .\cycle2_report.json --csv .\cycle2_report.csv
```

## Cycle 3 calibration metadata

v0.4 preserves these optional analyst-label fields during normalization:

```json
{
  "case_id": "short_case_name",
  "expected_alert": true,
  "expected_min_level": "WATCH",
  "expected_tags": ["persistence", "fanout"]
}
```

These fields are used only by `benchmark_calibration.py` / `pooleshield_cycle3.py` and are ignored by the core scorer.
