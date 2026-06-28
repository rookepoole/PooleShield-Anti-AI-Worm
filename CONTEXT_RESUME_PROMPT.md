# Context Resume Prompt

Copy/paste this into a future chat if context is lost:

```text
We are developing PooleShield, a defensive, non-executing AI-worm / prompt-contamination protection program using Poole Math local-defect logic. It scores prompt/RAG/tool/file events for local defect density, rising defect gradient, dangerous agency, fan-out, persistence, replication, and neighbor pressure.

Safety boundary: defensive only. Do not build exploit code, malware, credential theft, persistence, evasion, or working worm mechanics. The tool reads text-like files and writes reports; it does not delete, execute, send, block, or modify scanned content.

Current validated state: v1.2 real workflow passed. Real scan found 5 events: 3 NORMAL and 2 WATCH. Policy produced 2 ALLOW, 1 ALLOW_LOG, and 2 REQUIRE_APPROVAL. Review ledger applied 3 rows and produced effective decisions: 2 ALLOW, 1 ALLOW_LOG, 1 BLOCK, and 1 QUARANTINE, with 1 allowlist and 2 denylist entries. Bundle integrity had 0 hash mismatches.

Current package: v1.8 continuity release. It adds PROJECT_STATE.md, NEXT_BEST_MOVE.md, CONTEXT_RESUME_PROMPT.md, HANDOFF_PACKET.json, RECOVERY_COMMANDS.md, and a status command.

When I say “next,” continue the next best move cycle automatically. The next best implementation move after v1.8 is v1.8: build a real-world adapter, probably adapter_chat_export.py, to normalize chat/export/tool traces into PooleShield events.
```


## v1.8 continuation note

PooleShield v1.8 adds `adapter_chat_export.py` and `chat-scan` for ChatGPT/Codex/generic chat exports. The next best move is to run `chat-scan` on a small real export bundle and calibrate results before adding enforcement.
