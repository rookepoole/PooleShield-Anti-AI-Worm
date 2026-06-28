import json
import subprocess
import sys
from pathlib import Path

from corpus_scanner import normalize_scan_paths, scan_and_report


def test_corpus_scan_uses_chat_adapter(tmp_path):
    root = Path(__file__).resolve().parents[1]
    fixture = root / "examples" / "chat_export_fixture"
    normalized_path = tmp_path / "norm.jsonl"
    events, path_map, skipped = normalize_scan_paths([str(fixture)], normalized_path=str(normalized_path))
    assert len(events) >= 8
    assert normalized_path.exists()
    assert any(e["node_id"].startswith("chat:") for e in events)
    assert any("send_email" in e.get("tool_calls", []) for e in events)


def test_operator_chat_scan_command(tmp_path):
    root = Path(__file__).resolve().parents[1]
    fixture = root / "examples" / "chat_export_fixture"
    out = tmp_path / "chat_scan_out"
    cmd = [
        sys.executable, str(root / "pooleshield_operator.py"), "chat-scan",
        "--path", str(fixture),
        "--output-dir", str(out),
        "--clean-output",
        "--bundle-output",
    ]
    result = subprocess.run(cmd, cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert result.returncode == 0, result.stderr
    assert (out / "scan_report.json").exists()
    assert (out / "approval_queue.json").exists()
    assert (out / "pooleshield_results_bundle.zip").exists()
    data = json.loads((out / "scan_report.json").read_text(encoding="utf-8"))
    assert data["summary"]["total_events"] >= 8
    assert data["summary"]["by_level"].get("WATCH", 0) >= 1
