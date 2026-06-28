import json
import zipfile
from pathlib import Path

from batch_rollup import build_rollup, summarize_source
from result_bundler import bundle_output_dir


def _write_batch(out: Path, label: str, decisions: dict, events: int, extracted: int = 0):
    out.mkdir(parents=True, exist_ok=True)
    (out / "RUN_SUMMARY.json").write_text(json.dumps({
        "version": "2.1",
        "mode": "dat-batch-chat-scan",
        "output_dir": f"out\\{label}\\dat_chat_scan",
        "scan": {"scan": {"event_count": events, "skipped_count": 1}},
        "policy_summary": {"by_decision": decisions},
    }), encoding="utf-8")
    (out / "RUN_SUMMARY_APPLY_LEDGER.json").write_text(json.dumps({
        "version": "2.1",
        "mode": "apply-ledger",
        "output_dir": f"out\\{label}\\dat_chat_scan",
        "effective_summary": {
            "total_decisions": events,
            "ledger_rows": sum(decisions.values()),
            "applied_ledger_rows": sum(decisions.values()),
            "pending_review_rows": decisions.get("REQUIRE_APPROVAL", 0),
            "by_effective_decision": decisions,
        },
    }), encoding="utf-8")
    (out / "effective_policy_decisions.json").write_text(json.dumps({
        "summary": {
            "total_decisions": events,
            "ledger_rows": sum(decisions.values()),
            "applied_ledger_rows": sum(decisions.values()),
            "pending_review_rows": decisions.get("REQUIRE_APPROVAL", 0),
            "by_effective_decision": decisions,
        }
    }), encoding="utf-8")
    (out / "RUN_SUMMARY_DAT_BATCH.json").write_text(json.dumps({
        "version": "2.1",
        "mode": "dat-batch",
        "output_dir": f"out\\{label}",
        "start_index": int(label.rsplit("_", 1)[-1]),
        "batch_size": 150,
        "next_start_index": int(label.rsplit("_", 1)[-1]) + extracted,
        "extract_summary": {"summary": {"extracted_files": extracted, "remaining_extractable_estimate": 0}},
    }), encoding="utf-8")


def test_summarize_source_privacy_zip(tmp_path: Path):
    out = tmp_path / "dat_batch_0000" / "dat_chat_scan"
    _write_batch(out, "dat_batch_0000", {"ALLOW": 2, "ALLOW_LOG": 1}, 3, extracted=2)
    bundle = bundle_output_dir(str(out), privacy_mode=True)["bundle_path"]
    row = summarize_source(bundle)
    assert row["events_scanned"] == 3
    assert row["allow"] == 2
    assert row["allow_log"] == 1
    assert row["actionable_final_items"] == 0
    assert row["privacy_ok"] is True
    assert row["status"] == "complete"


def test_build_rollup_multiple_sources(tmp_path: Path):
    out1 = tmp_path / "dat_batch_0000" / "dat_chat_scan"
    out2 = tmp_path / "dat_batch_0150" / "dat_chat_scan"
    _write_batch(out1, "dat_batch_0000", {"ALLOW": 2, "ALLOW_LOG": 1}, 3, extracted=2)
    _write_batch(out2, "dat_batch_0150", {"ALLOW": 4, "REQUIRE_APPROVAL": 1}, 5, extracted=3)
    bundle1 = bundle_output_dir(str(out1), privacy_mode=True)["bundle_path"]
    bundle2 = bundle_output_dir(str(out2), privacy_mode=True)["bundle_path"]
    rollup = build_rollup([bundle1, bundle2], str(tmp_path / "rollup"), clean_output=True)
    assert rollup["source_count"] == 2
    assert rollup["total_events_scanned"] == 8
    assert rollup["by_final_decision"]["ALLOW"] == 6
    assert rollup["by_final_decision"]["REQUIRE_APPROVAL"] == 1
    assert rollup["needs_attention_batches"] == 1
    assert (tmp_path / "rollup" / "batch_rollup.csv").exists()
    assert (tmp_path / "rollup" / "batch_rollup.md").exists()


def test_directory_source_uses_embedded_privacy_bundle_not_local_artifacts(tmp_path: Path):
    batch_root = tmp_path / "dat_batch_0150"
    out = batch_root / "dat_chat_scan"
    _write_batch(out, "dat_batch_0150", {"ALLOW": 4, "ALLOW_LOG": 2}, 6, extracted=3)
    # Store dat-batch metadata one level above dat_chat_scan, matching v2.0 output layout.
    (batch_root / "RUN_SUMMARY_DAT_BATCH.json").write_text(json.dumps({
        "version": "2.1.1",
        "mode": "dat-batch",
        "output_dir": "out\\dat_batch_0150",
        "start_index": 150,
        "batch_size": 150,
        "next_start_index": 153,
        "extract_summary": {"summary": {"extracted_files": 3, "remaining_extractable_estimate": 0}},
    }), encoding="utf-8")
    # Local workspaces can contain raw files; privacy should be judged by the upload bundle.
    (out / "normalized_events.jsonl").write_text("private local content", encoding="utf-8")
    evidence_dir = out / "extracted_dat_text"
    evidence_dir.mkdir()
    (evidence_dir / "raw.txt").write_text("private local decoded text", encoding="utf-8")
    bundle_output_dir(str(out), privacy_mode=True)

    row = summarize_source(str(out))
    assert row["events_scanned"] == 6
    assert row["extracted_files"] == 3
    assert row["privacy_ok"] is True
    assert row["privacy_scope"] == "embedded_privacy_bundle"
    assert row["local_private_artifacts_present"] is True
    assert row["status"] == "complete"
