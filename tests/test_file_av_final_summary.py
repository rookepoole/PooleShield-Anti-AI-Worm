from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from file_av_final_summary import build_final_scan_summary


def test_final_summary_clean_after_policy(tmp_path: Path):
    out = tmp_path / "out"
    out.mkdir()
    report = {
        "items": [
            {"display_path": "a.txt", "decision": "ALLOW", "effective_decision": "ALLOW", "risk_score": 0.0},
            {"display_path": "helper.ps1", "decision": "REQUIRE_APPROVAL", "original_decision": "REQUIRE_APPROVAL", "effective_decision": "ALLOW_LOG", "risk_score": 0.3, "baseline_status": "trusted_hash"},
        ]
    }
    (out / "effective_file_av_baseline_decisions.json").write_text(json.dumps(report), encoding="utf-8")
    summary = build_final_scan_summary(str(out))
    assert summary["verdict"] == "CLEAN_AFTER_POLICY"
    assert summary["actionable_items"] == 0
    assert summary["baseline_matches"] == 1
    assert (out / "FINAL_SCAN_SUMMARY.md").exists()
    assert (out / "FINAL_SCAN_SUMMARY_ACTION_ITEMS.csv").exists()


def test_final_summary_review_required(tmp_path: Path):
    out = tmp_path / "out"
    out.mkdir()
    report = {"items": [{"display_path": "suspicious.ps1", "decision": "REQUIRE_APPROVAL", "risk_score": 0.4, "labels": ["script_risk"]}]}
    (out / "file_av_report.json").write_text(json.dumps(report), encoding="utf-8")
    summary = build_final_scan_summary(str(out))
    assert summary["verdict"] == "REVIEW_REQUIRED"
    assert summary["actionable_items"] == 1
    assert summary["top_actionable_items"][0]["display_path"] == "suspicious.ps1"


def test_operator_file_av_final_summary_cli(tmp_path: Path):
    repo = Path(__file__).resolve().parents[1]
    out = tmp_path / "out"
    out.mkdir()
    (out / "file_av_report.json").write_text(json.dumps({"items": [{"display_path": "x", "decision": "ALLOW"}]}), encoding="utf-8")
    cmd = [sys.executable, str(repo / "pooleshield_operator.py"), "file-av-final-summary", "--output-dir", str(out)]
    result = subprocess.run(cmd, cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert result.returncode == 0, result.stderr
    assert (out / "FINAL_SCAN_SUMMARY.json").exists()
    data = json.loads((out / "FINAL_SCAN_SUMMARY.json").read_text(encoding="utf-8"))
    assert data["verdict"] == "CLEAN_AFTER_POLICY"


def test_final_summary_counts_v342_baseline_statuses(tmp_path: Path):
    out = tmp_path / "out"
    out.mkdir()
    report = {
        "items": [
            {"display_path": "archive.zip", "original_decision": "REQUIRE_APPROVAL", "effective_decision": "ALLOW_LOG", "baseline_status": "matched"},
            {"display_path": "archive.zip!script.ps1", "original_decision": "BLOCK", "effective_decision": "ALLOW_LOG", "baseline_status": "archive_parent_matched"},
            {"display_path": "plain.txt", "original_decision": "ALLOW", "effective_decision": "ALLOW", "baseline_status": "not_matched"},
        ]
    }
    (out / "effective_file_av_baseline_decisions.json").write_text(json.dumps(report), encoding="utf-8")
    summary = build_final_scan_summary(str(out))
    assert summary["verdict"] == "CLEAN_AFTER_POLICY"
    assert summary["baseline_matches"] == 2
    assert "Baseline matches: `2`" in (out / "FINAL_SCAN_SUMMARY.md").read_text(encoding="utf-8")
