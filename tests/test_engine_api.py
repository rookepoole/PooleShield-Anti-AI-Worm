from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from pooleshield_config import default_config
from pooleshield_engine import (
    VERSION,
    config_validate,
    dispatch,
    file_av_scan_baseline,
    profile_list,
    results_load,
    profile_show,
)
from scan_history import list_history
from tests.test_file_av_baseline_scan import _make_baseline


def test_engine_profile_functions():
    catalog = profile_list()
    assert catalog["engine_version"] == VERSION
    assert "developer" in catalog["profile_names"]
    shown = profile_show("developer")
    assert shown["profile"]["name"] == "developer"
    assert shown["profile"]["risk_profile"] == "developer"


def test_engine_config_validate_default():
    summary = config_validate()
    assert summary["valid"] is True
    assert summary["engine_api_version"] == "1"
    assert summary["effective_config"]["safety"]["read_only"] is True


def test_engine_dispatch_success_and_error():
    ok = dispatch({"operation": "profile.show", "params": {"name": "developer"}})
    assert ok["ok"] is True
    assert ok["result"]["profile"]["name"] == "developer"
    bad = dispatch({"operation": "nope", "params": {}})
    assert bad["ok"] is False
    assert bad["error_type"] == "unsupported_operation"


def test_engine_file_av_scan_baseline_records_history(tmp_path: Path):
    root, baseline_path = _make_baseline(tmp_path)
    out = tmp_path / "engine_scan"
    db = tmp_path / "history" / "pooleshield_scan_history.sqlite"
    summary = file_av_scan_baseline(
        paths=[str(root)],
        baseline=str(baseline_path),
        output_dir=str(out),
        clean_output=True,
        bundle_output=True,
        privacy_bundle=True,
        history_db=str(db),
        record_history=True,
        history_notes="engine api test",
    )
    assert summary["engine_version"] == VERSION
    assert summary["final_verdict"] == "CLEAN_AFTER_POLICY"
    assert summary["history_record"]["scan_id"] == 1
    assert (out / "RUN_SUMMARY_FILE_AV_BASELINE_SCAN.json").exists()
    assert (out / "pooleshield_results_bundle.zip").exists()
    history = list_history(str(db), limit=5)
    assert history["total_scans"] == 1
    assert history["scans"][0]["notes"] == "engine api test"


def test_operator_engine_dispatch_cli(tmp_path: Path):
    repo = Path(__file__).resolve().parents[1]
    request = tmp_path / "engine_request.json"
    response = tmp_path / "engine_response.json"
    request.write_text(json.dumps({"operation": "profile.show", "params": {"name": "developer"}}), encoding="utf-8")
    cmd = [
        sys.executable,
        str(repo / "pooleshield_operator.py"),
        "engine-dispatch",
        "--request",
        str(request),
        "--output",
        str(response),
    ]
    result = subprocess.run(cmd, cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert result.returncode == 0, result.stderr
    data = json.loads(response.read_text(encoding="utf-8"))
    assert data["ok"] is True
    assert data["operation"] == "profile.show"
    assert data["result"]["profile"]["name"] == "developer"


def test_engine_results_load_metadata_only(tmp_path: Path):
    root, baseline_path = _make_baseline(tmp_path)
    out = tmp_path / "engine_results"
    summary = file_av_scan_baseline(
        paths=[str(root)],
        baseline=str(baseline_path),
        output_dir=str(out),
        clean_output=True,
        bundle_output=True,
        privacy_bundle=True,
    )
    assert summary["final_verdict"] == "CLEAN_AFTER_POLICY"
    loaded = results_load(str(out), decision="ALLOW_LOG", limit=10)
    assert loaded["engine_version"] == VERSION
    assert loaded["operation"] == "results.load"
    assert loaded["safety_boundary"]["metadata_only"] is True
    assert loaded["total_items_available"] >= loaded["items_returned"]
    assert loaded["items_returned"] > 0
    assert all(item["effective_decision"] == "ALLOW_LOG" for item in loaded["items"])
    first = loaded["items"][0]
    assert "display_path" in first
    assert "sha256" in first
    assert "reasons" in first


def test_operator_results_load_cli(tmp_path: Path):
    root, baseline_path = _make_baseline(tmp_path)
    out = tmp_path / "operator_results"
    file_av_scan_baseline(
        paths=[str(root)],
        baseline=str(baseline_path),
        output_dir=str(out),
        clean_output=True,
        bundle_output=True,
        privacy_bundle=True,
    )
    repo = Path(__file__).resolve().parents[1]
    response = tmp_path / "results_response.json"
    cmd = [
        sys.executable,
        str(repo / "pooleshield_operator.py"),
        "results-load",
        "--output-dir",
        str(out),
        "--decision",
        "ALLOW_LOG",
        "--limit",
        "5",
        "--output",
        str(response),
    ]
    result = subprocess.run(cmd, cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert result.returncode == 0, result.stderr
    data = json.loads(response.read_text(encoding="utf-8"))
    assert data["ok"] is True
    assert data["operation"] == "results.load"
    assert data["result"]["items_returned"] <= 5
