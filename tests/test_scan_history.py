from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scan_history import init_history_db, record_scan_output, list_history, show_history_scan
from tests.test_file_av_baseline_scan import _make_baseline
from pooleshield_config import default_config


def _run_baseline_scan(repo: Path, tmp_path: Path) -> tuple[Path, Path, Path]:
    root, baseline_path = _make_baseline(tmp_path)
    out = tmp_path / "scan_out"
    cmd = [
        sys.executable, str(repo / "pooleshield_operator.py"), "file-av-scan-baseline",
        "--path", str(root),
        "--baseline", str(baseline_path),
        "--output-dir", str(out),
        "--clean-output",
        "--bundle-output",
        "--privacy-bundle",
    ]
    result = subprocess.run(cmd, cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert result.returncode == 0, result.stderr
    return root, baseline_path, out


def test_scan_history_record_and_list(tmp_path: Path):
    repo = Path(__file__).resolve().parents[1]
    _, _, out = _run_baseline_scan(repo, tmp_path)
    db = tmp_path / "local_history" / "pooleshield_scan_history.sqlite"
    init = init_history_db(str(db))
    assert init["created_or_verified"] is True
    recorded = record_scan_output(str(out), str(db), notes="test scan")
    assert recorded["scan_id"] == 1
    assert recorded["verdict"] == "CLEAN_AFTER_POLICY"
    assert recorded["items_scanned"] >= 1
    assert recorded["baseline_matches"] >= 1
    assert (out / "SCAN_HISTORY_RECORD.json").exists()
    history = list_history(str(db), limit=5)
    assert history["total_scans"] == 1
    assert history["scans"][0]["scan_id"] == 1
    shown = show_history_scan(str(db), scan_id=1)
    assert shown["scan"]["notes"] == "test scan"


def test_operator_history_commands(tmp_path: Path):
    repo = Path(__file__).resolve().parents[1]
    _, _, out = _run_baseline_scan(repo, tmp_path)
    db = tmp_path / "history.sqlite"

    init_cmd = [sys.executable, str(repo / "pooleshield_operator.py"), "history-init", "--history-db", str(db)]
    result = subprocess.run(init_cmd, cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert result.returncode == 0, result.stderr

    rec_cmd = [
        sys.executable, str(repo / "pooleshield_operator.py"), "history-record",
        "--history-db", str(db),
        "--output-dir", str(out),
        "--notes", "operator test",
        "--bundle-output",
        "--privacy-bundle",
    ]
    result2 = subprocess.run(rec_cmd, cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert result2.returncode == 0, result2.stderr
    data = json.loads(result2.stdout)
    assert data["scan_id"] == 1
    assert data["verdict"] == "CLEAN_AFTER_POLICY"

    list_cmd = [sys.executable, str(repo / "pooleshield_operator.py"), "history-list", "--history-db", str(db), "--limit", "3"]
    result3 = subprocess.run(list_cmd, cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert result3.returncode == 0, result3.stderr
    hist = json.loads(result3.stdout)
    assert hist["total_scans"] == 1
    assert hist["scans"][0]["notes"] == "operator test"

    show_cmd = [sys.executable, str(repo / "pooleshield_operator.py"), "history-show", "--history-db", str(db), "--scan-id", "1"]
    result4 = subprocess.run(show_cmd, cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert result4.returncode == 0, result4.stderr
    shown = json.loads(result4.stdout)
    assert shown["scan"]["scan_id"] == 1


def test_file_av_scan_baseline_auto_records_history_from_config(tmp_path: Path):
    repo = Path(__file__).resolve().parents[1]
    root, baseline_path = _make_baseline(tmp_path)
    out = tmp_path / "configured_scan"
    db = tmp_path / "history" / "pooleshield_scan_history.sqlite"
    cfg = default_config()
    cfg["defaults"].update({
        "baseline": str(baseline_path),
        "file_av_baseline_scan_output_dir": str(out),
        "history_db": str(db),
        "record_history": True,
        "rule_pack": str(repo / "examples" / "rule_packs" / "file_av_rules.default.json"),
        "scan_profile": "developer",
    })
    config_path = tmp_path / "pooleshield_config.json"
    config_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    cmd = [
        sys.executable, str(repo / "pooleshield_operator.py"), "file-av-scan-baseline",
        "--config", str(config_path),
        "--path", str(root),
        "--clean-output",
        "--bundle-output",
        "--privacy-bundle",
    ]
    result = subprocess.run(cmd, cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert result.returncode == 0, result.stderr
    run_summary = json.loads((out / "RUN_SUMMARY_FILE_AV_BASELINE_SCAN.json").read_text(encoding="utf-8"))
    assert run_summary["history_record"]["scan_id"] == 1
    assert (out / "SCAN_HISTORY_RECORD.json").exists()
    history = list_history(str(db), limit=1)
    assert history["total_scans"] == 1
    assert history["scans"][0]["scan_profile"] == "developer"
