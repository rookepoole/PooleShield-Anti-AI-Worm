from __future__ import annotations

import csv
import json
import subprocess
import sys
import zipfile
from pathlib import Path

from file_antivirus import run_file_av_scan
from file_av_review import build_file_av_review_template, apply_file_av_review_ledger
from file_av_baseline import build_file_av_baseline
from file_av_baseline_scan import run_file_av_scan_with_baseline


def _approve_all_review_rows(ledger_path: Path) -> None:
    rows = []
    with ledger_path.open("r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            row["operator_decision"] = "ALLOW_LOG"
            row["operator"] = "test"
            row["notes"] = "trusted helper"
            rows.append(row)
    assert rows
    with ledger_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def _make_baseline(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "fixture"
    root.mkdir()
    (root / "helper.ps1").write_text("Remove-Item -Recurse $env:TEMP\\demo -ErrorAction SilentlyContinue\n", encoding="utf-8")
    reviewed = tmp_path / "reviewed"
    run_file_av_scan(paths=[str(root)], output_dir=str(reviewed), clean_output=True, bundle_output=False)
    build_file_av_review_template(str(reviewed), bundle_output=False)
    _approve_all_review_rows(reviewed / "file_av_review_ledger_template.csv")
    apply_file_av_review_ledger(str(reviewed), ledger=str(reviewed / "file_av_review_ledger_template.csv"), bundle_output=False)
    baseline_path = tmp_path / "local_trust" / "trusted_file_baseline.json"
    build_file_av_baseline(str(reviewed), baseline_path=str(baseline_path), bundle_output=False)
    assert baseline_path.exists()
    return root, baseline_path


def test_file_av_scan_baseline_one_command(tmp_path: Path):
    root, baseline_path = _make_baseline(tmp_path)
    out = tmp_path / "baseline_scan"
    summary = run_file_av_scan_with_baseline(
        paths=[str(root)],
        baseline=str(baseline_path),
        output_dir=str(out),
        clean_output=True,
        bundle_output=True,
        privacy_bundle=True,
    )
    assert summary["baseline_matches"] >= 1
    assert summary["pending_review_rows"] == 0
    assert summary["by_effective_decision"].get("ALLOW_LOG", 0) >= 1
    assert (out / "effective_dry_run_quarantine_plan.json").exists()
    assert (out / "FINAL_SCAN_SUMMARY.json").exists()
    assert (out / "FINAL_SCAN_SUMMARY.md").exists()
    plan = json.loads((out / "effective_dry_run_quarantine_plan.json").read_text(encoding="utf-8"))
    assert plan["items"] == []
    with zipfile.ZipFile(out / "pooleshield_results_bundle.zip") as z:
        names = set(z.namelist())
    assert "effective_file_av_baseline_decisions.json" in names
    assert "effective_dry_run_quarantine_plan.json" in names
    assert "FINAL_SCAN_SUMMARY.json" in names
    assert "FINAL_SCAN_SUMMARY.md" in names
    assert "trusted_file_baseline.json" not in names


def test_operator_file_av_scan_baseline_cli(tmp_path: Path):
    repo = Path(__file__).resolve().parents[1]
    root, baseline_path = _make_baseline(tmp_path)
    out = tmp_path / "cli_out"
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
    data = json.loads((out / "RUN_SUMMARY_FILE_AV_BASELINE_SCAN.json").read_text(encoding="utf-8"))
    assert data["pending_review_rows"] == 0
    assert data["baseline_matches"] >= 1
    assert data["final_verdict"] == "CLEAN_AFTER_POLICY"
