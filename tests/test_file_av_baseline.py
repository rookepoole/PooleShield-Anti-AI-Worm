from __future__ import annotations

import csv
import json
import zipfile
from pathlib import Path

from file_antivirus import run_file_av_scan
from file_av_review import build_file_av_review_template, apply_file_av_review_ledger
from file_av_baseline import build_file_av_baseline, apply_file_av_baseline


def _approve_all_review_rows(ledger_path: Path) -> int:
    rows = []
    with ledger_path.open("r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            row["operator_decision"] = "ALLOW_LOG"
            row["operator"] = "test"
            row["notes"] = "trusted local helper script"
            rows.append(row)
    with ledger_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def test_file_av_build_and_apply_trusted_baseline(tmp_path: Path):
    root = tmp_path / "fixture"
    root.mkdir()
    helper = root / "helper.ps1"
    helper.write_text("Remove-Item -Recurse $env:TEMP\\demo -ErrorAction SilentlyContinue\n", encoding="utf-8")
    out = tmp_path / "out"
    run_file_av_scan(paths=[str(root)], output_dir=str(out), clean_output=True, bundle_output=False)
    build_file_av_review_template(str(out), bundle_output=False)
    rows = _approve_all_review_rows(out / "file_av_review_ledger_template.csv")
    assert rows >= 1
    apply_file_av_review_ledger(str(out), ledger=str(out / "file_av_review_ledger_template.csv"), bundle_output=False)

    baseline_summary = build_file_av_baseline(str(out), bundle_output=True, privacy_bundle=True)
    assert baseline_summary["baseline_entries"] >= 1
    baseline_path = out / "trusted_file_baseline.json"
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    assert baseline["summary"]["entries"] >= 1

    # Rescan the same helper with no human ledger, then apply baseline.
    out2 = tmp_path / "out2"
    run_file_av_scan(paths=[str(root)], output_dir=str(out2), clean_output=True, bundle_output=False)
    result = apply_file_av_baseline(str(out2), baseline=str(baseline_path), bundle_output=True, privacy_bundle=True)
    assert result["baseline_matches"] >= 1
    assert result["pending_review_rows"] == 0
    assert result["by_effective_decision"].get("ALLOW_LOG", 0) >= 1
    effective = json.loads((out2 / "effective_file_av_baseline_decisions.json").read_text(encoding="utf-8"))
    matched = [i for i in effective["items"] if i.get("baseline_status") == "matched"]
    assert matched
    assert all(i["effective_decision"] == "ALLOW_LOG" for i in matched)
    assert any("baseline_trusted_hash" in i.get("labels", []) for i in matched)


def test_file_av_baseline_privacy_bundle_excludes_local_db(tmp_path: Path):
    root = tmp_path / "fixture"
    root.mkdir()
    (root / "helper.ps1").write_text("Remove-Item -Recurse $env:TEMP\\demo\n", encoding="utf-8")
    out = tmp_path / "out"
    run_file_av_scan(paths=[str(root)], output_dir=str(out), clean_output=True, bundle_output=False)
    build_file_av_review_template(str(out), bundle_output=False)
    _approve_all_review_rows(out / "file_av_review_ledger_template.csv")
    apply_file_av_review_ledger(str(out), ledger=str(out / "file_av_review_ledger_template.csv"), bundle_output=False)
    build_file_av_baseline(str(out), bundle_output=True, privacy_bundle=True)
    with zipfile.ZipFile(out / "pooleshield_results_bundle.zip") as z:
        names = set(z.namelist())
        manifest = json.loads(z.read("BUNDLE_MANIFEST.json").decode("utf-8"))
    assert "trusted_file_baseline.json" not in names
    assert "trusted_file_baseline.md" not in names
    excluded = set(manifest.get("excluded_content_files", []))
    assert {"trusted_file_baseline.json", "trusted_file_baseline.csv", "trusted_file_baseline.md"}.issubset(excluded)
