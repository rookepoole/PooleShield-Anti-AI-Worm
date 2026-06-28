from __future__ import annotations

import csv
import json
import zipfile
from pathlib import Path

from file_antivirus import run_file_av_scan
from file_av_review import build_file_av_review_template, apply_file_av_review_ledger


def test_file_av_review_template_and_apply_ledger(tmp_path: Path):
    root = tmp_path / "fixture"
    root.mkdir()
    helper = root / "helper.ps1"
    helper.write_text("Remove-Item -Recurse $env:TEMP\\demo -ErrorAction SilentlyContinue\n", encoding="utf-8")
    run_file_av_scan(
        paths=[str(root)],
        output_dir=str(tmp_path / "out"),
        clean_output=True,
        bundle_output=False,
        risk_profile="standard",
    )
    template = build_file_av_review_template(str(tmp_path / "out"), bundle_output=True, privacy_bundle=True)
    assert template["review_rows"] >= 1
    ledger_path = tmp_path / "out" / "file_av_review_ledger_template.csv"
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
    result = apply_file_av_review_ledger(
        str(tmp_path / "out"),
        ledger=str(ledger_path),
        bundle_output=True,
        privacy_bundle=True,
    )
    assert result["applied_ledger_rows"] == len(rows)
    assert result["pending_review_rows"] == 0
    assert result["by_effective_decision"].get("ALLOW_LOG", 0) >= 1
    effective = json.loads((tmp_path / "out" / "effective_file_av_decisions.json").read_text(encoding="utf-8"))
    assert effective["summary"]["pending_review_rows"] == 0
    with zipfile.ZipFile(tmp_path / "out" / "pooleshield_results_bundle.zip") as z:
        names = set(z.namelist())
    assert "file_av_review_ledger_template.csv" in names
    assert "effective_file_av_decisions.json" in names


def test_file_av_review_does_not_read_or_export_raw_file_content(tmp_path: Path):
    root = tmp_path / "fixture"
    root.mkdir()
    secret = "PRIVATE_TEXT_SHOULD_NOT_APPEAR_IN_REVIEW"
    (root / "script.ps1").write_text(f"# {secret}\nInvoke-Expression 'demo'\n", encoding="utf-8")
    run_file_av_scan(
        paths=[str(root)],
        output_dir=str(tmp_path / "out"),
        clean_output=True,
        bundle_output=False,
    )
    build_file_av_review_template(str(tmp_path / "out"), bundle_output=True, privacy_bundle=True)
    for name in [
        "file_av_review_ledger_template.csv",
        "file_av_review_ledger_template.json",
        "file_av_review_ledger_template.md",
    ]:
        assert secret not in (tmp_path / "out" / name).read_text(encoding="utf-8")
    with zipfile.ZipFile(tmp_path / "out" / "pooleshield_results_bundle.zip") as z:
        data = b"".join(z.read(name) for name in z.namelist() if name.endswith((".json", ".csv", ".md")))
    assert secret.encode() not in data
