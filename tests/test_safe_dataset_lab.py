from __future__ import annotations

import json
import zipfile
from pathlib import Path

from result_bundler import bundle_output_dir
from safe_dataset_lab import run_safe_dataset_dry_run, validate_external_feature_row


def test_validate_external_feature_row_rejects_raw_binary_and_sample_paths():
    errors, warnings = validate_external_feature_row(
        {
            "sample_id": "bad-1",
            "label": "malicious",
            "raw_binary_present": True,
            "features_only": False,
            "sample_path": r"C:\Users\rookp\Desktop\samples\evil.exe",
            "entropy": 7.1,
        },
        row_index=1,
    )
    joined = "; ".join(errors)
    assert "raw_binary_present=true" in joined
    assert "features_only=false" in joined
    assert "path field" in joined


def test_safe_dataset_dry_run_jsonl_accepts_features_and_rejects_unsafe_rows(tmp_path: Path):
    src = tmp_path / "external_features.jsonl"
    rows = [
        {
            "sha256": "a" * 64,
            "label": 1,
            "features_only": True,
            "raw_binary_present": False,
            "features": {"entropy": 7.4, "malicious_vendor_ratio": 0.9},
        },
        {
            "sha256": "b" * 64,
            "label": 0,
            "raw_binary_present": True,
            "features": {"entropy": 4.0},
        },
        {
            "sha256": "c" * 64,
            "label": "malicious",
            "sample_path": r"C:\Users\rookp\Desktop\samples\dropper.exe",
            "features": {"entropy": 7.9},
        },
    ]
    src.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    out = tmp_path / "dry_run"
    summary = run_safe_dataset_dry_run(
        str(src),
        output_dir=str(out),
        clean_output=True,
        source="unit_external",
        write_safe_jsonl=True,
        bundle_output=True,
        privacy_bundle=True,
        redact_paths=True,
    )
    assert summary["rows_seen"] == 3
    assert summary["accepted_count"] == 1
    assert summary["rejected_count"] == 2
    assert (out / "safe_external_dataset.jsonl").exists()
    assert (out / "safe_external_dataset_rejections.csv").exists()
    assert (out / "pooleshield_results_bundle.zip").exists()


def test_safe_dataset_dry_run_csv_accepts_numeric_feature_columns(tmp_path: Path):
    src = tmp_path / "external_features.csv"
    src.write_text(
        "sha256,label,features_only,raw_binary_present,entropy,malicious_vendor_ratio\n"
        + f"{'d'*64},benign,true,false,4.2,0.0\n",
        encoding="utf-8",
    )
    out = tmp_path / "csv_dry_run"
    summary = run_safe_dataset_dry_run(str(src), output_dir=str(out), clean_output=True, source="csv_unit")
    assert summary["accepted_count"] == 1
    assert summary["rejected_count"] == 0
    assert summary["record_summary"]["by_label"]["benign"] == 1


def test_result_bundler_redacts_local_paths_inside_bundle(tmp_path: Path):
    out = tmp_path / "bundle_me"
    out.mkdir()
    report = out / "leaky_report.json"
    report.write_text(
        json.dumps({
            "output_dir": r"C:\Users\rookp\Desktop\PooleShield-Anti-AI-Worm\out\run",
            "bundle_path": r"C:\Users\rookp\Desktop\PooleShield-Anti-AI-Worm\out\run\pooleshield_results_bundle.zip",
        }),
        encoding="utf-8",
    )
    bundle = out / "pooleshield_results_bundle.zip"
    summary = bundle_output_dir(str(out), str(bundle), privacy_mode=True, redact_paths=True)
    assert summary["redacted_file_count"] >= 1
    with zipfile.ZipFile(bundle, "r") as zf:
        text = zf.read("leaky_report.json").decode("utf-8")
        manifest = zf.read("BUNDLE_MANIFEST.json").decode("utf-8")
    assert "C:\\Users\\rookp" not in text
    assert "C:\\Users\\rookp" not in manifest
    assert "<LOCAL_PATH:" in text
