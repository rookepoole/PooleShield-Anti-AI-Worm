from __future__ import annotations

import json
import subprocess
import sys
import zipfile
from pathlib import Path


def test_safe_dataset_dry_run_cli_aliases_write_normalized_and_redact_paths(tmp_path: Path):
    repo = Path(__file__).resolve().parents[1]
    dataset = tmp_path / "external_alias_dataset.jsonl"
    dataset.write_text(
        "\ufeff" + json.dumps({
            "sample_id": "alias-benign-001",
            "source": "alias_unit",
            "label": "benign",
            "features_only": True,
            "raw_binary_present": False,
            "feature_vector": {"entropy": 4.0, "malicious_vendor_ratio": 0.0},
            "metadata": {},
            "tags": ["alias"],
            "safety_notes": ["feature-only alias test"],
        }) + "\n"
        + json.dumps({
            "sample_id": "alias-unsafe-path-001",
            "source": "alias_unit",
            "label": "malicious",
            "features_only": True,
            "raw_binary_present": False,
            "sample_path": r"C:\Users\rookp\Desktop\bad.exe",
            "feature_vector": {"entropy": 7.9, "malicious_vendor_ratio": 1.0},
            "metadata": {},
        }) + "\n",
        encoding="utf-8",
    )
    out = tmp_path / "alias_out"
    cmd = [
        sys.executable,
        str(repo / "pooleshield_operator.py"),
        "safe-dataset-dry-run",
        "--input", str(dataset),
        "--output-dir", str(out),
        "--clean-output",
        "--write-normalized",
        "--bundle-output",
        "--privacy-bundle",
        "--redact-paths",
    ]
    result = subprocess.run(cmd, cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert result.returncode == 0, result.stderr + "\n" + result.stdout
    report = json.loads((out / "SAFE_DATASET_DRY_RUN.json").read_text(encoding="utf-8"))
    assert report["accepted_count"] == 1
    assert report["rejected_count"] == 1
    assert report["write_safe_jsonl"] is True
    assert (out / "safe_external_dataset.jsonl").exists()

    bundle = out / "pooleshield_results_bundle.zip"
    assert bundle.exists()
    with zipfile.ZipFile(bundle, "r") as zf:
        joined = "\n".join(
            zf.read(name).decode("utf-8", errors="replace")
            for name in zf.namelist()
            if name.lower().endswith((".json", ".md", ".csv", ".jsonl", ".txt"))
        )
    assert r"C:\Users\rookp" not in joined
    assert "bad.exe" not in joined
