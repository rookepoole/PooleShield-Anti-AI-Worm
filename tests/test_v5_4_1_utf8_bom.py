from __future__ import annotations

import json
from pathlib import Path

from dataset_schema import load_safe_corpus
from safe_dataset_lab import run_safe_dataset_dry_run


def _sha(ch: str) -> str:
    return ch * 64


def test_dataset_schema_load_safe_corpus_accepts_utf8_bom_jsonl(tmp_path: Path):
    src = tmp_path / "safe_bom.jsonl"
    row = {
        "sample_id": _sha("a"),
        "source": "bom_unit",
        "label": "benign",
        "features_only": True,
        "raw_binary_present": False,
        "feature_vector": {"entropy": 4.1},
        "metadata": {},
        "safety_notes": ["test fixture only"],
    }
    src.write_text("\ufeff" + json.dumps(row) + "\n", encoding="utf-8")
    records = load_safe_corpus(src)
    assert len(records) == 1
    assert records[0]["validation"]["valid"] is True


def test_safe_dataset_dry_run_accepts_utf8_bom_jsonl(tmp_path: Path):
    src = tmp_path / "external_bom.jsonl"
    row = {
        "sha256": _sha("b"),
        "label": "benign",
        "features_only": True,
        "raw_binary_present": False,
        "features": {"entropy": 4.2, "malicious_vendor_ratio": 0.0},
    }
    src.write_text("\ufeff" + json.dumps(row) + "\n", encoding="utf-8")
    out = tmp_path / "dry_run_bom"
    summary = run_safe_dataset_dry_run(
        str(src),
        output_dir=str(out),
        clean_output=True,
        source="bom_jsonl_unit",
        write_safe_jsonl=True,
    )
    assert summary["rows_seen"] == 1
    assert summary["accepted_count"] == 1
    assert summary["rejected_count"] == 0


def test_safe_dataset_dry_run_accepts_utf8_bom_csv(tmp_path: Path):
    src = tmp_path / "external_bom.csv"
    src.write_text(
        "\ufeffsha256,label,features_only,raw_binary_present,entropy,malicious_vendor_ratio\n"
        + f"{_sha('c')},benign,true,false,4.0,0.0\n",
        encoding="utf-8",
    )
    out = tmp_path / "dry_run_bom_csv"
    summary = run_safe_dataset_dry_run(
        str(src),
        output_dir=str(out),
        clean_output=True,
        source="bom_csv_unit",
    )
    assert summary["rows_seen"] == 1
    assert summary["accepted_count"] == 1
    assert summary["rejected_count"] == 0
