#!/usr/bin/env python3
"""Feature-only adapter for SOREL-style JSONL rows."""
from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List

from dataset_schema import VERSION, iter_jsonl, normalize_label, normalize_record, summarize_records, write_jsonl


def _label_from_sorel(row: Dict[str, Any]) -> str:
    if "label" in row:
        return normalize_label(row.get("label"))
    if "is_malware" in row:
        return normalize_label(row.get("is_malware"))
    if "rl_fs_label" in row:
        return normalize_label(row.get("rl_fs_label"))
    return "unknown"


def _extract_features(row: Dict[str, Any]) -> Dict[str, Any]:
    if isinstance(row.get("features"), dict):
        return dict(row["features"])
    if isinstance(row.get("feature_vector"), dict):
        return dict(row["feature_vector"])
    candidate_keys = ["malicious_vendor_ratio", "entropy", "packer_score", "suspicious_imports", "network_indicators"]
    return {k: row[k] for k in candidate_keys if k in row}


def normalize_sorel_file(input_path: str | Path, output_path: str | Path, limit: int | None = None) -> Dict[str, Any]:
    records: List[Dict[str, Any]] = []
    for idx, row in enumerate(iter_jsonl(input_path)):
        if limit is not None and idx >= limit:
            break
        raw = {
            "sample_id": row.get("sha256") or row.get("sample_id") or row.get("file_id") or f"sorel-row-{idx}",
            "source": "sorel",
            "label": _label_from_sorel(row),
            "features_only": True,
            "raw_binary_present": False,
            "feature_vector": _extract_features(row),
            "metadata": {k: row.get(k) for k in ("tags", "family", "vendor_count", "detection_count") if k in row},
            "tags": row.get("tags", []),
            "safety_notes": ["SOREL-style feature row", "no raw binary included"],
        }
        records.append(normalize_record(raw, source="sorel"))
    write_jsonl(output_path, records)
    return {
        "tool": "PooleShield SOREL feature adapter",
        "version": VERSION,
        "mode": "sorel-adapter",
        "input_path": str(Path(input_path)),
        "output_path": str(Path(output_path)),
        "summary": summarize_records(records),
        "ok": True,
    }
