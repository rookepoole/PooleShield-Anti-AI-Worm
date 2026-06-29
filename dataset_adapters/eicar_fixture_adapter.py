#!/usr/bin/env python3
"""Write inert EICAR-style metadata fixtures without malware binaries."""
from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List

from dataset_schema import VERSION, normalize_record, write_jsonl, summarize_records


def safe_eicar_style_records() -> List[Dict[str, Any]]:
    # Intentionally does not include the canonical EICAR string. Some AV products
    # quarantine the string itself, which is inconvenient for a public repo.
    raw = [
        {
            "sample_id": "fixture-benign-readme",
            "source": "safe_fixture",
            "label": "benign",
            "features_only": True,
            "raw_binary_present": False,
            "feature_vector": {"entropy": 3.2, "unsigned_binary": 0, "suspicious_imports": 0},
            "metadata": {"description": "benign text/document fixture"},
            "tags": ["fixture", "benign"],
        },
        {
            "sample_id": "fixture-suspicious-script-metadata",
            "source": "safe_fixture",
            "label": "suspicious",
            "features_only": True,
            "raw_binary_present": False,
            "feature_vector": {"powershell_flags": 0.9, "network_indicators": 0.3, "entropy": 5.1},
            "metadata": {"description": "synthetic suspicious script feature vector only"},
            "tags": ["fixture", "script", "metadata_only"],
        },
        {
            "sample_id": "fixture-eicar-style-marker-no-string",
            "source": "safe_fixture",
            "label": "malicious",
            "features_only": True,
            "raw_binary_present": False,
            "feature_vector": {"eicar_style_marker": 1.0, "malicious_vendor_ratio": 0.95},
            "metadata": {"description": "EICAR-style detection plumbing marker without canonical EICAR test string"},
            "tags": ["fixture", "eicar_style", "metadata_only"],
        },
    ]
    return [normalize_record(r, source="safe_fixture") for r in raw]


def write_fixture(output_path: str | Path) -> Dict[str, Any]:
    records = safe_eicar_style_records()
    write_jsonl(output_path, records)
    return {
        "tool": "PooleShield safe EICAR-style fixture adapter",
        "version": VERSION,
        "mode": "safe-corpus-fixture",
        "output_path": str(Path(output_path)),
        "summary": summarize_records(records),
        "safety_boundary": {
            "canonical_eicar_string_included": False,
            "raw_binaries_included": False,
            "malware_samples_downloaded": False,
            "artifacts_executed": False,
        },
        "ok": True,
    }
