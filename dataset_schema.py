#!/usr/bin/env python3
"""PooleShield v5.3.0 safe-corpus schema helpers.

Defensive purpose:
  Normalize feature-only malware/benign benchmark records without collecting,
  unpacking, executing, or committing live malware samples.
"""
from __future__ import annotations

import json
import hashlib
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

VERSION = "5.3.0"
ALLOWED_LABELS = {"benign", "malicious", "suspicious", "unknown"}
POSITIVE_LABELS = {"malicious", "suspicious"}
NEGATIVE_LABELS = {"benign"}

_LABEL_ALIASES = {
    "0": "benign",
    "1": "malicious",
    "benignware": "benign",
    "goodware": "benign",
    "clean": "benign",
    "malware": "malicious",
    "malicious": "malicious",
    "suspicious": "suspicious",
    "pua": "suspicious",
    "pup": "suspicious",
    "unlabeled": "unknown",
    "unknown": "unknown",
    "": "unknown",
    "none": "unknown",
}

REQUIRED_FIELDS = (
    "sample_id",
    "source",
    "label",
    "features_only",
    "raw_binary_present",
    "feature_vector",
    "metadata",
    "safety_notes",
)


def normalize_label(value: Any) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, bool):
        return "malicious" if value else "benign"
    if isinstance(value, (int, float)):
        if int(value) == 1:
            return "malicious"
        if int(value) == 0:
            return "benign"
    text = str(value).strip().lower()
    return _LABEL_ALIASES.get(text, text if text in ALLOWED_LABELS else "unknown")


def _safe_sample_id(raw: Dict[str, Any], source: str) -> str:
    for key in ("sample_id", "sha256", "sha256_hash", "id", "file_id"):
        value = raw.get(key)
        if value:
            return str(value)
    digest_src = json.dumps(raw, sort_keys=True, default=str).encode("utf-8", errors="replace")
    return f"{source}:{hashlib.sha256(digest_src).hexdigest()}"


def _coerce_number(value: Any) -> Any:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text == "":
            return value
        try:
            if "." in text:
                return float(text)
            return int(text)
        except ValueError:
            return value
    return value


def _normalize_feature_vector(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    out: Dict[str, Any] = {}
    for key, val in value.items():
        if key is None:
            continue
        out[str(key)] = _coerce_number(val)
    return out


def _normalize_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x) for x in value if str(x)]
    if isinstance(value, str):
        if ";" in value:
            return [p.strip() for p in value.split(";") if p.strip()]
        if "," in value:
            return [p.strip() for p in value.split(",") if p.strip()]
        return [value] if value else []
    return [str(value)]


def normalize_record(raw: Dict[str, Any], *, source: str = "generic", allow_raw_binary: bool = False) -> Dict[str, Any]:
    """Normalize one safe-corpus record.

    This function does not read file contents. It accepts metadata/features only.
    If raw_binary_present is true and allow_raw_binary is false, validation will
    flag the record as unsafe for PooleShield's public benchmark path.
    """
    if not isinstance(raw, dict):
        raise TypeError("safe-corpus record must be a JSON object")
    rec_source = str(raw.get("source") or source or "generic")
    label = normalize_label(raw.get("label", raw.get("malware_label", raw.get("is_malicious"))))
    features = raw.get("feature_vector")
    if features is None:
        features = raw.get("features")
    if features is None:
        features = {k: v for k, v in raw.items() if str(k).startswith("feature_")}
    metadata = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
    tags = _normalize_list(raw.get("tags"))
    raw_binary_present = bool(raw.get("raw_binary_present", False))
    features_only = bool(raw.get("features_only", not raw_binary_present))
    safety_notes = _normalize_list(raw.get("safety_notes"))
    if not safety_notes:
        safety_notes = ["metadata/features only", "no executable sample included"]
    normalized = {
        "sample_id": _safe_sample_id(raw, rec_source),
        "source": rec_source,
        "label": label,
        "features_only": features_only,
        "raw_binary_present": raw_binary_present,
        "family": raw.get("family"),
        "tags": tags,
        "feature_vector": _normalize_feature_vector(features),
        "metadata": dict(metadata),
        "safety_notes": safety_notes,
    }
    errors, warnings = validate_record(normalized, allow_raw_binary=allow_raw_binary)
    normalized["validation"] = {"valid": not errors, "errors": errors, "warnings": warnings}
    return normalized


def validate_record(record: Dict[str, Any], *, allow_raw_binary: bool = False) -> Tuple[List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []
    for field in REQUIRED_FIELDS:
        if field not in record:
            errors.append(f"missing required field: {field}")
    label = normalize_label(record.get("label"))
    if label not in ALLOWED_LABELS:
        errors.append(f"unsupported label: {record.get('label')}")
    if record.get("raw_binary_present") and not allow_raw_binary:
        errors.append("raw_binary_present=true is not allowed for safe benchmark mode")
    if not record.get("features_only"):
        errors.append("features_only must be true for safe benchmark mode")
    if not isinstance(record.get("feature_vector"), dict):
        errors.append("feature_vector must be an object")
    if not record.get("feature_vector"):
        warnings.append("feature_vector is empty; score will be low-information")
    if label == "unknown":
        warnings.append("unknown labels are excluded from supervised metrics")
    return errors, warnings


def iter_jsonl(path: str | Path) -> Iterable[Dict[str, Any]]:
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                data = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL at {p}:{line_no}: {exc}") from exc
            if not isinstance(data, dict):
                raise ValueError(f"JSONL row is not an object at {p}:{line_no}")
            yield data


def load_safe_corpus(path: str | Path, *, source: str = "generic", allow_raw_binary: bool = False) -> List[Dict[str, Any]]:
    return [normalize_record(row, source=source, allow_raw_binary=allow_raw_binary) for row in iter_jsonl(path)]


def write_jsonl(path: str | Path, records: Iterable[Dict[str, Any]]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def summarize_records(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_label: Dict[str, int] = {}
    by_source: Dict[str, int] = {}
    invalid = 0
    raw_binary = 0
    for rec in records:
        by_label[rec.get("label") or "unknown"] = by_label.get(rec.get("label") or "unknown", 0) + 1
        by_source[rec.get("source") or "unknown"] = by_source.get(rec.get("source") or "unknown", 0) + 1
        if not (rec.get("validation") or {}).get("valid", True):
            invalid += 1
        if rec.get("raw_binary_present"):
            raw_binary += 1
    return {
        "record_count": len(records),
        "by_label": dict(sorted(by_label.items())),
        "by_source": dict(sorted(by_source.items())),
        "invalid_records": invalid,
        "raw_binary_present_records": raw_binary,
        "features_only": raw_binary == 0,
    }


def corpus_sha256(records: List[Dict[str, Any]]) -> str:
    payload = "\n".join(json.dumps(r, sort_keys=True, ensure_ascii=False) for r in records).encode("utf-8")
    return hashlib.sha256(payload).hexdigest().upper()
