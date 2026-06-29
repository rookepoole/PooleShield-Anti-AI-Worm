#!/usr/bin/env python3
"""PooleShield v5.4 safe external dataset dry-run lab.

Defensive purpose:
  Let code testers inspect/normalize feature-only external benchmark rows
  without collecting, unpacking, executing, or fetching malware samples.

Safety boundary:
  This module reads JSONL/CSV metadata rows only. It rejects raw-binary flags,
  download/link fields, executable/archive sample paths, payload-like fields,
  and unsupported input file types. It never opens paths referenced by rows.
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from dataset_schema import VERSION as SCHEMA_VERSION
from dataset_schema import normalize_label, normalize_record, summarize_records, write_jsonl
from result_bundler import bundle_output_dir

VERSION = "5.4.2"

SUPPORTED_INPUT_SUFFIXES = {".jsonl", ".csv"}
BLOCKED_INPUT_SUFFIXES = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".msi", ".ps1", ".bat", ".cmd",
    ".vbs", ".js", ".jse", ".wsf", ".jar", ".apk", ".ipa", ".dmg", ".iso",
    ".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz",
}
SAMPLE_SUFFIXES = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".msi", ".ps1", ".bat", ".cmd",
    ".vbs", ".js", ".jse", ".wsf", ".jar", ".apk", ".ipa", ".dmg", ".iso",
    ".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz",
}
HARD_REJECT_KEY_EXACT = {
    "raw", "raw_bytes", "raw_binary", "binary", "bytes", "bytez", "payload", "payload_b64",
    "base64", "contents", "content", "file_content", "script_content", "pe_bytes", "hex_blob",
    "download_url", "malware_url", "sample_url", "url", "uri",
}
PATH_KEY_FRAGMENTS = ("path", "filename", "file_name", "sample_file", "binary_file", "archive")
RESERVED_NON_FEATURE_KEYS = {
    "sample_id", "sha256", "sha256_hash", "id", "file_id", "source", "label", "malware_label",
    "is_malicious", "is_malware", "rl_fs_label", "family", "tags", "metadata", "features",
    "feature_vector", "features_only", "raw_binary_present", "safety_notes", "appeared", "avclass",
    "subset", "vendor_count", "detection_count",
}
KNOWN_FEATURE_KEYS = {
    "entropy", "suspicious_imports", "network_indicators", "powershell_flags", "macro_indicators",
    "packer_score", "malicious_vendor_ratio", "rare_section_names", "self_modifying_hint",
    "unsigned_binary", "eicar_style_marker", "known_test_malware_marker",
}
URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://")
WINDOWS_DRIVE_RE = re.compile(r"(?i)^[a-z]:[\\/]")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _boolish(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"true", "1", "yes", "y", "on"}:
        return True
    if text in {"false", "0", "no", "n", "off", ""}:
        return False
    return None


def _maybe_number(value: Any) -> Any:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float)):
        return value
    text = str(value).strip()
    if text == "":
        return value
    try:
        if any(ch in text.lower() for ch in (".", "e")):
            return float(text)
        return int(text)
    except ValueError:
        return value


def _looks_like_sample_reference(value: Any) -> bool:
    if value is None:
        return False
    text = str(value).strip()
    if not text:
        return False
    if URL_RE.search(text):
        return True
    lowered = text.lower().replace("/", "\\")
    if WINDOWS_DRIVE_RE.match(text) or "\\" in lowered or "/" in text:
        suffix = Path(lowered).suffix.lower()
        if suffix in SAMPLE_SUFFIXES:
            return True
    suffix = Path(lowered).suffix.lower()
    if suffix in SAMPLE_SUFFIXES:
        return True
    return False


def _safe_sample_id(row: Dict[str, Any], source: str, index: int) -> str:
    for key in ("sample_id", "sha256", "sha256_hash", "id", "file_id"):
        value = row.get(key)
        if value not in (None, ""):
            return str(value)
    payload = json.dumps(row, sort_keys=True, default=str).encode("utf-8", errors="replace")
    return f"{source}:row-{index}:{hashlib.sha256(payload).hexdigest()[:16]}"


def _row_label(row: Dict[str, Any]) -> str:
    for key in ("label", "malware_label", "is_malicious", "is_malware", "rl_fs_label"):
        if key in row:
            return normalize_label(row.get(key))
    return "unknown"


def _extract_features(row: Dict[str, Any]) -> Dict[str, Any]:
    if isinstance(row.get("feature_vector"), dict):
        return {str(k): _maybe_number(v) for k, v in row["feature_vector"].items()}
    if isinstance(row.get("features"), dict):
        return {str(k): _maybe_number(v) for k, v in row["features"].items()}

    features: Dict[str, Any] = {}
    for key, value in row.items():
        k = str(key)
        lk = k.lower()
        if lk in RESERVED_NON_FEATURE_KEYS:
            continue
        if lk in HARD_REJECT_KEY_EXACT:
            continue
        if any(fragment in lk for fragment in PATH_KEY_FRAGMENTS):
            continue
        if lk in KNOWN_FEATURE_KEYS or lk.startswith("feature_"):
            features[k] = _maybe_number(value)
            continue
        converted = _maybe_number(value)
        if isinstance(converted, (int, float, bool)):
            features[k] = converted
    return features


def _metadata_preview(row: Dict[str, Any]) -> Dict[str, Any]:
    metadata: Dict[str, Any] = {}
    for key in ("appeared", "avclass", "subset", "vendor_count", "detection_count", "family"):
        if key in row and row.get(key) not in (None, ""):
            metadata[key] = row.get(key)
    return metadata


def _row_key_list(row: Dict[str, Any], limit: int = 30) -> str:
    keys = sorted(str(k) for k in row.keys())[:limit]
    suffix = "..." if len(row.keys()) > limit else ""
    return ";".join(keys) + suffix


def validate_external_feature_row(
    row: Dict[str, Any],
    *,
    row_index: int,
    strict_path_fields: bool = True,
    allow_url_metadata: bool = False,
) -> Tuple[List[str], List[str]]:
    """Return validation errors/warnings for one external feature-only row."""
    errors: List[str] = []
    warnings: List[str] = []
    if not isinstance(row, dict):
        return ["row is not a JSON/CSV object"], []

    raw_binary_present = _boolish(row.get("raw_binary_present"))
    features_only = _boolish(row.get("features_only"))
    if raw_binary_present is True:
        errors.append("raw_binary_present=true is not allowed")
    if features_only is False:
        errors.append("features_only=false is not allowed")

    for key, value in row.items():
        lk = str(key).strip().lower()
        if value in (None, "", [], {}):
            continue
        if lk in HARD_REJECT_KEY_EXACT:
            if lk in {"url", "uri"} and allow_url_metadata:
                warnings.append(f"url-like metadata field ignored: {key}")
            else:
                errors.append(f"content/download/payload-like field is not allowed: {key}")
        if URL_RE.search(str(value)) and not allow_url_metadata:
            errors.append(f"URL value is not allowed in safe dataset mode: {key}")
        if strict_path_fields and any(fragment in lk for fragment in PATH_KEY_FRAGMENTS):
            if _looks_like_sample_reference(value):
                errors.append(f"sample/archive/executable path field is not allowed: {key}")
            else:
                warnings.append(f"path-like field ignored: {key}")
        elif _looks_like_sample_reference(value):
            errors.append(f"sample/archive/executable reference is not allowed: {key}")

    features = _extract_features(row)
    if not features:
        warnings.append("no numeric feature_vector/features detected; record will be low-information")
    if _row_label(row) == "unknown":
        warnings.append("unknown label; excluded from supervised metrics")
    return errors, warnings


def _normalize_external_row(row: Dict[str, Any], *, source: str, row_index: int) -> Dict[str, Any]:
    raw = {
        "sample_id": _safe_sample_id(row, source, row_index),
        "source": source,
        "label": _row_label(row),
        "features_only": True,
        "raw_binary_present": False,
        "family": row.get("family"),
        "tags": row.get("tags", []),
        "feature_vector": _extract_features(row),
        "metadata": _metadata_preview(row),
        "safety_notes": [
            "external feature-only dry-run row",
            "raw binary not loaded",
            "row path/url fields ignored or rejected",
        ],
    }
    return normalize_record(raw, source=source, allow_raw_binary=False)


def _iter_jsonl(path: Path) -> Iterator[Dict[str, Any]]:
    with path.open("r", encoding="utf-8-sig") as f:
        for line_no, line in enumerate(f, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                row = json.loads(text)
            except json.JSONDecodeError as exc:
                yield {"__poole_parse_error__": f"invalid JSONL at line {line_no}: {exc}"}
                continue
            if not isinstance(row, dict):
                yield {"__poole_parse_error__": f"row at line {line_no} is not an object"}
                continue
            yield row


def _iter_csv(path: Path) -> Iterator[Dict[str, Any]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            yield {str(k): v for k, v in row.items() if k is not None}


def _iter_rows(path: Path, input_format: str = "auto") -> Iterator[Dict[str, Any]]:
    suffix = path.suffix.lower()
    fmt = input_format.lower().strip()
    if fmt == "auto":
        fmt = "jsonl" if suffix == ".jsonl" else "csv" if suffix == ".csv" else ""
    if fmt == "jsonl":
        yield from _iter_jsonl(path)
    elif fmt == "csv":
        yield from _iter_csv(path)
    else:
        raise ValueError(f"unsupported safe dataset input format: {input_format}; use auto, jsonl, or csv")


def _validate_input_path(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(f"external dataset input not found: {path}")
    if not path.is_file():
        raise IsADirectoryError(f"external dataset input must be a JSONL/CSV file, not a directory: {path}")
    suffix = path.suffix.lower()
    if suffix in BLOCKED_INPUT_SUFFIXES:
        raise ValueError(f"unsafe/unsupported input suffix for safe dataset mode: {suffix}")
    if suffix not in SUPPORTED_INPUT_SUFFIXES:
        raise ValueError(f"unsupported input suffix for safe dataset mode: {suffix}; expected .jsonl or .csv")


def _write_rejection_csv(path: Path, rows: Sequence[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["row_index", "sample_id", "label", "errors", "warnings", "row_keys"]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def _write_report_md(path: Path, summary: Dict[str, Any]) -> None:
    lines = [
        "# PooleShield Safe External Dataset Dry Run",
        "",
        f"Version: `{summary.get('version')}`",
        f"Input display: `{summary.get('input_display')}`",
        f"Source label: `{summary.get('source')}`",
        f"Rows seen: `{summary.get('rows_seen')}`",
        f"Accepted rows: `{summary.get('accepted_count')}`",
        f"Rejected rows: `{summary.get('rejected_count')}`",
        f"Warning rows: `{summary.get('warning_count')}`",
        f"Write safe JSONL: `{summary.get('write_safe_jsonl')}`",
        "",
        "## Safety boundary",
        "",
        "This dry run reads JSONL/CSV metadata rows only. It does not download malware, execute samples, unpack archives, open paths referenced inside dataset rows, quarantine files, delete files, or upload raw contents.",
        "",
        "## Outputs",
        "",
    ]
    for name, value in sorted((summary.get("reports") or {}).items()):
        if value:
            lines.append(f"- `{name}`: `{value}`")
    path.write_text("\n".join(lines), encoding="utf-8")


def run_safe_dataset_dry_run(
    input_path: str,
    output_dir: str = "out/safe_dataset_dry_run",
    clean_output: bool = False,
    source: str = "external",
    input_format: str = "auto",
    limit: Optional[int] = None,
    preview_limit: int = 50,
    write_safe_jsonl: bool = False,
    strict_path_fields: bool = True,
    allow_url_metadata: bool = False,
    bundle_output: bool = False,
    bundle_path: Optional[str] = None,
    privacy_bundle: bool = True,
    redact_paths: bool = True,
    path_redaction_mode: str = "basename",
) -> Dict[str, Any]:
    """Validate/normalize an external feature-only JSONL/CSV dataset locally."""
    inp = Path(input_path).expanduser()
    _validate_input_path(inp)
    out = Path(output_dir)
    if clean_output and out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    accepted: List[Dict[str, Any]] = []
    accepted_preview: List[Dict[str, Any]] = []
    rejections: List[Dict[str, Any]] = []
    warning_count = 0
    rows_seen = 0
    max_limit = None if limit is None else max(0, int(limit))

    for row_index, row in enumerate(_iter_rows(inp, input_format=input_format), start=1):
        if max_limit is not None and rows_seen >= max_limit:
            break
        rows_seen += 1
        if "__poole_parse_error__" in row:
            rejections.append({
                "row_index": row_index,
                "sample_id": "",
                "label": "unknown",
                "errors": row.get("__poole_parse_error__"),
                "warnings": "",
                "row_keys": "",
            })
            continue
        errors, warnings = validate_external_feature_row(
            row,
            row_index=row_index,
            strict_path_fields=strict_path_fields,
            allow_url_metadata=allow_url_metadata,
        )
        if warnings:
            warning_count += 1
        if errors:
            rejections.append({
                "row_index": row_index,
                "sample_id": _safe_sample_id(row, source, row_index),
                "label": _row_label(row),
                "errors": "; ".join(errors),
                "warnings": "; ".join(warnings),
                "row_keys": _row_key_list(row),
            })
            continue
        normalized = _normalize_external_row(row, source=source, row_index=row_index)
        validation = normalized.get("validation") or {}
        if not validation.get("valid", True):
            rejections.append({
                "row_index": row_index,
                "sample_id": normalized.get("sample_id", ""),
                "label": normalized.get("label", "unknown"),
                "errors": "; ".join(validation.get("errors", [])),
                "warnings": "; ".join((validation.get("warnings", []) or []) + warnings),
                "row_keys": _row_key_list(row),
            })
            continue
        accepted.append(normalized)
        if len(accepted_preview) < max(0, int(preview_limit)):
            accepted_preview.append(normalized)

    safe_jsonl_path = out / "safe_external_dataset.jsonl"
    preview_path = out / "safe_external_dataset_preview.jsonl"
    rejections_csv = out / "safe_external_dataset_rejections.csv"
    report_json = out / "SAFE_DATASET_DRY_RUN.json"
    report_md = out / "SAFE_DATASET_DRY_RUN.md"

    if write_safe_jsonl:
        write_jsonl(safe_jsonl_path, accepted)
    write_jsonl(preview_path, accepted_preview)
    _write_rejection_csv(rejections_csv, rejections)

    summary: Dict[str, Any] = {
        "tool": "PooleShield safe external dataset dry run",
        "version": VERSION,
        "schema_version": SCHEMA_VERSION,
        "mode": "safe-dataset-dry-run",
        "generated_at": _utc_now(),
        "input_display": inp.name,
        "input_suffix": inp.suffix.lower(),
        "input_path_sha256": hashlib.sha256(str(inp).encode("utf-8", errors="replace")).hexdigest().upper(),
        "source": source,
        "output_dir": str(out),
        "rows_seen": rows_seen,
        "accepted_count": len(accepted),
        "rejected_count": len(rejections),
        "warning_count": warning_count,
        "record_summary": summarize_records(accepted),
        "write_safe_jsonl": bool(write_safe_jsonl),
        "strict_path_fields": bool(strict_path_fields),
        "allow_url_metadata": bool(allow_url_metadata),
        "reports": {
            "json": str(report_json),
            "md": str(report_md),
            "accepted_preview_jsonl": str(preview_path),
            "safe_jsonl": str(safe_jsonl_path) if write_safe_jsonl else "",
            "rejections_csv": str(rejections_csv),
        },
        "safety_boundary": {
            "features_only": True,
            "raw_binaries_loaded": False,
            "row_referenced_paths_opened": False,
            "malware_samples_downloaded": False,
            "archives_unpacked": False,
            "artifacts_executed": False,
            "files_deleted": False,
            "files_quarantined": False,
            "network_uploads": False,
        },
        "accepted_preview": accepted_preview,
        "rejections_preview": rejections[:100],
    }

    report_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    _write_report_md(report_md, summary)

    if bundle_output:
        bundle = bundle_output_dir(
            str(out),
            bundle_path or str(out / "pooleshield_results_bundle.zip"),
            privacy_mode=privacy_bundle,
            redact_paths=redact_paths,
            path_redaction_mode=path_redaction_mode,
        )
        summary["bundle_summary"] = {
            "bundle_path": bundle.get("bundle_path"),
            "bundle_size_bytes": bundle.get("bundle_size_bytes"),
            "file_count": bundle.get("file_count"),
            "manifest_name": bundle.get("manifest_name"),
            "privacy_mode": bundle.get("privacy_mode"),
            "redact_paths": bundle.get("redact_paths"),
            "path_redaction_mode": bundle.get("path_redaction_mode"),
            "excluded_content_files": bundle.get("excluded_content_files"),
        }
        summary["result_bundle"] = bundle.get("bundle_path")
        report_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
        _write_report_md(report_md, summary)
        bundle_output_dir(
            str(out),
            bundle_path or str(out / "pooleshield_results_bundle.zip"),
            privacy_mode=privacy_bundle,
            redact_paths=redact_paths,
            path_redaction_mode=path_redaction_mode,
        )
    return summary


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="PooleShield safe external feature-only dataset dry run")
    parser.add_argument("--input", required=True, help="External feature-only JSONL/CSV file")
    parser.add_argument("--output-dir", default="out/safe_dataset_dry_run")
    parser.add_argument("--clean-output", action="store_true")
    parser.add_argument("--source", default="external")
    parser.add_argument("--format", choices=["auto", "jsonl", "csv"], default="auto")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--preview-limit", type=int, default=50)
    parser.add_argument("--write-safe-jsonl", action="store_true")
    parser.add_argument("--allow-path-fields", action="store_true", help="Do not reject non-sample path-like metadata; still never opens row paths")
    parser.add_argument("--allow-url-metadata", action="store_true", help="Allow URL-like metadata as ignored metadata; never fetches URLs")
    parser.add_argument("--bundle-output", action="store_true")
    parser.add_argument("--bundle-path", default=None)
    parser.add_argument("--privacy-bundle", action="store_true", default=True)
    parser.add_argument("--no-redact-paths", action="store_true")
    parser.add_argument("--path-redaction-mode", choices=["basename", "hash", "relative"], default="basename")
    args = parser.parse_args()
    summary = run_safe_dataset_dry_run(
        input_path=args.input,
        output_dir=args.output_dir,
        clean_output=args.clean_output,
        source=args.source,
        input_format=args.format,
        limit=args.limit,
        preview_limit=args.preview_limit,
        write_safe_jsonl=args.write_safe_jsonl,
        strict_path_fields=not args.allow_path_fields,
        allow_url_metadata=args.allow_url_metadata,
        bundle_output=args.bundle_output,
        bundle_path=args.bundle_path,
        privacy_bundle=args.privacy_bundle,
        redact_paths=not args.no_redact_paths,
        path_redaction_mode=args.path_redaction_mode,
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
