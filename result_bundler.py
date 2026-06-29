#!/usr/bin/env python3
"""
PooleShield result bundler.

Defensive purpose:
  Create a single ZIP archive containing PooleShield reports so operators can
  upload/share one artifact instead of many JSON/CSV/Markdown files.

Safety boundary:
  This module only reads report files from an output directory and writes a ZIP.
  It does not execute, quarantine, delete, or modify scanned content.
"""
from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

VERSION = "3.9.0"

DEFAULT_EXCLUDE_DIRS = {"__pycache__", ".git", ".venv", "venv", "node_modules"}
DEFAULT_INCLUDE_SUFFIXES = {
    ".json",
    ".jsonl",
    ".csv",
    ".md",
    ".txt",
    ".log",
}

GENERATED_BUNDLE_FILE_NAMES = {
    "BUNDLE_MANIFEST.json",
    "PRIVACY_BUNDLE_NOTE.md",
}

# Files with normalized raw event content can include excerpts from scanned
# chats/logs. Privacy bundles exclude them so an operator can share the
# decisions, hashes, and summary reports without uploading full chat content.
CONTENT_BEARING_NAME_PATTERNS = [
    "pooleshield_scan_history.sqlite",
    "pooleshield_history.sqlite",
    "normalized_events.jsonl",
    "review_evidence_local.md",
    # v2.0 privacy fix: the full evidence JSON can contain redacted
    # snippet context, so privacy bundles must exclude it too.
    "review_evidence_report.json",
    # v3.2 local trust DB can expose local path/hash inventory; keep it local by default.
    "trusted_file_baseline.json",
    "trusted_file_baseline.csv",
    "trusted_file_baseline.md",
]

CONTENT_BEARING_DIR_NAMES = {
    "extracted_dat_text",
    "extracted_dat_content",
    "extracted_text_like",
}


def is_content_bearing(path: Path) -> bool:
    parts = {part.lower() for part in path.parts}
    if parts.intersection(CONTENT_BEARING_DIR_NAMES):
        return True
    name = path.name.lower()
    if path.suffix.lower() in {".sqlite", ".sqlite3", ".db"}:
        return True
    if name in CONTENT_BEARING_NAME_PATTERNS:
        return True
    if name.endswith(".jsonl") and "normalized" in name and "event" in name:
        return True
    return False


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def iter_bundle_files(output_dir: Path, bundle_path: Path, privacy_mode: bool = False) -> Tuple[List[Path], List[str]]:
    """Return files to bundle and privacy-excluded relative paths."""
    output_dir = output_dir.resolve()
    bundle_path = bundle_path.resolve()
    selected: List[Path] = []
    excluded_content: List[str] = []
    for path in sorted(output_dir.rglob("*")):
        if path.is_dir():
            continue
        if any(part in DEFAULT_EXCLUDE_DIRS for part in path.parts):
            continue
        if path.resolve() == bundle_path:
            continue
        if path.name in GENERATED_BUNDLE_FILE_NAMES:
            continue
        if path.name.endswith(".zip"):
            continue
        if path.suffix.lower() not in DEFAULT_INCLUDE_SUFFIXES:
            continue
        if privacy_mode and is_content_bearing(path):
            excluded_content.append(path.relative_to(output_dir).as_posix())
            continue
        selected.append(path)
    return selected, excluded_content


def bundle_output_dir(
    output_dir: str,
    bundle_path: Optional[str] = None,
    manifest_name: str = "BUNDLE_MANIFEST.json",
    privacy_mode: bool = False,
) -> Dict[str, Any]:
    out = Path(output_dir).resolve()
    if not out.exists():
        raise FileNotFoundError(f"Output directory does not exist: {out}")
    if not out.is_dir():
        raise NotADirectoryError(f"Output path is not a directory: {out}")

    bundle = Path(bundle_path) if bundle_path else out / "pooleshield_results_bundle.zip"
    if not bundle.is_absolute():
        bundle = Path.cwd() / bundle
    bundle.parent.mkdir(parents=True, exist_ok=True)

    files, excluded_content_files = iter_bundle_files(out, bundle, privacy_mode=privacy_mode)
    created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    manifest_entries: List[Dict[str, Any]] = []

    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in files:
            rel = path.relative_to(out).as_posix()
            digest = sha256_file(path)
            manifest_entries.append({
                "path": rel,
                "size_bytes": path.stat().st_size,
                "sha256": digest,
            })
            zf.write(path, rel)
        if privacy_mode:
            note = (
                "# PooleShield Privacy Bundle\n\n"
                "This bundle was created with privacy_mode=true. Content-bearing normalized JSONL/event files "
                "and local review-evidence files were excluded so reports can be shared without uploading "
                "full scanned chat/log text or matched snippet context. Policy decisions, risk scores, "
                "labels, hashes, source paths, and review metadata remain.\n"
            ).encode("utf-8")
            manifest_entries.append({
                "path": "PRIVACY_BUNDLE_NOTE.md",
                "size_bytes": len(note),
                "sha256": hashlib.sha256(note).hexdigest(),
                "generated": True,
            })
            zf.writestr("PRIVACY_BUNDLE_NOTE.md", note)

        manifest = {
            "tool": "PooleShield result bundle",
            "version": VERSION,
            "generated_at": created_at,
            "output_dir": str(out),
            "bundle_path": str(bundle),
            "privacy_mode": privacy_mode,
            "excluded_content_files": excluded_content_files,
            "file_count": len(manifest_entries),
            "files": manifest_entries,
        }
        zf.writestr(manifest_name, json.dumps(manifest, indent=2, ensure_ascii=False))

    return {
        "tool": "PooleShield result bundle",
        "version": VERSION,
        "generated_at": created_at,
        "output_dir": str(out),
        "bundle_path": str(bundle),
        "bundle_size_bytes": bundle.stat().st_size,
        "file_count": len(manifest_entries),
        "manifest_name": manifest_name,
        "privacy_mode": privacy_mode,
        "excluded_content_files": excluded_content_files,
        "files": manifest_entries,
    }


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Create a single ZIP from a PooleShield output directory")
    parser.add_argument("--output-dir", required=True, help="PooleShield output folder to bundle")
    parser.add_argument("--bundle-path", default=None, help="Optional ZIP path. Default: <output-dir>/pooleshield_results_bundle.zip")
    parser.add_argument("--privacy-bundle", action="store_true", help="Exclude content-bearing normalized event JSONL files")
    args = parser.parse_args()
    report = bundle_output_dir(args.output_dir, args.bundle_path, privacy_mode=args.privacy_bundle)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
