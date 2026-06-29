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
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

VERSION = "5.4.2"

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

PATH_REDACTION_MODES = {"basename", "hash", "relative"}
# Match common local absolute paths in JSON/CSV/Markdown/text. The Windows
# pattern intentionally handles JSON-escaped backslashes (C:\\Users\\...) too.
WINDOWS_PATH_RE = re.compile(r"(?i)[a-z]:(?:\\+|/+)(?:users|documents and settings)(?:\\+|/+)[^\r\n\"'`<>]+")
WINDOWS_GENERIC_PATH_RE = re.compile(r"(?i)[a-z]:(?:\\+|/+)[^\r\n\"'`<>]+")
POSIX_HOME_PATH_RE = re.compile(r"(?i)/(?:users|home)/[^\s\r\n\"'`<>]+")


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


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


def _normalize_mode(path_redaction_mode: str) -> str:
    mode = (path_redaction_mode or "basename").strip().lower()
    if mode not in PATH_REDACTION_MODES:
        raise ValueError(f"unsupported path redaction mode: {path_redaction_mode}; expected basename, hash, or relative")
    return mode


def _redaction_token(raw: str, mode: str) -> str:
    normalized = raw.replace("\\\\", "\\").replace("/", "\\")
    parts = [p for p in re.split(r"[\\/]+", normalized) if p]
    tail = parts[-1] if parts else "path"
    if mode == "hash":
        digest = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest().upper()[:16]
        return f"<LOCAL_PATH_SHA256:{digest}>"
    if mode == "relative":
        if len(parts) >= 2:
            return "<LOCAL_PATH>/" + "/".join(parts[-2:])
        return f"<LOCAL_PATH>/{tail}"
    return f"<LOCAL_PATH:{tail}>"


def redact_local_paths_in_text(text: str, mode: str = "basename") -> str:
    """Redact local absolute path strings from bundle copies of report text."""
    safe_mode = _normalize_mode(mode)

    def repl(match: re.Match[str]) -> str:
        return _redaction_token(match.group(0), safe_mode)

    out = WINDOWS_PATH_RE.sub(repl, text)
    out = WINDOWS_GENERIC_PATH_RE.sub(repl, out)
    out = POSIX_HOME_PATH_RE.sub(repl, out)
    return out


def _looks_like_path_string(value: str) -> bool:
    return bool(WINDOWS_PATH_RE.search(value) or WINDOWS_GENERIC_PATH_RE.search(value) or POSIX_HOME_PATH_RE.search(value))


def redact_local_paths_in_obj(value: Any, mode: str = "basename") -> Any:
    if isinstance(value, dict):
        return {k: redact_local_paths_in_obj(v, mode=mode) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_local_paths_in_obj(v, mode=mode) for v in value]
    if isinstance(value, str) and _looks_like_path_string(value):
        return redact_local_paths_in_text(value, mode=mode)
    return value


def _maybe_redacted_file_bytes(path: Path, *, redact_paths: bool, path_redaction_mode: str) -> Tuple[bytes, bool]:
    data = path.read_bytes()
    if not redact_paths or path.suffix.lower() not in DEFAULT_INCLUDE_SUFFIXES:
        return data, False
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data, False
    redacted = text
    if path.suffix.lower() == ".json":
        try:
            payload = json.loads(text)
            payload = redact_local_paths_in_obj(payload, mode=path_redaction_mode)
            redacted = json.dumps(payload, indent=2, ensure_ascii=False)
        except Exception:
            redacted = redact_local_paths_in_text(text, mode=path_redaction_mode)
    else:
        redacted = redact_local_paths_in_text(text, mode=path_redaction_mode)
    if redacted == text:
        return data, False
    return redacted.encode("utf-8"), True


def bundle_output_dir(
    output_dir: str,
    bundle_path: Optional[str] = None,
    manifest_name: str = "BUNDLE_MANIFEST.json",
    privacy_mode: bool = False,
    redact_paths: bool = False,
    path_redaction_mode: str = "basename",
) -> Dict[str, Any]:
    out = Path(output_dir).resolve()
    if not out.exists():
        raise FileNotFoundError(f"Output directory does not exist: {out}")
    if not out.is_dir():
        raise NotADirectoryError(f"Output path is not a directory: {out}")

    mode = _normalize_mode(path_redaction_mode)
    bundle = Path(bundle_path) if bundle_path else out / "pooleshield_results_bundle.zip"
    if not bundle.is_absolute():
        bundle = Path.cwd() / bundle
    bundle.parent.mkdir(parents=True, exist_ok=True)

    files, excluded_content_files = iter_bundle_files(out, bundle, privacy_mode=privacy_mode)
    created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    manifest_entries: List[Dict[str, Any]] = []
    redacted_file_count = 0

    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in files:
            rel = path.relative_to(out).as_posix()
            file_bytes, was_redacted = _maybe_redacted_file_bytes(path, redact_paths=redact_paths, path_redaction_mode=mode)
            if was_redacted:
                redacted_file_count += 1
            manifest_entries.append({
                "path": rel,
                "size_bytes": len(file_bytes),
                "sha256": sha256_bytes(file_bytes),
                "path_redacted": bool(was_redacted),
            })
            zf.writestr(rel, file_bytes)
        if privacy_mode:
            note_text = (
                "# PooleShield Privacy Bundle\n\n"
                "This bundle was created with privacy_mode=true. Content-bearing normalized JSONL/event files "
                "and local review-evidence files were excluded so reports can be shared without uploading "
                "full scanned chat/log text or matched snippet context. Policy decisions, risk scores, "
                "labels, hashes, source paths, and review metadata remain.\n"
            )
            if redact_paths:
                note_text += "\nLocal absolute paths were redacted in bundle copies of text reports.\n"
            note = note_text.encode("utf-8")
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
            "output_dir": redact_local_paths_in_text(str(out), mode=mode) if redact_paths else str(out),
            "bundle_path": redact_local_paths_in_text(str(bundle), mode=mode) if redact_paths else str(bundle),
            "privacy_mode": privacy_mode,
            "redact_paths": bool(redact_paths),
            "path_redaction_mode": mode if redact_paths else "none",
            "redacted_file_count": redacted_file_count,
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
        "redact_paths": bool(redact_paths),
        "path_redaction_mode": mode if redact_paths else "none",
        "redacted_file_count": redacted_file_count,
        "excluded_content_files": excluded_content_files,
        "files": manifest_entries,
    }


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Create a single ZIP from a PooleShield output directory")
    parser.add_argument("--output-dir", required=True, help="PooleShield output folder to bundle")
    parser.add_argument("--bundle-path", default=None, help="Optional ZIP path. Default: <output-dir>/pooleshield_results_bundle.zip")
    parser.add_argument("--privacy-bundle", action="store_true", help="Exclude content-bearing normalized event JSONL files")
    parser.add_argument("--redact-paths", action="store_true", help="Redact local absolute paths in bundled text/JSON reports")
    parser.add_argument("--path-redaction-mode", choices=sorted(PATH_REDACTION_MODES), default="basename")
    args = parser.parse_args()
    report = bundle_output_dir(
        args.output_dir,
        args.bundle_path,
        privacy_mode=args.privacy_bundle,
        redact_paths=args.redact_paths,
        path_redaction_mode=args.path_redaction_mode,
    )
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
