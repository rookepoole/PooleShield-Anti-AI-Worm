#!/usr/bin/env python3
"""
PooleShield v1.8 local-only DAT text extractor.

Defensive purpose:
  Convert only text-like/json-like `.dat` blobs from ChatGPT/export folders into
  local `.txt`/`.json` fixture files that PooleShield can scan.

Safety boundary:
  - Does not execute files.
  - Does not extract binary DAT files.
  - Does not unpack nested archives.
  - Does not upload or bundle decoded content when privacy bundles are used.
  - Writes decoded text only to the operator's local output directory.
"""
from __future__ import annotations

import csv
import datetime as dt
import hashlib
import json
import re
import shutil
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from adapter_dat_files import classify_dat, iter_local_dat_files, inspect_dat_paths

VERSION = "2.0"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def safe_stem(value: str, max_len: int = 80) -> str:
    value = value.replace("\\", "/").split("/")[-1]
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value)
    value = value.strip("._-") or "dat_entry"
    if len(value) > max_len:
        value = value[:max_len]
    return value


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode_full_text(data: bytes, preferred: str = "utf-8") -> Tuple[str, str, bool]:
    encodings = []
    if preferred:
        encodings.append(preferred)
    encodings += ["utf-8", "utf-8-sig", "cp1252", "latin-1"]
    seen = set()
    for enc in encodings:
        if enc in seen:
            continue
        seen.add(enc)
        try:
            return data.decode(enc, errors="strict"), enc, True
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace"), "utf-8-replace", False


def iter_candidate_sources(paths: Sequence[str], recursive: bool = True) -> Iterator[Dict[str, Any]]:
    """Yield local DAT files and DAT entries from ZIP archives without extracting binaries."""
    for raw in paths:
        root = Path(raw).expanduser().resolve()
        if not root.exists():
            yield {"source_kind": "missing", "path": raw, "resolved_path": str(root)}
            continue
        if root.is_dir():
            for p in iter_local_dat_files(root, recursive=recursive):
                yield {"source_kind": "file", "path": str(p), "container_path": "", "entry_name": "", "name": p.name, "size_bytes": p.stat().st_size}
            zips = list(root.rglob("*.zip") if recursive else root.glob("*.zip"))
            for zp in zips:
                yield from iter_zip_dat_sources(zp)
        elif root.is_file() and root.suffix.lower() == ".dat":
            yield {"source_kind": "file", "path": str(root), "container_path": "", "entry_name": "", "name": root.name, "size_bytes": root.stat().st_size}
        elif root.is_file() and root.suffix.lower() == ".zip":
            yield from iter_zip_dat_sources(root)
        else:
            yield {"source_kind": "unsupported", "path": str(root), "resolved_path": str(root), "name": root.name}


def iter_zip_dat_sources(zip_path: Path) -> Iterator[Dict[str, Any]]:
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir() or not info.filename.lower().endswith(".dat"):
                    continue
                yield {
                    "source_kind": "zip_entry",
                    "path": f"{zip_path}!{info.filename}",
                    "container_path": str(zip_path),
                    "entry_name": info.filename,
                    "name": Path(info.filename).name,
                    "size_bytes": info.file_size,
                    "compressed_size_bytes": info.compress_size,
                }
    except Exception as exc:
        yield {"source_kind": "zip_error", "path": str(zip_path), "error": str(exc), "name": zip_path.name}


def read_source_bytes(source: Dict[str, Any], max_bytes: int) -> Tuple[Optional[bytes], str]:
    kind = source.get("source_kind")
    size = int(source.get("size_bytes") or 0)
    if size > max_bytes:
        return None, f"too_large:{size}>{max_bytes}"
    try:
        if kind == "file":
            return Path(source["path"]).read_bytes(), ""
        if kind == "zip_entry":
            with zipfile.ZipFile(source["container_path"], "r") as zf:
                return zf.read(source["entry_name"]), ""
    except Exception as exc:
        return None, f"read_error:{exc}"
    return None, f"unsupported_source_kind:{kind}"


def make_output_name(index: int, source: Dict[str, Any], likely_type: str, content_hash: str) -> str:
    stem = safe_stem(source.get("name") or source.get("entry_name") or f"dat_{index:04d}")
    ext = ".json" if likely_type == "json_text" else ".txt"
    return f"{index:04d}_{stem}_{content_hash[:10]}{ext}"


def run_dat_extract(
    paths: Sequence[str],
    output_dir: str = "out/dat_extract",
    clean_output: bool = False,
    recursive: bool = True,
    sample_bytes: int = 16384,
    max_files: int = 200,
    max_bytes_per_file: int = 5 * 1024 * 1024,
    include_plain_text: bool = True,
    include_json_text: bool = True,
    start_index: int = 0,
    bundle_output: bool = False,
    bundle_path: Optional[str] = None,
    privacy_bundle: bool = True,
) -> Dict[str, Any]:
    from result_bundler import bundle_output_dir

    out = Path(output_dir)
    if clean_output and out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)
    extracted_dir = out / "extracted_dat_text"
    extracted_dir.mkdir(parents=True, exist_ok=True)

    rows: List[Dict[str, Any]] = []
    extracted_count = 0
    skipped_count = 0
    source_count = 0
    extractable_seen = 0
    start_index = max(0, int(start_index or 0))
    max_files = max(0, int(max_files or 0))
    now = utc_now()

    for source in iter_candidate_sources(paths, recursive=recursive):
        source_count += 1
        row: Dict[str, Any] = {
            "source_kind": source.get("source_kind"),
            "path": source.get("path", ""),
            "container_path": source.get("container_path", ""),
            "entry_name": source.get("entry_name", ""),
            "name": source.get("name", ""),
            "size_bytes": source.get("size_bytes", 0),
            "extracted": False,
            "output_path": "",
            "skip_reason": "",
            "likely_type": "",
            "magic_type": "",
            "sha256": "",
            "encoding": "",
            "strict_decode": "",
        }
        if source.get("source_kind") in {"missing", "unsupported", "zip_error"}:
            row["skip_reason"] = source.get("error") or source.get("source_kind")
            skipped_count += 1
            rows.append(row)
            continue
        data, error = read_source_bytes(source, max_bytes=max_bytes_per_file)
        if data is None:
            row["skip_reason"] = error
            skipped_count += 1
            rows.append(row)
            continue
        sample = data[:sample_bytes]
        meta = classify_dat(sample, source.get("name", ""))
        row.update({
            "likely_type": meta.get("likely_type"),
            "magic_type": meta.get("magic_type"),
            "encoding": meta.get("encoding_guess"),
            "strict_decode": meta.get("strict_decode"),
            "text_like": meta.get("text_like"),
            "json_like": meta.get("json_like"),
            "sha256": sha256_bytes(data),
        })
        likely = meta.get("likely_type")
        should_extract = (likely == "json_text" and include_json_text) or (likely == "plain_text" and include_plain_text)
        if not should_extract:
            row["skip_reason"] = f"not_selected_or_not_text:{likely}"
            skipped_count += 1
            rows.append(row)
            continue

        current_extractable_index = extractable_seen
        row["extractable_index"] = current_extractable_index
        extractable_seen += 1

        if current_extractable_index < start_index:
            row["skip_reason"] = f"before_start_index:{current_extractable_index}<{start_index}"
            skipped_count += 1
            rows.append(row)
            continue
        if extracted_count >= max_files:
            row["skip_reason"] = f"batch_limit_reached:{max_files}"
            skipped_count += 1
            rows.append(row)
            continue
        text, enc, strict = decode_full_text(data, preferred=str(meta.get("encoding_guess") or "utf-8"))
        output_name = make_output_name(start_index + extracted_count + 1, source, likely, row["sha256"])
        output_path = extracted_dir / output_name
        output_path.write_text(text, encoding="utf-8", errors="replace")
        row.update({
            "extracted": True,
            "output_path": str(output_path),
            "output_name": output_name,
            "encoding": enc,
            "strict_decode": strict,
            "skip_reason": "",
            "content_chars": len(text),
        })
        extracted_count += 1
        rows.append(row)

    by_likely: Dict[str, int] = {}
    by_extracted_type: Dict[str, int] = {}
    for row in rows:
        lt = row.get("likely_type") or row.get("source_kind") or "unknown"
        by_likely[lt] = by_likely.get(lt, 0) + 1
        if row.get("extracted"):
            by_extracted_type[lt] = by_extracted_type.get(lt, 0) + 1

    manifest = {
        "tool": "PooleShield DAT extractor",
        "version": VERSION,
        "generated_at": now,
        "mode": "dat-extract",
        "paths": list(paths),
        "output_dir": str(out),
        "extracted_dir": str(extracted_dir),
        "recursive": recursive,
        "sample_bytes": sample_bytes,
        "max_files": max_files,
        "start_index": start_index,
        "next_start_index": start_index + extracted_count,
        "max_bytes_per_file": max_bytes_per_file,
        "summary": {
            "source_items_seen": source_count,
            "rows": len(rows),
            "extractable_candidates_seen": extractable_seen,
            "start_index": start_index,
            "batch_size": max_files,
            "next_start_index": start_index + extracted_count,
            "remaining_extractable_estimate": max(0, extractable_seen - (start_index + extracted_count)),
            "extracted_files": extracted_count,
            "skipped_items": skipped_count,
            "by_likely_type": dict(sorted(by_likely.items())),
            "by_extracted_type": dict(sorted(by_extracted_type.items())),
            "privacy_note": "Extracted text/json files are local output. Use --privacy-bundle to exclude extracted_dat_text from upload bundles.",
        },
        "rows": rows,
    }

    manifest_json = out / "dat_extract_manifest.json"
    manifest_csv = out / "dat_extract_manifest.csv"
    manifest_md = out / "dat_extract_manifest.md"
    run_summary_json = out / "RUN_SUMMARY.json"

    manifest_json.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    with manifest_csv.open("w", encoding="utf-8", newline="") as f:
        fields = [
            "source_kind", "path", "container_path", "entry_name", "name", "size_bytes",
            "likely_type", "magic_type", "text_like", "json_like", "sha256", "extracted",
            "output_path", "skip_reason", "content_chars", "extractable_index",
        ]
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    lines = [
        "# PooleShield DAT Extraction",
        "",
        f"Version: {VERSION}",
        f"Generated: {now}",
        "",
        "## Summary",
        "",
        f"Source items seen: `{source_count}`",
        f"Extractable candidates seen: `{extractable_seen}`",
        f"Start index: `{start_index}`",
        f"Batch size: `{max_files}`",
        f"Extracted files: `{extracted_count}`",
        f"Next start index: `{start_index + extracted_count}`",
        f"Skipped items: `{skipped_count}`",
        f"By likely type: `{dict(sorted(by_likely.items()))}`",
        f"By extracted type: `{dict(sorted(by_extracted_type.items()))}`",
        "",
        "## Privacy note",
        "",
        "Decoded DAT content is written only under `extracted_dat_text/`. Use `--privacy-bundle` so decoded text is excluded from upload bundles.",
        "",
        "## Next command",
        "",
        "```powershell",
        f"python .\\pooleshield_operator.py chat-scan --path \"{extracted_dir}\" --output-dir .\\out\\dat_chat_scan --clean-output --policy-profile balanced --bundle-output --privacy-bundle",
        "```",
        "",
        "## Extracted files",
        "",
    ]
    for row in rows:
        if row.get("extracted"):
            lines.append(f"- `{row.get('output_name')}` from `{row.get('path')}`")
    manifest_md.write_text("\n".join(lines), encoding="utf-8")

    run_summary = {
        "tool": "PooleShield DAT extractor",
        "version": VERSION,
        "mode": "dat-extract",
        "output_dir": str(out),
        "dat_extract_manifest": str(manifest_json),
        "summary": manifest["summary"],
        "extracted_dir": str(extracted_dir),
        "start_index": start_index,
        "batch_size": max_files,
        "next_start_index": start_index + extracted_count,
        "next_command": f'python .\\pooleshield_operator.py chat-scan --path "{extracted_dir}" --output-dir .\\out\\dat_chat_scan --clean-output --policy-profile balanced --bundle-output --privacy-bundle',
        "result_bundle": "",
        "bundle_summary": None,
    }
    if bundle_output:
        bundle_report = bundle_output_dir(str(out), bundle_path or str(out / "pooleshield_results_bundle.zip"), privacy_mode=privacy_bundle)
        run_summary["result_bundle"] = bundle_report.get("bundle_path", "")
        run_summary["bundle_summary"] = {
            "bundle_path": bundle_report.get("bundle_path"),
            "bundle_size_bytes": bundle_report.get("bundle_size_bytes"),
            "file_count": bundle_report.get("file_count"),
            "privacy_mode": bundle_report.get("privacy_mode"),
            "excluded_content_files": bundle_report.get("excluded_content_files"),
        }
    run_summary_json.write_text(json.dumps(run_summary, indent=2, ensure_ascii=False), encoding="utf-8")
    return run_summary


def main(argv: Optional[Sequence[str]] = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="PooleShield v1.8 local-only DAT text extractor")
    parser.add_argument("--path", "-p", nargs="+", required=True)
    parser.add_argument("--output-dir", default="out/dat_extract")
    parser.add_argument("--clean-output", action="store_true")
    parser.add_argument("--no-recursive", action="store_true")
    parser.add_argument("--sample-bytes", type=int, default=16384)
    parser.add_argument("--max-files", type=int, default=200)
    parser.add_argument("--start-index", type=int, default=0, help="Skip this many eligible text/json DAT blobs before extracting the batch")
    parser.add_argument("--max-bytes-per-file", type=int, default=5 * 1024 * 1024)
    parser.add_argument("--json-only", action="store_true", help="Extract only JSON-like DAT blobs")
    parser.add_argument("--bundle-output", action="store_true")
    parser.add_argument("--bundle-path", default=None)
    parser.add_argument("--privacy-bundle", action="store_true", default=True)
    args = parser.parse_args()
    report = run_dat_extract(
        paths=args.path,
        output_dir=args.output_dir,
        clean_output=args.clean_output,
        recursive=not args.no_recursive,
        sample_bytes=args.sample_bytes,
        max_files=args.max_files,
        max_bytes_per_file=args.max_bytes_per_file,
        include_plain_text=not args.json_only,
        include_json_text=True,
        start_index=args.start_index,
        bundle_output=args.bundle_output,
        bundle_path=args.bundle_path,
        privacy_bundle=args.privacy_bundle,
    )
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
