#!/usr/bin/env python3
"""
PooleShield v1.8 DAT inspector.

Defensive purpose:
  Chat/export bundles can contain opaque `.dat` blobs rather than friendly
  `conversations.json` files. This inspector inventories those blobs safely so
  operators can decide what is text-like, JSON-like, image/PDF/archive-like, or
  unsupported binary before attempting a scan.

Safety boundary:
  This module does not execute files, follow links, call APIs, decrypt data, or
  unpack nested content into runnable form. It reads metadata and small samples,
  computes hashes, and writes inventory reports only.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import math
import re
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

VERSION = "2.0"

TEXT_EXT_HINTS = {".txt", ".md", ".json", ".jsonl", ".csv", ".log", ".html", ".xml", ".yaml", ".yml"}
DAT_SUFFIX = ".dat"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_zip_entry(zf: zipfile.ZipFile, name: str) -> str:
    h = hashlib.sha256()
    with zf.open(name, "r") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def guess_magic(data: bytes, name: str = "") -> str:
    if not data:
        return "empty"
    lower = name.lower()
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return "gif"
    if data.startswith(b"%PDF-"):
        return "pdf"
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06") or data.startswith(b"PK\x07\x08"):
        return "zip"
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    if data.startswith(b"SQLite format 3\x00"):
        return "sqlite"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if data.lstrip()[:1] in {b"{", b"["}:
        return "json_or_text"
    if lower.endswith(".dat"):
        # Keep magic conservative; text_like fields below carry the stronger signal.
        return "dat_unknown"
    return "unknown"


def decode_text_sample(data: bytes) -> Tuple[str, str, bool]:
    for enc in ("utf-8", "utf-8-sig", "cp1252", "latin-1"):
        try:
            return data.decode(enc, errors="strict"), enc, True
        except UnicodeDecodeError:
            continue
    try:
        return data.decode("utf-8", errors="replace"), "utf-8-replace", False
    except Exception:
        return "", "binary", False


def printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable = 0
    for ch in text:
        if ch in "\n\r\t" or (ord(ch) >= 32 and ord(ch) != 127):
            printable += 1
    return printable / max(1, len(text))


def looks_json(text: str) -> bool:
    s = text.strip()
    if not s or s[0] not in "{[":
        return False
    try:
        json.loads(s[:2_000_000])
        return True
    except Exception:
        # Some samples are truncated. A leading JSON marker plus common keys is still useful.
        return bool(re.search(r'"(mapping|messages|conversations|content|author|role|message)"\s*:', s[:2000], re.I))


def classify_dat(data: bytes, name: str = "") -> Dict[str, Any]:
    magic = guess_magic(data, name)
    text, enc, strict_decode = decode_text_sample(data)
    ratio = printable_ratio(text)
    has_nul = b"\x00" in data[:4096]
    text_like = (not has_nul) and (ratio >= 0.88) and magic not in {"png", "jpeg", "gif", "pdf", "zip", "gzip", "sqlite", "webp"}
    json_like = text_like and looks_json(text)
    if magic == "json_or_text" and json_like:
        likely_type = "json_text"
    elif json_like:
        likely_type = "json_text"
    elif text_like:
        likely_type = "plain_text"
    elif magic in {"png", "jpeg", "gif", "webp"}:
        likely_type = "image_binary"
    elif magic == "pdf":
        likely_type = "pdf_binary"
    elif magic in {"zip", "gzip"}:
        likely_type = "archive_binary"
    elif magic == "sqlite":
        likely_type = "database_binary"
    elif magic == "empty":
        likely_type = "empty"
    else:
        likely_type = "unknown_binary"
    return {
        "magic_type": magic,
        "likely_type": likely_type,
        "encoding_guess": enc,
        "strict_decode": strict_decode,
        "printable_ratio": round(ratio, 4),
        "has_nul_byte": has_nul,
        "text_like": text_like,
        "json_like": json_like,
    }


def iter_local_dat_files(root: Path, recursive: bool = True) -> Iterator[Path]:
    if root.is_file():
        if root.suffix.lower() == DAT_SUFFIX:
            yield root
        return
    walker = root.rglob("*") if recursive else root.glob("*")
    for p in walker:
        if p.is_file() and p.suffix.lower() == DAT_SUFFIX:
            yield p


def inspect_local_dat(path: Path, sample_bytes: int) -> Dict[str, Any]:
    size = path.stat().st_size
    data = path.read_bytes()[:sample_bytes]
    meta = classify_dat(data, path.name)
    return {
        "source_kind": "file",
        "path": str(path),
        "container_path": "",
        "entry_name": "",
        "name": path.name,
        "suffix": path.suffix.lower(),
        "size_bytes": size,
        "sample_bytes": len(data),
        "sha256": sha256_file(path),
        **meta,
    }


def inspect_zip_dat_entries(path: Path, sample_bytes: int) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    summary = {"zip_path": str(path), "zip_entries": 0, "dat_entries": 0, "zip_error": ""}
    try:
        with zipfile.ZipFile(path, "r") as zf:
            infos = zf.infolist()
            summary["zip_entries"] = len(infos)
            for info in infos:
                if info.is_dir():
                    continue
                if not info.filename.lower().endswith(DAT_SUFFIX):
                    continue
                summary["dat_entries"] += 1
                with zf.open(info, "r") as f:
                    data = f.read(sample_bytes)
                meta = classify_dat(data, info.filename)
                digest = sha256_zip_entry(zf, info.filename)
                rows.append({
                    "source_kind": "zip_entry",
                    "path": f"{path}!{info.filename}",
                    "container_path": str(path),
                    "entry_name": info.filename,
                    "name": Path(info.filename).name,
                    "suffix": DAT_SUFFIX,
                    "size_bytes": info.file_size,
                    "compressed_size_bytes": info.compress_size,
                    "sample_bytes": len(data),
                    "sha256": digest,
                    **meta,
                })
    except Exception as exc:
        summary["zip_error"] = str(exc)
    return rows, summary


def inspect_dat_paths(paths: Sequence[str], recursive: bool = True, sample_bytes: int = 16384) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    zip_summaries: List[Dict[str, Any]] = []
    inputs: List[Dict[str, Any]] = []
    for raw in paths:
        root = Path(raw).expanduser().resolve()
        item = {"path": raw, "resolved_path": str(root), "exists": root.exists(), "kind": "missing"}
        if not root.exists():
            inputs.append(item)
            continue
        if root.is_dir():
            item["kind"] = "directory"
            dats = list(iter_local_dat_files(root, recursive=recursive))
            item["dat_files"] = len(dats)
            for p in dats:
                rows.append(inspect_local_dat(p, sample_bytes=sample_bytes))
            # Also inspect ZIP files inside the folder because uploaded exports are often archives.
            zips = list(root.rglob("*.zip") if recursive else root.glob("*.zip"))
            item["zip_files"] = len(zips)
            for zp in zips:
                zr, zs = inspect_zip_dat_entries(zp, sample_bytes=sample_bytes)
                rows.extend(zr)
                zip_summaries.append(zs)
        elif root.is_file():
            item["kind"] = "file"
            if root.suffix.lower() == DAT_SUFFIX:
                rows.append(inspect_local_dat(root, sample_bytes=sample_bytes))
                item["dat_files"] = 1
            elif root.suffix.lower() == ".zip":
                zr, zs = inspect_zip_dat_entries(root, sample_bytes=sample_bytes)
                rows.extend(zr)
                zip_summaries.append(zs)
                item["zip_files"] = 1
                item["dat_entries"] = zs.get("dat_entries", 0)
            else:
                item["note"] = "not_a_dat_or_zip"
        inputs.append(item)

    by_likely: Dict[str, int] = {}
    by_magic: Dict[str, int] = {}
    for r in rows:
        by_likely[r["likely_type"]] = by_likely.get(r["likely_type"], 0) + 1
        by_magic[r["magic_type"]] = by_magic.get(r["magic_type"], 0) + 1
    recommended_next = []
    if any(r.get("json_like") for r in rows):
        recommended_next.append("json_like_dat_found:copy/extract locally and scan with chat-scan if it contains conversation messages")
    if any(r.get("text_like") and not r.get("json_like") for r in rows):
        recommended_next.append("text_like_dat_found:save locally as .txt/.md and scan with chat-scan or scan")
    if any(r.get("likely_type") in {"image_binary", "pdf_binary", "archive_binary", "database_binary"} for r in rows):
        recommended_next.append("binary_dat_found:inventory only; do not treat as chat text")
    if not rows:
        recommended_next.append("no_dat_entries_found:look for export folders or archives containing .dat blobs")
    return {
        "tool": "PooleShield DAT inspector",
        "version": VERSION,
        "generated_at": utc_now(),
        "inputs": inputs,
        "recursive": recursive,
        "sample_bytes": sample_bytes,
        "summary": {
            "total_dat_entries": len(rows),
            "by_likely_type": dict(sorted(by_likely.items())),
            "by_magic_type": dict(sorted(by_magic.items())),
            "zip_archives_seen": len(zip_summaries),
            "zip_dat_entries": sum(int(z.get("dat_entries", 0)) for z in zip_summaries),
            "recommended_next": recommended_next,
        },
        "zip_summaries": zip_summaries,
        "entries": rows,
    }


def write_json(path: str, obj: Dict[str, Any]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def write_csv(path: str, report: Dict[str, Any]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    rows = report.get("entries", [])
    fields = [
        "source_kind", "path", "container_path", "entry_name", "name", "size_bytes",
        "sample_bytes", "sha256", "magic_type", "likely_type", "encoding_guess",
        "printable_ratio", "has_nul_byte", "text_like", "json_like",
    ]
    with p.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            w.writerow(row)


def write_md(path: str, report: Dict[str, Any]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    s = report.get("summary", {})
    lines = [
        "# PooleShield DAT Inspection",
        "",
        f"Version: {report.get('version')}",
        f"Generated: {report.get('generated_at')}",
        "",
        "## Summary",
        "",
        f"Total `.dat` entries: `{s.get('total_dat_entries')}`",
        f"By likely type: `{s.get('by_likely_type')}`",
        f"By magic type: `{s.get('by_magic_type')}`",
        f"ZIP archives seen: `{s.get('zip_archives_seen')}`",
        f"ZIP `.dat` entries: `{s.get('zip_dat_entries')}`",
        "",
        "## Recommended next",
        "",
    ]
    for rec in s.get("recommended_next", []):
        lines.append(f"- `{rec}`")
    lines += ["", "## Entries", ""]
    for r in report.get("entries", [])[:200]:
        lines.append(f"### {r.get('likely_type')} — `{r.get('path')}`")
        lines.append(f"- size_bytes: `{r.get('size_bytes')}`")
        lines.append(f"- magic_type: `{r.get('magic_type')}`")
        lines.append(f"- text_like: `{r.get('text_like')}`; json_like: `{r.get('json_like')}`")
        lines.append(f"- sha256: `{r.get('sha256')}`")
        lines.append("")
    p.write_text("\n".join(lines), encoding="utf-8")


def run_dat_inspect(
    paths: Sequence[str],
    output_dir: str = "out/dat_inspect",
    clean_output: bool = False,
    recursive: bool = True,
    sample_bytes: int = 16384,
    bundle_output: bool = False,
    bundle_path: Optional[str] = None,
    privacy_bundle: bool = True,
) -> Dict[str, Any]:
    from result_bundler import bundle_output_dir

    out = Path(output_dir)
    if clean_output and out.exists():
        import shutil
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    report = inspect_dat_paths(paths, recursive=recursive, sample_bytes=sample_bytes)
    json_path = out / "dat_inventory.json"
    csv_path = out / "dat_inventory.csv"
    md_path = out / "dat_inventory.md"
    summary_path = out / "RUN_SUMMARY.json"
    write_json(str(json_path), report)
    write_csv(str(csv_path), report)
    write_md(str(md_path), report)
    run_summary = {
        "tool": "PooleShield DAT inspector",
        "version": VERSION,
        "mode": "dat-inspect",
        "output_dir": str(out),
        "paths": list(paths),
        "dat_inventory": str(json_path),
        "summary": report.get("summary", {}),
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
    write_json(str(summary_path), run_summary)
    return run_summary


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="PooleShield v1.8 DAT inspector")
    parser.add_argument("--path", "-p", nargs="+", required=True, help="Path(s) to .dat files, folders, or ZIP archives")
    parser.add_argument("--output-dir", default="out/dat_inspect")
    parser.add_argument("--clean-output", action="store_true")
    parser.add_argument("--no-recursive", action="store_true")
    parser.add_argument("--sample-bytes", type=int, default=16384)
    parser.add_argument("--bundle-output", action="store_true")
    parser.add_argument("--bundle-path", default=None)
    parser.add_argument("--privacy-bundle", action="store_true", default=True)
    args = parser.parse_args(argv)
    report = run_dat_inspect(
        paths=args.path,
        output_dir=args.output_dir,
        clean_output=args.clean_output,
        recursive=not args.no_recursive,
        sample_bytes=args.sample_bytes,
        bundle_output=args.bundle_output,
        bundle_path=args.bundle_path,
        privacy_bundle=args.privacy_bundle,
    )
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
