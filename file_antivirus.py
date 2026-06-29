#!/usr/bin/env python3
"""
PooleShield v3.4.2 read-only file/folder antivirus scanner.

Defensive purpose:
  Provide a second-opinion static scanner for files, folders, scripts, and ZIP
  archives. The scanner writes reports and dry-run quarantine recommendations.

Safety boundary:
  This module does not execute scanned files, follow links, kill processes,
  delete files, modify files, quarantine files, or install hooks/drivers. All
  containment output is advisory/dry-run only.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import re
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from result_bundler import bundle_output_dir
from file_av_rules import apply_rule_pack, load_rule_pack, rule_pack_summary

VERSION = "5.2.1"

SCRIPT_EXTENSIONS = {
    ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".hta", ".py", ".rb", ".pl", ".sh", ".bash", ".zsh", ".lua", ".php",
}
EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".com", ".msi", ".msp", ".cpl", ".sys", ".drv", ".ocx",
}
DOCUMENT_MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".xlam"}
ARCHIVE_EXTENSIONS = {".zip", ".jar", ".docx", ".xlsx", ".pptx"}
TEXT_EXTENSIONS = {
    ".txt", ".md", ".json", ".jsonl", ".csv", ".log", ".xml", ".yaml", ".yml", ".ini",
    ".cfg", ".conf", ".tex", ".rst", ".toml", ".html", ".htm", ".css", ".svg",
} | SCRIPT_EXTENSIONS

RISK_PATTERNS: List[Tuple[str, str, float]] = [
    ("powershell_encoded_command", r"(?i)(?:-enc|-encodedcommand)\b", 0.30),
    ("powershell_download_execute", r"(?i)(downloadstring|downloadfile|invoke-webrequest|iwr\b|curl\b|wget\b).{0,120}(iex|invoke-expression|start-process|powershell)", 0.36),
    ("encoded_payload_marker", r"(?i)(frombase64string|base64decode|atob\(|certutil\s+.*-decode)", 0.26),
    ("script_exec_eval", r"(?i)\b(eval|exec|invoke-expression|iex)\b", 0.20),
    ("shell_execution_marker", r"(?i)(subprocess\.|os\.system|popen\(|wscript\.shell|shellexecute|start-process)", 0.22),
    ("defender_tamper_marker", r"(?i)(set-mppreference|add-mppreference|disableantispyware|disablebehaviormonitoring|realtimeprotection)", 0.36),
    ("persistence_marker", r"(?i)(schtasks\b|new-service\b|reg\s+add|currentversion\\run|startup\\|launchagents|crontab)", 0.24),
    ("credential_or_secret_marker", r"(?i)(password\s*=|api[_-]?key\s*=|secret\s*=|token\s*=|credential|mimikatz|lsass)", 0.22),
    ("destructive_action_marker", r"(?i)(remove-item\s+.*-recurse|del\s+/[sfq]|rm\s+-rf|format\s+[a-z]:|cipher\s+/w|vssadmin\s+delete|wbadmin\s+delete)", 0.38),
    ("living_off_land_tool", r"(?i)\b(bitsadmin|certutil|mshta|rundll32|regsvr32|wmic|powershell|cmd\.exe)\b", 0.16),
    ("network_exfil_marker", r"(?i)(invoke-restmethod|requests\.post|webclient|net\.webclient|socket\.|ftp://|http://|https://).{0,80}(upload|post|token|secret|password|key)", 0.24),
    ("office_macro_marker", r"(?i)(autoopen|document_open|workbook_open|createobject\(|shell\()", 0.28),
]

HIGH_SEVERITY_LABELS = {
    "powershell_download_execute",
    "defender_tamper_marker",
    "destructive_action_marker",
}

MAGIC_SIGNATURES = [
    (b"MZ", "pe_executable"),
    (b"PK\x03\x04", "zip_archive"),
    (b"%PDF", "pdf_document"),
    (b"\x7fELF", "elf_executable"),
    (b"\x1f\x8b", "gzip_archive"),
    (b"\x89PNG\r\n\x1a\n", "png_image"),
    (b"\xff\xd8\xff", "jpeg_image"),
    (b"7z\xbc\xaf\x27\x1c", "seven_zip_archive"),
    (b"Rar!\x1a\x07", "rar_archive"),
]

SAFE_REASON = "static read-only scan; no action taken"


@dataclass
class ScanItem:
    source_path: str
    display_path: str
    kind: str
    size_bytes: int
    sha256: str
    risk_score: float
    decision: str
    labels: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    entropy: float = 0.0
    magic_type: str = "unknown"
    skipped_reason: str = ""
    archive_parent: str = ""
    archive_parent_sha256: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_path": self.source_path,
            "display_path": self.display_path,
            "kind": self.kind,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "risk_score": round(float(self.risk_score), 4),
            "decision": self.decision,
            "labels": list(dict.fromkeys(self.labels)),
            "reasons": list(dict.fromkeys(self.reasons)),
            "entropy": round(float(self.entropy), 4),
            "magic_type": self.magic_type,
            "skipped_reason": self.skipped_reason,
            "archive_parent": self.archive_parent,
            "archive_parent_sha256": self.archive_parent_sha256,
        }


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def classify_magic(data: bytes) -> str:
    for sig, label in MAGIC_SIGNATURES:
        if data.startswith(sig):
            return label
    if data[:256].count(b"\x00") > 12:
        return "binary_unknown"
    try:
        data[:2048].decode("utf-8")
        return "text_like"
    except UnicodeDecodeError:
        try:
            data[:2048].decode("utf-16")
            return "text_like_utf16"
        except UnicodeDecodeError:
            return "unknown"


def is_hidden(path: Path) -> bool:
    return any(part.startswith(".") for part in path.parts if part not in (".", ".."))


def iter_files(paths: Sequence[str], recursive: bool = True, include_hidden: bool = False) -> Iterable[Path]:
    for raw in paths:
        root = Path(raw).expanduser()
        if not root.exists():
            continue
        if root.is_file():
            if include_hidden or not is_hidden(root):
                yield root
            continue
        if root.is_dir():
            iterator = root.rglob("*") if recursive else root.glob("*")
            for p in iterator:
                if p.is_file() and (include_hidden or not is_hidden(p)):
                    yield p


def has_double_extension(path: Path) -> bool:
    suffixes = [s.lower() for s in path.suffixes]
    if len(suffixes) < 2:
        return False
    decoy = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".rtf"}
    dangerous = EXECUTABLE_EXTENSIONS | SCRIPT_EXTENSIONS
    return suffixes[-1] in dangerous and any(s in decoy for s in suffixes[:-1])


def decode_text(data: bytes, path: Path) -> str:
    # Keep decoding permissive but never return snippets in reports.
    candidates = ["utf-8", "utf-16", "latin-1"]
    for enc in candidates:
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="ignore")


DEVELOPER_CONTEXT_MARKERS = [
    "pooleshield",
    "defensive purpose",
    "safety boundary",
    "read-only",
    "dry-run",
    "privacy bundle",
    "risk_patterns",
    "matched static pattern",
    "pytest",
    "assert ",
    "fixture",
    "test_",
]


def has_developer_reference_context(text: str, display_path: str) -> bool:
    """Detect local source/test/reference files that mention risky strings as data.

    This is only used when risk_profile="developer". It exists to reduce
    PooleShield self-scan noise when scanning its own source packages or test
    fixtures. It does not apply to the default profile.
    """
    lower = text[:120000].lower()
    path_lower = display_path.lower()
    marker_hits = sum(1 for marker in DEVELOPER_CONTEXT_MARKERS if marker in lower or marker in path_lower)
    path_context = any(part in path_lower for part in (
        "pooleshield",
        "test_",
        "\\tests\\",
        "/tests/",
        "fixture",
        ".md",
        ".py",
    ))
    return path_context and marker_hits >= 2


def scan_bytes(
    data: bytes,
    display_path: str,
    source_path: str,
    suffix: str,
    kind: str,
    archive_parent: str = "",
    archive_parent_sha256: str = "",
    truncated: bool = False,
    risk_profile: str = "standard",
    rule_pack: Optional[Dict[str, Any]] = None,
) -> ScanItem:
    labels: List[str] = []
    reasons: List[str] = []
    risk = 0.0
    size = len(data)
    digest = sha256_bytes(data)
    magic = classify_magic(data[:4096])
    entropy = shannon_entropy(data[: min(len(data), 1024 * 1024)])
    suffix = suffix.lower()

    if suffix in SCRIPT_EXTENSIONS:
        labels.append("script_file")
        risk += 0.12
        reasons.append("script-like extension")
    if suffix in EXECUTABLE_EXTENSIONS:
        labels.append("executable_extension")
        risk += 0.16
        reasons.append("executable-like extension")
    if suffix in DOCUMENT_MACRO_EXTENSIONS:
        labels.append("macro_document_extension")
        risk += 0.18
        reasons.append("macro-capable Office extension")
    if suffix in ARCHIVE_EXTENSIONS or magic == "zip_archive":
        labels.append("archive_file")
        risk += 0.04
    if has_double_extension(Path(display_path)):
        labels.append("double_extension")
        risk += 0.18
        reasons.append("double extension with risky final extension")
    if magic in {"pe_executable", "elf_executable"} and suffix not in EXECUTABLE_EXTENSIONS:
        labels.append("extension_magic_mismatch")
        risk += 0.24
        reasons.append("binary executable magic does not match extension")
    if magic == "zip_archive" and suffix not in ARCHIVE_EXTENSIONS:
        labels.append("extension_magic_mismatch")
        risk += 0.14
        reasons.append("archive magic does not match extension")
    if entropy >= 7.4 and size >= 1024:
        labels.append("high_entropy")
        risk += 0.12 if magic not in {"pe_executable", "elf_executable"} else 0.18
        reasons.append("high entropy may indicate packing/encryption/compression")
    if truncated:
        labels.append("large_file_limited_scan")
        risk += 0.04
        reasons.append("file was larger than max scan bytes; content scan was partial")

    should_text_scan = suffix in TEXT_EXTENSIONS or magic.startswith("text_like")
    developer_reference_context = False
    text: Optional[str] = None
    if should_text_scan:
        text = decode_text(data, Path(display_path))
        for label, pattern, weight in RISK_PATTERNS:
            if re.search(pattern, text):
                labels.append(label)
                risk += weight
                reasons.append(f"matched static pattern: {label}")
        if risk_profile == "developer" and has_developer_reference_context(text, display_path):
            developer_reference_context = True
            labels.append("developer_reference_context")
            reasons.append("developer/source-code/reference context detected; risk capped in developer profile")
            # Source/test files often contain detection strings as inert text.
            # Keep an audit log, but avoid BLOCK unless another layer reviews it.
            risk = min(risk, 0.34)

    risk = apply_rule_pack(
        rule_pack,
        display_path=display_path,
        suffix=suffix,
        magic_type=magic,
        labels=labels,
        reasons=reasons,
        risk=risk,
        text=text,
    )

    # Cap risk but preserve high-severity decisions below.
    risk = min(risk, 0.99)
    decision = decision_for(risk, labels)
    if not reasons:
        reasons.append(SAFE_REASON)
    return ScanItem(
        source_path=source_path,
        display_path=display_path,
        kind=kind,
        size_bytes=size,
        sha256=digest,
        risk_score=risk,
        decision=decision,
        labels=list(dict.fromkeys(labels)),
        reasons=list(dict.fromkeys(reasons)),
        entropy=entropy,
        magic_type=magic,
        archive_parent=archive_parent,
        archive_parent_sha256=archive_parent_sha256,
    )


def decision_for(risk: float, labels: Sequence[str]) -> str:
    labels_set = set(labels)
    if labels_set.intersection(HIGH_SEVERITY_LABELS) and risk >= 0.55:
        return "BLOCK"
    if risk >= 0.65:
        return "BLOCK"
    if risk >= 0.35:
        return "REQUIRE_APPROVAL"
    if risk >= 0.12:
        return "ALLOW_LOG"
    return "ALLOW"


def scan_regular_file(path: Path, max_bytes_per_file: int, risk_profile: str = "standard", rule_pack: Optional[Dict[str, Any]] = None) -> ScanItem:
    stat = path.stat()
    truncated = stat.st_size > max_bytes_per_file
    with path.open("rb") as f:
        data = f.read(max_bytes_per_file)
    # Hash full file separately while content scan stays capped.
    digest = sha256_file(path)
    item = scan_bytes(
        data=data,
        display_path=str(path),
        source_path=str(path),
        suffix=path.suffix,
        kind="file",
        truncated=truncated,
        risk_profile=risk_profile,
        rule_pack=rule_pack,
    )
    item.size_bytes = stat.st_size
    item.sha256 = digest
    return item


def scan_zip_archive(path: Path, max_archive_entries: int, max_entry_bytes: int, risk_profile: str = "standard", rule_pack: Optional[Dict[str, Any]] = None) -> Tuple[List[ScanItem], Dict[str, Any]]:
    items: List[ScanItem] = []
    inventory: Dict[str, Any] = {
        "archive_path": str(path),
        "archive_sha256": sha256_file(path),
        "entries_seen": 0,
        "entries_scanned": 0,
        "entries_skipped": 0,
        "skipped_reasons": {},
    }
    archive_hash = str(inventory.get("archive_sha256") or "")
    try:
        with zipfile.ZipFile(path) as zf:
            infos = [info for info in zf.infolist() if not info.is_dir()]
            inventory["entries_seen"] = len(infos)
            for idx, info in enumerate(infos[:max_archive_entries]):
                display = f"{path}!{info.filename}"
                if info.file_size > max_entry_bytes:
                    inventory["entries_skipped"] += 1
                    inventory["skipped_reasons"]["entry_larger_than_max_bytes"] = inventory["skipped_reasons"].get("entry_larger_than_max_bytes", 0) + 1
                    items.append(ScanItem(
                        source_path=display,
                        display_path=display,
                        kind="archive_entry",
                        size_bytes=info.file_size,
                        sha256="",
                        risk_score=0.08,
                        decision="ALLOW",
                        labels=["archive_entry_skipped_large"],
                        reasons=["archive entry larger than max entry scan bytes"],
                        skipped_reason="entry_larger_than_max_bytes",
                        archive_parent=str(path),
                        archive_parent_sha256=archive_hash,
                    ))
                    continue
                try:
                    data = zf.read(info, pwd=None)
                except Exception as exc:  # pragma: no cover - defensive against malformed archives
                    inventory["entries_skipped"] += 1
                    inventory["skipped_reasons"]["read_error"] = inventory["skipped_reasons"].get("read_error", 0) + 1
                    items.append(ScanItem(
                        source_path=display,
                        display_path=display,
                        kind="archive_entry",
                        size_bytes=info.file_size,
                        sha256="",
                        risk_score=0.10,
                        decision="ALLOW_LOG",
                        labels=["archive_entry_read_error"],
                        reasons=[f"could not read archive entry: {type(exc).__name__}"],
                        skipped_reason="read_error",
                        archive_parent=str(path),
                        archive_parent_sha256=archive_hash,
                    ))
                    continue
                item = scan_bytes(
                    data=data,
                    display_path=display,
                    source_path=display,
                    suffix=Path(info.filename).suffix,
                    kind="archive_entry",
                    archive_parent=str(path),
                    archive_parent_sha256=archive_hash,
                    truncated=False,
                    risk_profile=risk_profile,
                    rule_pack=rule_pack,
                )
                item.size_bytes = info.file_size
                items.append(item)
                inventory["entries_scanned"] += 1
            if len(infos) > max_archive_entries:
                inventory["entries_skipped"] += len(infos) - max_archive_entries
                inventory["skipped_reasons"]["over_max_archive_entries"] = len(infos) - max_archive_entries
    except zipfile.BadZipFile:
        inventory["error"] = "bad_zip_file"
    return items, inventory


def write_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            clean = dict(row)
            clean["labels"] = ";".join(row.get("labels") or [])
            clean["reasons"] = ";".join(row.get("reasons") or [])
            writer.writerow(clean)


def build_quarantine_plan(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    plan: List[Dict[str, Any]] = []
    for item in items:
        decision = item.get("decision")
        if decision not in {"REQUIRE_APPROVAL", "BLOCK", "QUARANTINE"}:
            continue
        plan.append({
            "display_path": item.get("display_path", ""),
            "source_path": item.get("source_path", ""),
            "sha256": item.get("sha256", ""),
            "risk_score": item.get("risk_score", ""),
            "decision": decision,
            "dry_run_action": "review_before_opening" if decision == "REQUIRE_APPROVAL" else "dry_run_quarantine_recommendation",
            "labels": ";".join(item.get("labels") or []),
            "reason": ";".join(item.get("reasons") or []),
        })
    return plan


def write_markdown_report(path: Path, report: Dict[str, Any]) -> None:
    summary = report.get("summary", {})
    top = sorted(report.get("items", []), key=lambda x: float(x.get("risk_score", 0)), reverse=True)[:25]
    lines = [
        "# PooleShield File AV Scan Report",
        "",
        f"Version: {report.get('version')}",
        f"Generated: {report.get('generated_at')}",
        f"Mode: `{report.get('mode')}`",
        "",
        "## Summary",
        "",
        f"Input paths: `{len(report.get('paths') or [])}`",
        f"Items scanned: `{summary.get('items_scanned')}`",
        f"Files scanned: `{summary.get('files_scanned')}`",
        f"Archive entries scanned: `{summary.get('archive_entries_scanned')}`",
        f"Skipped inputs: `{summary.get('skipped_inputs')}`",
        f"By decision: `{summary.get('by_decision')}`",
        f"Max risk: `{summary.get('max_risk_score')}`",
        "",
        "## Safety boundary",
        "",
        "This scan is read-only. PooleShield did not execute, delete, quarantine, modify, or upload scanned file contents.",
        "",
        "## Top risk items",
        "",
        "| Decision | Risk | Path | Labels |",
        "|---|---:|---|---|",
    ]
    for item in top:
        labels = ", ".join(item.get("labels") or [])
        path_text = str(item.get("display_path", "")).replace("|", "\\|")
        lines.append(f"| `{item.get('decision')}` | `{item.get('risk_score')}` | `{path_text}` | `{labels}` |")
    path.write_text("\n".join(lines), encoding="utf-8")


def write_quarantine_plan_md(path: Path, plan: List[Dict[str, Any]]) -> None:
    lines = [
        "# PooleShield Dry-Run Quarantine Plan",
        "",
        "No files were moved, modified, deleted, or quarantined. This file is advisory only.",
        "",
        f"Items: `{len(plan)}`",
        "",
        "| Decision | Risk | Dry-run action | Path | Labels |",
        "|---|---:|---|---|---|",
    ]
    for item in plan:
        path_text = str(item.get("display_path", "")).replace("|", "\\|")
        labels = str(item.get("labels", "")).replace("|", "\\|")
        lines.append(f"| `{item.get('decision')}` | `{item.get('risk_score')}` | `{item.get('dry_run_action')}` | `{path_text}` | `{labels}` |")
    path.write_text("\n".join(lines), encoding="utf-8")


def summarize(items: List[Dict[str, Any]], paths: Sequence[str], skipped_inputs: List[str]) -> Dict[str, Any]:
    by_decision: Dict[str, int] = {}
    by_label: Dict[str, int] = {}
    max_risk = 0.0
    for item in items:
        dec = str(item.get("decision") or "UNKNOWN")
        by_decision[dec] = by_decision.get(dec, 0) + 1
        max_risk = max(max_risk, float(item.get("risk_score") or 0))
        for label in item.get("labels") or []:
            by_label[label] = by_label.get(label, 0) + 1
    return {
        "paths": list(paths),
        "items_scanned": len(items),
        "files_scanned": sum(1 for item in items if item.get("kind") == "file"),
        "archive_entries_scanned": sum(1 for item in items if item.get("kind") == "archive_entry"),
        "skipped_inputs": len(skipped_inputs),
        "skipped_input_paths": skipped_inputs,
        "by_decision": dict(sorted(by_decision.items())),
        "top_labels": dict(sorted(by_label.items(), key=lambda kv: (-kv[1], kv[0]))[:20]),
        "max_risk_score": round(max_risk, 4),
        "read_only": True,
        "dry_run_only": True,
    }


def run_file_av_scan(
    paths: Sequence[str],
    output_dir: str = "out/file_av_scan",
    clean_output: bool = False,
    recursive: bool = True,
    include_hidden: bool = False,
    max_bytes_per_file: int = 5 * 1024 * 1024,
    max_archive_entries: int = 500,
    max_archive_entry_bytes: int = 2 * 1024 * 1024,
    scan_archives: bool = True,
    risk_profile: str = "standard",
    scan_profile: Optional[str] = None,
    rule_pack: Optional[str] = None,
    mode: str = "av-scan",
    bundle_output: bool = False,
    bundle_path: Optional[str] = None,
    privacy_bundle: bool = True,
) -> Dict[str, Any]:
    out = Path(output_dir)
    if clean_output and out.exists():
        import shutil
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)
    loaded_rule_pack = load_rule_pack(rule_pack)

    report_json = out / "file_av_report.json"
    report_csv = out / "file_av_report.csv"
    report_md = out / "file_av_report.md"
    q_json = out / "dry_run_quarantine_plan.json"
    q_csv = out / "dry_run_quarantine_plan.csv"
    q_md = out / "dry_run_quarantine_plan.md"
    archive_json = out / "archive_inventory.json"
    run_json = out / "RUN_SUMMARY_FILE_AV.json"
    run_md = out / "RUN_SUMMARY_FILE_AV.md"

    items: List[ScanItem] = []
    archives: List[Dict[str, Any]] = []
    skipped_inputs: List[str] = []
    seen_files = list(iter_files(paths, recursive=recursive, include_hidden=include_hidden))
    existing_inputs = [str(Path(p).expanduser()) for p in paths if Path(p).expanduser().exists()]
    missing_inputs = [str(Path(p).expanduser()) for p in paths if not Path(p).expanduser().exists()]
    skipped_inputs.extend(missing_inputs)

    for file_path in seen_files:
        try:
            item = scan_regular_file(file_path, max_bytes_per_file=max_bytes_per_file, risk_profile=risk_profile, rule_pack=loaded_rule_pack)
            items.append(item)
            if scan_archives and (file_path.suffix.lower() == ".zip" or item.magic_type == "zip_archive"):
                entry_items, inv = scan_zip_archive(file_path, max_archive_entries=max_archive_entries, max_entry_bytes=max_archive_entry_bytes, risk_profile=risk_profile, rule_pack=loaded_rule_pack)
                archives.append(inv)
                items.extend(entry_items)
                suspicious_children = [e for e in entry_items if e.decision in {"REQUIRE_APPROVAL", "BLOCK", "QUARANTINE"}]
                if suspicious_children:
                    item.labels.append("archive_contains_suspicious_items")
                    item.reasons.append("archive contains entries requiring review")
                    item.risk_score = max(item.risk_score, min(max(e.risk_score for e in suspicious_children) * 0.75, 0.85))
                    item.decision = decision_for(item.risk_score, item.labels)
        except Exception as exc:  # pragma: no cover - safety against bad files/permissions
            skipped_inputs.append(f"{file_path}: {type(exc).__name__}: {exc}")

    item_dicts = [item.to_dict() for item in items]
    summary = summarize(item_dicts, paths, skipped_inputs)
    report = {
        "tool": "PooleShield file antivirus scanner",
        "version": VERSION,
        "generated_at": utc_now(),
        "mode": mode,
        "paths": list(paths),
        "existing_inputs": existing_inputs,
        "settings": {
            "recursive": recursive,
            "include_hidden": include_hidden,
            "max_bytes_per_file": max_bytes_per_file,
            "max_archive_entries": max_archive_entries,
            "max_archive_entry_bytes": max_archive_entry_bytes,
            "scan_archives": scan_archives,
            "risk_profile": risk_profile,
            "scan_profile": scan_profile or "manual",
            "rule_pack": rule_pack_summary(loaded_rule_pack),
            "read_only": True,
            "dry_run_only": True,
        },
        "summary": summary,
        "items": item_dicts,
        "archive_inventory": archives,
    }
    report_json.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    csv_fields = [
        "decision", "risk_score", "display_path", "kind", "size_bytes", "sha256", "magic_type",
        "entropy", "labels", "reasons", "skipped_reason", "archive_parent", "archive_parent_sha256", "source_path",
    ]
    write_csv(report_csv, item_dicts, csv_fields)
    write_markdown_report(report_md, report)
    archive_json.write_text(json.dumps(archives, indent=2, ensure_ascii=False), encoding="utf-8")

    plan = build_quarantine_plan(item_dicts)
    q_json.write_text(json.dumps({"tool": "PooleShield dry-run quarantine plan", "version": VERSION, "items": plan}, indent=2, ensure_ascii=False), encoding="utf-8")
    write_csv(q_csv, plan, ["decision", "risk_score", "dry_run_action", "display_path", "source_path", "sha256", "labels", "reason"])
    write_quarantine_plan_md(q_md, plan)

    run_summary = {
        "tool": "PooleShield operator",
        "version": VERSION,
        "mode": mode,
        "output_dir": str(out),
        "report_json": str(report_json),
        "report_csv": str(report_csv),
        "report_md": str(report_md),
        "dry_run_quarantine_plan": str(q_json),
        "rule_pack": rule_pack_summary(loaded_rule_pack),
        "summary": summary,
        "bundle_summary": None,
        "result_bundle": str(out / "pooleshield_results_bundle.zip") if bundle_output else "",
    }
    run_json.write_text(json.dumps(run_summary, indent=2, ensure_ascii=False), encoding="utf-8")
    run_md.write_text("\n".join([
        "# PooleShield File AV Run Summary",
        "",
        f"Version: {VERSION}",
        f"Mode: `{mode}`",
        f"Output dir: `{out}`",
        "",
        "## Summary",
        "",
        f"Items scanned: `{summary.get('items_scanned')}`",
        f"By decision: `{summary.get('by_decision')}`",
        f"Max risk: `{summary.get('max_risk_score')}`",
        f"Dry-run quarantine/review items: `{len(plan)}`",
        "",
        "Safety: read-only scan. No execution, deletion, or quarantine occurred.",
    ]), encoding="utf-8")
    if bundle_output:
        bundle_report = bundle_output_dir(str(out), bundle_path or str(out / "pooleshield_results_bundle.zip"), privacy_mode=privacy_bundle)
        run_summary["bundle_summary"] = bundle_report
        run_summary["result_bundle"] = bundle_report.get("bundle_path")
        run_json.write_text(json.dumps(run_summary, indent=2, ensure_ascii=False), encoding="utf-8")
        # Re-bundle so updated run summary is included.
        bundle_output_dir(str(out), bundle_path or str(out / "pooleshield_results_bundle.zip"), privacy_mode=privacy_bundle)
    return run_summary


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="PooleShield v3.4.2 read-only file AV scanner")
    parser.add_argument("--path", "-p", nargs="+", required=True)
    parser.add_argument("--output-dir", default="out/file_av_scan")
    parser.add_argument("--clean-output", action="store_true")
    parser.add_argument("--no-recursive", action="store_true")
    parser.add_argument("--include-hidden", action="store_true")
    parser.add_argument("--max-bytes-per-file", type=int, default=5 * 1024 * 1024)
    parser.add_argument("--max-archive-entries", type=int, default=500)
    parser.add_argument("--max-archive-entry-bytes", type=int, default=2 * 1024 * 1024)
    parser.add_argument("--no-archives", action="store_true")
    parser.add_argument("--risk-profile", choices=["standard", "developer"], default="standard",
                        help="Use 'developer' only for scanning trusted source/test packages to reduce self-scan false positives")
    parser.add_argument("--rule-pack", default=None, help="Optional local JSON rule pack for extra static file-AV labels/risk deltas")
    parser.add_argument("--bundle-output", action="store_true")
    parser.add_argument("--bundle-path", default=None)
    parser.add_argument("--privacy-bundle", action="store_true")
    args = parser.parse_args(argv)
    result = run_file_av_scan(
        paths=args.path,
        output_dir=args.output_dir,
        clean_output=args.clean_output,
        recursive=not args.no_recursive,
        include_hidden=args.include_hidden,
        max_bytes_per_file=args.max_bytes_per_file,
        max_archive_entries=args.max_archive_entries,
        max_archive_entry_bytes=args.max_archive_entry_bytes,
        scan_archives=not args.no_archives,
        risk_profile=args.risk_profile,
        rule_pack=args.rule_pack,
        bundle_output=args.bundle_output,
        bundle_path=args.bundle_path,
        privacy_bundle=args.privacy_bundle,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
