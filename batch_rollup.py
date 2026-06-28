#!/usr/bin/env python3
"""PooleShield batch rollup dashboard.

Defensive purpose:
  Summarize multiple PooleShield output folders or privacy bundles without
  reading decoded DAT text. This is for operator visibility after deterministic
  local batches have been scanned, triaged, and ledger-applied.

Privacy boundary:
  Reads report metadata only: RUN_SUMMARY*.json, effective_policy_decisions.json,
  BUNDLE_MANIFEST.json, and scan/quarantine summaries when present. It does not
  open normalized_events.jsonl, extracted_dat_text/, or local evidence snippets.
"""
from __future__ import annotations

import csv
import json
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

VERSION = "2.1.1"
DANGEROUS_FINAL_DECISIONS = ("REQUIRE_APPROVAL", "BLOCK", "QUARANTINE")
PRIVACY_EXCLUDED_REQUIRED = ("normalized_events.jsonl", "review_evidence_local.md", "review_evidence_report.json")


def _safe_json_loads(raw: bytes | str | None) -> Dict[str, Any]:
    if not raw:
        return {}
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    try:
        obj = json.loads(raw)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


@dataclass
class SourceReader:
    path: Path
    is_zip: bool
    names: List[str]

    @classmethod
    def open(cls, path: str | Path) -> "SourceReader":
        p = Path(path)
        if p.is_file() and p.suffix.lower() == ".zip":
            with zipfile.ZipFile(p, "r") as z:
                return cls(path=p, is_zip=True, names=z.namelist())
        if p.is_dir():
            names = [str(x.relative_to(p)).replace("\\", "/") for x in p.rglob("*") if x.is_file()]
            return cls(path=p, is_zip=False, names=names)
        raise FileNotFoundError(f"Rollup source not found or unsupported: {p}")

    def resolve_name(self, name: str) -> Optional[str]:
        norm = name.replace("\\", "/")
        if norm in self.names:
            return norm
        suffix = "/" + norm
        matches = [n for n in self.names if n.endswith(suffix)]
        if matches:
            # Prefer dat_chat_scan reports over nested test/cache copies.
            matches.sort(key=lambda n: ("dat_chat_scan" not in n, len(n), n))
            return matches[0]
        return None

    def exists(self, name: str) -> bool:
        return self.resolve_name(name) is not None

    def read_bytes(self, name: str) -> Optional[bytes]:
        resolved = self.resolve_name(name)
        if not resolved:
            return None
        if self.is_zip:
            with zipfile.ZipFile(self.path, "r") as z:
                return z.read(resolved)
        q = self.path / resolved
        if q.exists():
            return q.read_bytes()
        return None

    def read_json(self, *candidate_names: str) -> Dict[str, Any]:
        for name in candidate_names:
            raw = self.read_bytes(name)
            if raw is not None:
                return _safe_json_loads(raw)
        return {}


def _get_nested(d: Dict[str, Any], *path: str) -> Any:
    cur: Any = d
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _as_int(value: Any, default: int = 0) -> int:
    try:
        if value is None or value == "":
            return default
        return int(value)
    except Exception:
        return default


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except Exception:
        return default




def split_label_path(raw: str | Path) -> tuple[Optional[str], str]:
    text = str(raw)
    # Allow explicit labels as LABEL=path. Avoid treating Windows drive
    # letters or normal paths as labels.
    if "=" in text:
        left, right = text.split("=", 1)
        if left and right and not any(sep in left for sep in ("/", "\\")) and ":" not in left:
            return left.strip(), right.strip()
    return None, text

def _counts_from_effective(effective: Dict[str, Any]) -> Dict[str, int]:
    summary = effective.get("summary") or {}
    counts = summary.get("by_effective_decision") or {}
    return {str(k): _as_int(v) for k, v in counts.items()}


def _counts_from_policy(run_summary: Dict[str, Any]) -> Dict[str, int]:
    policy = run_summary.get("policy_summary") or {}
    counts = policy.get("by_decision") or {}
    return {str(k): _as_int(v) for k, v in counts.items()}


def _source_label(path: Path, run_summary: Dict[str, Any], batch_summary: Dict[str, Any]) -> str:
    out = str(run_summary.get("output_dir") or batch_summary.get("output_dir") or path)
    m = re.search(r"dat_batch[_\\/\-]?(\d{4,})", out, re.IGNORECASE)
    if m:
        return f"dat_batch_{m.group(1)}"
    m = re.search(r"dat_batch[_\\/\-]?(\d+)", str(path), re.IGNORECASE)
    if m:
        return f"dat_batch_{int(m.group(1)):04d}"
    if "dat_chat_scan" in out.replace("\\", "/") and not batch_summary:
        return "dat_batch_unknown"
    return path.stem if path.is_file() else path.name


def _start_index_from_path_or_summary(path: Path, run_summary: Dict[str, Any], batch_summary: Dict[str, Any]) -> int:
    for candidate in (batch_summary.get("start_index"), run_summary.get("start_index")):
        if candidate is not None:
            return _as_int(candidate, -1)
    joined = " ".join([str(path), str(run_summary.get("output_dir") or ""), str(batch_summary.get("output_dir") or "")])
    m = re.search(r"dat_batch[_\\/\-]?(\d{4,})", joined, re.IGNORECASE)
    if m:
        return int(m.group(1))
    return -1


def _batch_size_from_summary(batch_summary: Dict[str, Any]) -> int:
    return _as_int(batch_summary.get("batch_size"), 0)


def _scan_event_count(run_summary: Dict[str, Any], effective: Dict[str, Any]) -> int:
    total = _as_int(_get_nested(effective, "summary", "total_decisions"), 0)
    if total:
        return total
    scan = run_summary.get("scan") or {}
    if isinstance(scan, dict):
        nested = scan.get("scan") if isinstance(scan.get("scan"), dict) else scan
        return _as_int(nested.get("event_count") or (scan.get("summary") or {}).get("total_events"), 0)
    return 0


def _skipped_count(run_summary: Dict[str, Any]) -> int:
    scan = run_summary.get("scan") or {}
    if isinstance(scan, dict):
        nested = scan.get("scan") if isinstance(scan.get("scan"), dict) else scan
        return _as_int(nested.get("skipped_count"), 0)
    return 0


FORBIDDEN_CONTENT_MARKERS = (
    "normalized_events.jsonl",
    "review_evidence_local.md",
    "review_evidence_report.json",
    "extracted_dat_text",
)


def _contains_forbidden_content(names: Iterable[str]) -> bool:
    norm_names = [str(n).replace("\\", "/") for n in names]
    return any(any(marker in n for marker in FORBIDDEN_CONTENT_MARKERS) for n in norm_names)


def _bundle_privacy_check(names: Iterable[str], manifest: Dict[str, Any]) -> Tuple[bool, List[str]]:
    problems: List[str] = []
    norm_names = [str(n).replace("\\", "/") for n in names]
    if manifest.get("privacy_mode") is not True:
        problems.append("BUNDLE_MANIFEST privacy_mode is not true")
    for marker in FORBIDDEN_CONTENT_MARKERS:
        if any(marker in n for n in norm_names):
            problems.append(f"privacy bundle contains forbidden content marker: {marker}")
    return (len(problems) == 0), problems


def _embedded_bundle(reader: SourceReader) -> Tuple[Dict[str, Any], List[str], str]:
    """Return manifest, names, and path for the source's privacy bundle.

    Directory sources are local workspaces and may legitimately contain raw
    artifacts that are not safe to upload. For directory sources, the privacy
    check must target the embedded pooleshield_results_bundle.zip rather than
    the local workspace itself.
    """
    if reader.is_zip:
        manifest = reader.read_json("BUNDLE_MANIFEST.json")
        return manifest, list(reader.names), str(reader.path)

    bundle_name = reader.resolve_name("pooleshield_results_bundle.zip")
    if not bundle_name:
        return {}, [], ""
    bundle_path = reader.path / bundle_name
    try:
        with zipfile.ZipFile(bundle_path, "r") as z:
            names = z.namelist()
            raw = z.read("BUNDLE_MANIFEST.json") if "BUNDLE_MANIFEST.json" in names else None
        return _safe_json_loads(raw), names, str(bundle_path)
    except Exception:
        return {}, [], str(bundle_path)


def _privacy_status(reader: SourceReader, direct_manifest: Dict[str, Any]) -> Tuple[bool, List[str], str, bool, bool, int, str]:
    """Assess export privacy without treating local workspace files as leaked.

    Returns:
      privacy_ok, problems, privacy_scope, local_private_artifacts_present,
      bundle_privacy_mode, bundle_file_count, bundle_generated_at
    """
    local_private_present = _contains_forbidden_content(reader.names)

    if reader.is_zip:
        manifest, names, bundle_path = _embedded_bundle(reader)
        ok, problems = _bundle_privacy_check(names, manifest)
        return (
            ok,
            problems,
            "source_zip",
            local_private_present,
            bool(manifest.get("privacy_mode")),
            _as_int(manifest.get("file_count"), len(names)),
            str(manifest.get("generated_at") or ""),
        )

    manifest, names, bundle_path = _embedded_bundle(reader)
    if not bundle_path:
        return (
            False,
            ["directory source has no pooleshield_results_bundle.zip privacy bundle"],
            "directory_no_bundle",
            local_private_present,
            False,
            0,
            "",
        )
    ok, problems = _bundle_privacy_check(names, manifest)
    if ok and local_private_present:
        # This is expected for local output folders. The local workspace can
        # contain decoded/private artifacts as long as the upload bundle does not.
        problems = []
    return (
        ok,
        problems,
        "embedded_privacy_bundle",
        local_private_present,
        bool(manifest.get("privacy_mode")),
        _as_int(manifest.get("file_count"), len(names)),
        str(manifest.get("generated_at") or ""),
    )


def summarize_source(source_path: str | Path) -> Dict[str, Any]:
    label_override, resolved_source_path = split_label_path(source_path)
    reader = SourceReader.open(resolved_source_path)
    run_summary = reader.read_json("RUN_SUMMARY_APPLY_LEDGER.json", "RUN_SUMMARY.json")
    # Keep original scan summary too when apply-ledger summary is dominant.
    original_run_summary = reader.read_json("RUN_SUMMARY.json")
    batch_summary = reader.read_json("RUN_SUMMARY_DAT_BATCH.json")
    if not batch_summary and not reader.is_zip and reader.path.name.lower() == "dat_chat_scan":
        # v2.0 final applied bundles usually live inside dat_batch_xxxx/dat_chat_scan,
        # while RUN_SUMMARY_DAT_BATCH.json is stored one level up.
        try:
            parent_reader = SourceReader.open(reader.path.parent)
            batch_summary = parent_reader.read_json("RUN_SUMMARY_DAT_BATCH.json")
        except Exception:
            batch_summary = {}
    effective = reader.read_json("effective_policy_decisions.json")
    evidence = reader.read_json("RUN_SUMMARY_EVIDENCE.json")
    triage = reader.read_json("RUN_SUMMARY_TRIAGE.json")
    manifest = reader.read_json("BUNDLE_MANIFEST.json")

    counts = _counts_from_effective(effective) or _counts_from_policy(run_summary) or _counts_from_policy(original_run_summary)
    actionable = sum(_as_int(counts.get(k)) for k in DANGEROUS_FINAL_DECISIONS)
    allow = _as_int(counts.get("ALLOW"), 0)
    allow_log = _as_int(counts.get("ALLOW_LOG"), 0)
    (
        privacy_ok,
        privacy_problems,
        privacy_scope,
        local_private_artifacts_present,
        bundle_privacy_mode,
        bundle_file_count,
        bundle_generated_at,
    ) = _privacy_status(reader, manifest)

    src_path = Path(resolved_source_path)
    row = {
        "source_path": str(resolved_source_path),
        "source_type": "zip" if reader.is_zip else "directory",
        "batch_label": label_override or _source_label(src_path, original_run_summary or run_summary, batch_summary),
        "start_index": _start_index_from_path_or_summary(Path(label_override or str(src_path)), original_run_summary or run_summary, batch_summary),
        "batch_size": _batch_size_from_summary(batch_summary),
        "next_start_index": _as_int(batch_summary.get("next_start_index"), -1),
        "extracted_files": _as_int(_get_nested(batch_summary, "extract_summary", "summary", "extracted_files"), 0),
        "remaining_extractable_estimate": _as_int(_get_nested(batch_summary, "extract_summary", "summary", "remaining_extractable_estimate"), -1),
        "events_scanned": _scan_event_count(original_run_summary or run_summary, effective),
        "skipped_files": _skipped_count(original_run_summary or run_summary),
        "ledger_rows": _as_int(_get_nested(effective, "summary", "ledger_rows"), 0),
        "applied_ledger_rows": _as_int(_get_nested(effective, "summary", "applied_ledger_rows"), 0),
        "pending_review_rows": _as_int(_get_nested(effective, "summary", "pending_review_rows"), 0),
        "allow": allow,
        "allow_log": allow_log,
        "require_approval": _as_int(counts.get("REQUIRE_APPROVAL"), 0),
        "block": _as_int(counts.get("BLOCK"), 0),
        "quarantine": _as_int(counts.get("QUARANTINE"), 0),
        "actionable_final_items": actionable,
        "evidence_reviewed_items": _as_int(_get_nested(evidence, "summary", "reviewed_items"), 0),
        "evidence_live_action_hits": _as_int(_get_nested(evidence, "summary", "items_with_live_action_hits"), 0),
        "privacy_mode": bundle_privacy_mode,
        "privacy_ok": privacy_ok,
        "privacy_scope": privacy_scope,
        "local_private_artifacts_present": local_private_artifacts_present,
        "privacy_problems": "; ".join(privacy_problems),
        "bundle_file_count": bundle_file_count,
        "bundle_generated_at": bundle_generated_at,
        # The final effective decisions are the operational truth. Some older
        # batches kept a nonzero pending_review_rows bookkeeping artifact even
        # after every final decision was ALLOW/ALLOW_LOG. Treat those as
        # complete when no actionable final decision remains.
        "status": "complete" if actionable == 0 and privacy_ok else "needs_attention",
    }
    return row


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    fields = [
        "batch_label", "status", "start_index", "batch_size", "next_start_index", "extracted_files",
        "remaining_extractable_estimate", "events_scanned", "skipped_files", "allow", "allow_log",
        "require_approval", "block", "quarantine", "actionable_final_items", "pending_review_rows",
        "ledger_rows", "applied_ledger_rows", "evidence_reviewed_items", "evidence_live_action_hits",
        "privacy_mode", "privacy_ok", "privacy_scope", "local_private_artifacts_present", "privacy_problems", "source_type", "source_path",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _sum(rows: Iterable[Dict[str, Any]], key: str) -> int:
    return sum(_as_int(row.get(key), 0) for row in rows)


def build_rollup(paths: List[str], output_dir: str, clean_output: bool = False) -> Dict[str, Any]:
    out = Path(output_dir)
    if clean_output and out.exists():
        import shutil
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    rows = [summarize_source(p) for p in paths]
    rows.sort(key=lambda r: (_as_int(r.get("start_index"), 10**9), str(r.get("batch_label"))))
    total_events = _sum(rows, "events_scanned")
    total_allow = _sum(rows, "allow")
    total_allow_log = _sum(rows, "allow_log")
    total_require_approval = _sum(rows, "require_approval")
    total_block = _sum(rows, "block")
    total_quarantine = _sum(rows, "quarantine")
    total_actionable = _sum(rows, "actionable_final_items")
    total_pending = _sum(rows, "pending_review_rows")
    privacy_ok = all(bool(r.get("privacy_ok")) for r in rows) if rows else False
    complete_batches = sum(1 for r in rows if r.get("status") == "complete")
    total_extracted = _sum(rows, "extracted_files")

    summary = {
        "tool": "PooleShield batch rollup",
        "version": VERSION,
        "mode": "batch-rollup",
        "output_dir": str(out),
        "source_count": len(rows),
        "complete_batches": complete_batches,
        "needs_attention_batches": len(rows) - complete_batches,
        "privacy_ok": privacy_ok,
        "total_extracted_files": total_extracted,
        "total_events_scanned": total_events,
        "total_skipped_files": _sum(rows, "skipped_files"),
        "by_final_decision": {
            "ALLOW": total_allow,
            "ALLOW_LOG": total_allow_log,
            "REQUIRE_APPROVAL": total_require_approval,
            "BLOCK": total_block,
            "QUARANTINE": total_quarantine,
        },
        "actionable_final_items": total_actionable,
        "pending_review_rows": total_pending,
        "rows": rows,
    }
    (out / "batch_rollup.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    write_csv(out / "batch_rollup.csv", rows)
    write_md(out / "batch_rollup.md", summary)
    return summary


def write_md(path: Path, summary: Dict[str, Any]) -> None:
    counts = summary.get("by_final_decision") or {}
    lines = [
        "# PooleShield Batch Rollup",
        "",
        f"Version: {summary.get('version')}",
        f"Sources: `{summary.get('source_count')}`",
        f"Complete batches: `{summary.get('complete_batches')}`",
        f"Needs attention: `{summary.get('needs_attention_batches')}`",
        f"Privacy OK: `{summary.get('privacy_ok')}`",
        "",
        "## Totals",
        "",
        f"Extracted text/json DAT files: `{summary.get('total_extracted_files')}`",
        f"Events scanned: `{summary.get('total_events_scanned')}`",
        f"Skipped files: `{summary.get('total_skipped_files')}`",
        f"ALLOW: `{counts.get('ALLOW', 0)}`",
        f"ALLOW_LOG: `{counts.get('ALLOW_LOG', 0)}`",
        f"REQUIRE_APPROVAL: `{counts.get('REQUIRE_APPROVAL', 0)}`",
        f"BLOCK: `{counts.get('BLOCK', 0)}`",
        f"QUARANTINE: `{counts.get('QUARANTINE', 0)}`",
        f"Actionable final items: `{summary.get('actionable_final_items')}`",
        f"Pending review rows: `{summary.get('pending_review_rows')}`",
        "",
        "## Batch table",
        "",
        "| Batch | Status | Extracted | Events | ALLOW | ALLOW_LOG | Approval | Block | Quarantine | Privacy | Scope |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for row in summary.get("rows") or []:
        lines.append(
            "| {batch_label} | {status} | {extracted_files} | {events_scanned} | {allow} | {allow_log} | {require_approval} | {block} | {quarantine} | {privacy_ok} | {privacy_scope} |".format(**row)
        )
    lines += [
        "",
        "## Privacy boundary",
        "",
        "This rollup reads report metadata only. For directory sources, local private artifacts may exist in the workspace, but privacy status is based on the generated `pooleshield_results_bundle.zip` export.",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":  # pragma: no cover
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="+")
    parser.add_argument("--output-dir", default="out/batch_rollup")
    parser.add_argument("--clean-output", action="store_true")
    args = parser.parse_args()
    print(json.dumps(build_rollup(args.paths, args.output_dir, args.clean_output), indent=2))
