#!/usr/bin/env python3
"""PooleShield v4.0 engine API.

Defensive purpose:
  Provide a small, stable, JSON-friendly backend layer that future desktop UI
  code can call without shelling directly through the operator CLI.

Safety boundary:
  The engine keeps the same PooleShield constraints as the CLI. It reads local
  artifacts and writes metadata/report outputs only. It does not execute scanned
  files, delete files, quarantine files, kill processes, install hooks/drivers,
  send network requests, or upload raw scanned contents.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional, Sequence

from file_av_baseline_scan import run_file_av_scan_with_baseline
from file_av_rules import validate_rule_pack_file
from pooleshield_config import (
    PooleShieldConfigError,
    expand_config_path,
    load_and_validate_config,
    resolve_file_av_baseline_scan_options,
    resolve_rule_pack_validate_options,
    write_default_config,
)
from result_bundler import bundle_output_dir
from scan_history import (
    init_history_db,
    list_history,
    record_scan_output,
    show_history_scan,
    write_history_list_reports,
)
from scan_profiles import ScanProfileError, get_scan_profile, profile_catalog

VERSION = "4.3.0"
ENGINE_API_VERSION = "1"

SUPPORTED_OPERATIONS = (
    "config.init",
    "config.validate",
    "config.show",
    "profile.list",
    "profile.show",
    "history.init",
    "history.record",
    "history.list",
    "history.show",
    "rule_pack.validate",
    "file_av.scan_baseline",
    "results.load",
    "baseline.load",
    "baseline.diff",
)


def _ns(**kwargs: Any) -> SimpleNamespace:
    """Build a lightweight argparse-compatible namespace for legacy resolvers."""
    return SimpleNamespace(**kwargs)


def _bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    return bool(value)


def ensure_output_dir(path: str, clean: bool = False) -> Path:
    out = Path(path)
    if clean and out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)
    return out


def write_json(path: str | Path, data: Any) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def write_text(path: str | Path, text: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _with_engine_metadata(summary: Dict[str, Any], operation: str) -> Dict[str, Any]:
    summary.setdefault("engine", "PooleShield Engine API")
    summary.setdefault("engine_version", VERSION)
    summary.setdefault("engine_api_version", ENGINE_API_VERSION)
    summary.setdefault("operation", operation)
    return summary


def config_init(config: str, force: bool = False) -> Dict[str, Any]:
    summary = write_default_config(config, force=force)
    return _with_engine_metadata(summary, "config.init")


def config_validate(config: Optional[str] = None, require_existing_paths: bool = False) -> Dict[str, Any]:
    cfg, _config_path, validation = load_and_validate_config(config, require_existing_paths=require_existing_paths)
    summary = dict(validation)
    summary["effective_config"] = cfg
    return _with_engine_metadata(summary, "config.validate")


def config_show(config: Optional[str] = None) -> Dict[str, Any]:
    cfg, config_path, validation = load_and_validate_config(config)
    summary = {
        "tool": "PooleShield config show",
        "version": VERSION,
        "config_path": str(config_path) if config_path else None,
        "used_config_file": config_path is not None,
        "validation": validation,
        "effective_config": cfg,
    }
    return _with_engine_metadata(summary, "config.show")


def profile_list(config: Optional[str] = None) -> Dict[str, Any]:
    cfg, config_path, validation = load_and_validate_config(config)
    summary = profile_catalog(cfg.get("scan_profiles"))
    summary["config_path"] = str(config_path) if config_path else None
    summary["validation"] = validation
    return _with_engine_metadata(summary, "profile.list")


def profile_show(name: str, config: Optional[str] = None) -> Dict[str, Any]:
    cfg, config_path, validation = load_and_validate_config(config)
    try:
        profile = get_scan_profile(name, cfg.get("scan_profiles"))
    except ScanProfileError as exc:
        raise PooleShieldConfigError(str(exc)) from exc
    summary = {
        "tool": "PooleShield scan profile",
        "version": VERSION,
        "config_path": str(config_path) if config_path else None,
        "validation": validation,
        "profile": profile,
    }
    return _with_engine_metadata(summary, "profile.show")


def _resolve_history_db(config: Optional[str] = None, history_db: Optional[str] = None) -> str:
    cfg, config_path, _validation = load_and_validate_config(config)
    defaults = cfg.get("defaults", {})
    base_dir = config_path.parent if config_path else Path.cwd()
    raw = history_db or defaults.get("history_db")
    if not raw:
        raise PooleShieldConfigError("history_db is required; pass history_db or set defaults.history_db in config")
    return expand_config_path(raw, base_dir=base_dir) or str(Path("local_history") / "pooleshield_scan_history.sqlite")


def history_init(config: Optional[str] = None, history_db: Optional[str] = None) -> Dict[str, Any]:
    summary = init_history_db(_resolve_history_db(config=config, history_db=history_db))
    return _with_engine_metadata(summary, "history.init")


def history_record(
    output_dir: str,
    config: Optional[str] = None,
    history_db: Optional[str] = None,
    notes: str = "",
    bundle_output: bool = False,
    bundle_path: Optional[str] = None,
    privacy_bundle: bool = True,
) -> Dict[str, Any]:
    db = _resolve_history_db(config=config, history_db=history_db)
    summary = record_scan_output(output_dir, db, notes=notes)
    if bundle_output:
        bundle_report = bundle_output_dir(output_dir, bundle_path, privacy_mode=privacy_bundle)
        summary["bundle_summary"] = bundle_report
        summary["result_bundle"] = bundle_report.get("bundle_path")
        write_json(Path(output_dir) / "SCAN_HISTORY_RECORD.json", summary)
        bundle_output_dir(output_dir, bundle_path, privacy_mode=privacy_bundle)
    return _with_engine_metadata(summary, "history.record")


def history_list(
    config: Optional[str] = None,
    history_db: Optional[str] = None,
    limit: int = 10,
    output_dir: Optional[str] = None,
    bundle_output: bool = False,
    bundle_path: Optional[str] = None,
    privacy_bundle: bool = True,
) -> Dict[str, Any]:
    db = _resolve_history_db(config=config, history_db=history_db)
    summary = list_history(db, limit=limit)
    if output_dir:
        reports = write_history_list_reports(output_dir, summary)
        summary["output_dir"] = output_dir
        summary["reports"] = reports
        if bundle_output:
            bundle_report = bundle_output_dir(output_dir, bundle_path, privacy_mode=privacy_bundle)
            summary["bundle_summary"] = bundle_report
            summary["result_bundle"] = bundle_report.get("bundle_path")
            write_json(Path(output_dir) / "SCAN_HISTORY_LIST.json", summary)
            bundle_output_dir(output_dir, bundle_path, privacy_mode=privacy_bundle)
    return _with_engine_metadata(summary, "history.list")


def history_show(scan_id: int, config: Optional[str] = None, history_db: Optional[str] = None) -> Dict[str, Any]:
    db = _resolve_history_db(config=config, history_db=history_db)
    summary = show_history_scan(db, scan_id=scan_id)
    return _with_engine_metadata(summary, "history.show")


def rule_pack_validate(
    config: Optional[str] = None,
    rule_pack: Optional[str] = None,
    output_dir: Optional[str] = None,
    clean_output: bool = False,
    bundle_output: bool = False,
    bundle_path: Optional[str] = None,
    privacy_bundle: bool = True,
) -> Dict[str, Any]:
    args = _ns(config=config, rule_pack=rule_pack, output_dir=output_dir)
    resolved_rule = resolve_rule_pack_validate_options(args)
    out = ensure_output_dir(resolved_rule["output_dir"], clean=clean_output)
    summary = validate_rule_pack_file(resolved_rule["rule_pack"])
    summary["mode"] = "rule-pack-validate"
    summary["version"] = VERSION
    summary["output_dir"] = str(out)
    summary["config_summary"] = resolved_rule.get("config_summary")
    report_path = out / "rule_pack_validation.json"
    write_json(report_path, summary)
    md = out / "rule_pack_validation.md"
    write_text(md, "\n".join([
        "# PooleShield Rule Pack Validation",
        "",
        f"Valid: `{summary.get('valid')}`",
        f"Rules loaded: `{summary.get('rule_pack', {}).get('rules_loaded')}`",
        f"Rules enabled: `{summary.get('rule_pack', {}).get('rules_enabled')}`",
        f"Errors: `{summary.get('rule_pack', {}).get('errors')}`",
    ]))
    if bundle_output:
        bundle_report = bundle_output_dir(str(out), bundle_path, privacy_mode=privacy_bundle)
        summary["bundle_summary"] = bundle_report
        summary["result_bundle"] = bundle_report.get("bundle_path")
        write_json(report_path, summary)
        bundle_output_dir(str(out), bundle_path, privacy_mode=privacy_bundle)
    return _with_engine_metadata(summary, "rule_pack.validate")


def file_av_scan_baseline(
    paths: Sequence[str],
    config: Optional[str] = None,
    baseline: Optional[str] = None,
    output_dir: Optional[str] = None,
    clean_output: bool = False,
    no_recursive: bool = False,
    include_hidden: bool = False,
    max_bytes_per_file: Optional[int] = None,
    max_archive_entries: Optional[int] = None,
    max_archive_entry_bytes: Optional[int] = None,
    no_archives: bool = False,
    scan_profile: Optional[str] = None,
    risk_profile: Optional[str] = None,
    rule_pack: Optional[str] = None,
    bundle_output: bool = False,
    bundle_path: Optional[str] = None,
    privacy_bundle: bool = True,
    history_db: Optional[str] = None,
    record_history: bool = False,
    history_notes: str = "",
) -> Dict[str, Any]:
    args = _ns(
        config=config,
        baseline=baseline,
        output_dir=output_dir,
        no_recursive=no_recursive,
        include_hidden=include_hidden,
        max_bytes_per_file=max_bytes_per_file,
        max_archive_entries=max_archive_entries,
        max_archive_entry_bytes=max_archive_entry_bytes,
        no_archives=no_archives,
        scan_profile=scan_profile,
        risk_profile=risk_profile,
        rule_pack=rule_pack,
        bundle_output=bundle_output,
        privacy_bundle=privacy_bundle,
        history_db=history_db,
        record_history=record_history,
        history_notes=history_notes,
    )
    resolved = resolve_file_av_baseline_scan_options(args)
    summary = run_file_av_scan_with_baseline(
        paths=list(paths),
        baseline=resolved["baseline"],
        output_dir=resolved["output_dir"],
        clean_output=clean_output,
        recursive=resolved["recursive"],
        include_hidden=resolved["include_hidden"],
        max_bytes_per_file=resolved["max_bytes_per_file"],
        max_archive_entries=resolved["max_archive_entries"],
        max_archive_entry_bytes=resolved["max_archive_entry_bytes"],
        scan_archives=resolved["scan_archives"],
        risk_profile=resolved["risk_profile"],
        scan_profile=resolved["scan_profile"],
        rule_pack=resolved["rule_pack"],
        bundle_output=bundle_output,
        bundle_path=bundle_path,
        privacy_bundle=privacy_bundle,
    )
    summary["config_summary"] = resolved.get("config_summary")
    if resolved.get("record_history"):
        history = record_scan_output(summary["output_dir"], resolved["history_db"], notes=resolved.get("history_notes", ""))
        summary["history_record"] = history
        write_json(Path(summary["output_dir"]) / "RUN_SUMMARY_FILE_AV_BASELINE_SCAN.json", summary)
        if bundle_output:
            bundle_report = bundle_output_dir(summary["output_dir"], bundle_path, privacy_mode=privacy_bundle)
            summary["bundle_summary"] = bundle_report
            summary["result_bundle"] = bundle_report.get("bundle_path")
            write_json(Path(summary["output_dir"]) / "RUN_SUMMARY_FILE_AV_BASELINE_SCAN.json", summary)
            bundle_output_dir(summary["output_dir"], bundle_path, privacy_mode=privacy_bundle)
    else:
        write_json(Path(summary["output_dir"]) / "RUN_SUMMARY_FILE_AV_BASELINE_SCAN.json", summary)
    return _with_engine_metadata(summary, "file_av.scan_baseline")


def _read_json_if_exists(path: Path) -> Any:
    if path.exists():
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    return None


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value if str(v)]
    if isinstance(value, str):
        if ";" in value:
            return [part.strip() for part in value.split(";") if part.strip()]
        return [value] if value else []
    return [str(value)]


def _result_items_from_report(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, dict):
        if isinstance(data.get("items"), list):
            return [dict(x) for x in data["items"] if isinstance(x, dict)]
        if isinstance(data.get("results"), list):
            return [dict(x) for x in data["results"] if isinstance(x, dict)]
    if isinstance(data, list):
        return [dict(x) for x in data if isinstance(x, dict)]
    return []


def _result_decision(item: Dict[str, Any]) -> str:
    return str(item.get("effective_decision") or item.get("decision") or item.get("original_decision") or "UNKNOWN")


def _result_original_decision(item: Dict[str, Any]) -> str:
    return str(item.get("original_decision") or item.get("decision") or "UNKNOWN")


def _result_risk(item: Dict[str, Any]) -> float:
    try:
        return float(item.get("risk_score") or item.get("risk") or 0.0)
    except Exception:
        return 0.0


def _normalize_result_item(item: Dict[str, Any]) -> Dict[str, Any]:
    labels = _as_list(item.get("labels"))
    reasons = _as_list(item.get("reasons") or item.get("reason"))
    display_path = str(item.get("display_path") or item.get("path") or item.get("source_path") or "")
    return {
        "effective_decision": _result_decision(item),
        "original_decision": _result_original_decision(item),
        "risk_score": _result_risk(item),
        "display_path": display_path,
        "source_path": str(item.get("source_path") or display_path),
        "sha256": str(item.get("sha256") or ""),
        "kind": str(item.get("kind") or ""),
        "size_bytes": item.get("size_bytes", ""),
        "baseline_status": str(item.get("baseline_status") or ""),
        "baseline_match_type": str(item.get("baseline_match_type") or ""),
        "baseline_decision": str(item.get("baseline_decision") or ""),
        "review_status": str(item.get("review_status") or ""),
        "archive_parent": str(item.get("archive_parent") or ""),
        "archive_parent_sha256": str(item.get("archive_parent_sha256") or ""),
        "magic_type": str(item.get("magic_type") or ""),
        "entropy": item.get("entropy", ""),
        "labels": labels,
        "reasons": reasons,
    }


def _matches_result_filters(row: Dict[str, Any], decision: Optional[str], label: Optional[str], text: Optional[str]) -> bool:
    if decision and decision != "ANY" and row.get("effective_decision") != decision:
        return False
    if label:
        needle = label.lower()
        if not any(needle in str(x).lower() for x in row.get("labels", [])):
            return False
    if text:
        needle = text.lower()
        haystack = " ".join([
            str(row.get("display_path", "")),
            str(row.get("sha256", "")),
            str(row.get("baseline_status", "")),
            str(row.get("baseline_match_type", "")),
            " ".join(row.get("labels", [])),
            " ".join(row.get("reasons", [])),
        ]).lower()
        if needle not in haystack:
            return False
    return True


def results_load(
    output_dir: str,
    decision: Optional[str] = None,
    label: Optional[str] = None,
    text: Optional[str] = None,
    limit: int = 500,
) -> Dict[str, Any]:
    """Load metadata-only scan results for the v4.3 Results UI.

    This reads PooleShield output JSON reports only. It does not open scanned
    files, execute anything, modify the scanned corpus, or include matched file
    contents/snippets.
    """
    out = Path(output_dir)
    if not out.exists():
        raise FileNotFoundError(f"results output folder not found: {out}")

    report_candidates = [
        out / "effective_file_av_baseline_decisions.json",
        out / "effective_file_av_decisions.json",
        out / "file_av_report.json",
    ]
    source_report = next((p for p in report_candidates if p.exists()), None)
    if source_report is None:
        raise FileNotFoundError(
            f"metadata result report not found in {out}. Expected effective_file_av_baseline_decisions.json, effective_file_av_decisions.json, or file_av_report.json."
        )

    final_summary = _read_json_if_exists(out / "FINAL_SCAN_SUMMARY.json") or {}
    bundle_manifest = _read_json_if_exists(out / "BUNDLE_MANIFEST.json") or {}
    data = _read_json_if_exists(source_report)
    raw_items = _result_items_from_report(data)
    rows = [_normalize_result_item(item) for item in raw_items]
    rows.sort(key=lambda item: (item.get("effective_decision") in {"REQUIRE_APPROVAL", "BLOCK", "QUARANTINE"}, item.get("risk_score", 0.0)), reverse=True)
    filtered = [row for row in rows if _matches_result_filters(row, decision, label, text)]
    try:
        safe_limit = max(1, min(int(limit), 5000))
    except Exception:
        safe_limit = 500

    summary = {
        "tool": "PooleShield results loader",
        "version": VERSION,
        "mode": "results-load",
        "output_dir": str(out),
        "source_report": str(source_report),
        "final_summary_path": str(out / "FINAL_SCAN_SUMMARY.json") if (out / "FINAL_SCAN_SUMMARY.json").exists() else "",
        "bundle_path": str(bundle_manifest.get("bundle_path") or ""),
        "privacy_mode": bool(bundle_manifest.get("privacy_mode", True)) if bundle_manifest else True,
        "final_verdict": final_summary.get("verdict"),
        "headline": final_summary.get("headline"),
        "items_scanned": final_summary.get("items_scanned", len(rows)),
        "baseline_matches": final_summary.get("baseline_matches"),
        "actionable_items": final_summary.get("actionable_items"),
        "by_effective_decision": final_summary.get("by_effective_decision", {}),
        "filters": {"decision": decision or "ANY", "label": label or "", "text": text or "", "limit": safe_limit},
        "total_items_available": len(rows),
        "items_after_filter": len(filtered),
        "items_returned": min(len(filtered), safe_limit),
        "items": filtered[:safe_limit],
        "safety_boundary": {
            "metadata_only": True,
            "raw_scanned_file_contents_loaded": False,
            "executed_files": False,
            "modified_files": False,
            "deleted_files": False,
            "quarantined_files": False,
        },
    }
    return _with_engine_metadata(summary, "results.load")



def _load_baseline_json(baseline: str) -> tuple[Path, Dict[str, Any]]:
    path = Path(baseline).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"trusted baseline not found: {path}")
    data = _read_json_if_exists(path)
    if not isinstance(data, dict):
        raise ValueError(f"trusted baseline is not a JSON object: {path}")
    if not isinstance(data.get("entries"), list):
        raise ValueError(f"trusted baseline has no entries list: {path}")
    return path, data


def _normalize_baseline_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    labels = _as_list(entry.get("labels"))
    hints = _as_list(entry.get("path_hints"))
    digest = str(entry.get("sha256") or "").strip().lower()
    return {
        "sha256": digest,
        "sha256_prefix": digest[:16],
        "trusted_decision": str(entry.get("trusted_decision") or ""),
        "source_effective_decision": str(entry.get("source_effective_decision") or ""),
        "kind": str(entry.get("kind") or ""),
        "size_bytes": entry.get("size_bytes", ""),
        "labels": labels,
        "path_hints": hints,
        "first_path_hint": hints[0] if hints else "",
        "first_seen": str(entry.get("first_seen") or ""),
        "last_seen": str(entry.get("last_seen") or ""),
        "review_key": str(entry.get("review_key") or ""),
        "review_notes": str(entry.get("review_notes") or ""),
    }


def _matches_baseline_filters(row: Dict[str, Any], decision: Optional[str], kind: Optional[str], text: Optional[str]) -> bool:
    if decision and decision != "ANY" and row.get("trusted_decision") != decision:
        return False
    if kind:
        needle = kind.lower()
        if needle not in str(row.get("kind", "")).lower():
            return False
    if text:
        needle = text.lower()
        haystack = " ".join([
            str(row.get("sha256", "")),
            str(row.get("trusted_decision", "")),
            str(row.get("source_effective_decision", "")),
            str(row.get("kind", "")),
            " ".join(row.get("labels", [])),
            " ".join(row.get("path_hints", [])),
            str(row.get("review_notes", "")),
        ]).lower()
        if needle not in haystack:
            return False
    return True


def baseline_load(
    baseline: str,
    decision: Optional[str] = None,
    kind: Optional[str] = None,
    text: Optional[str] = None,
    limit: int = 500,
) -> Dict[str, Any]:
    """Load a local trusted-hash baseline as metadata-only rows for v4.3.

    This reads only the local trusted baseline JSON. It does not open, execute,
    modify, delete, quarantine, or trust any scanned files.
    """
    path, data = _load_baseline_json(baseline)
    rows = [_normalize_baseline_entry(x) for x in data.get("entries", []) if isinstance(x, dict)]
    rows.sort(key=lambda item: (str(item.get("kind", "")), str(item.get("first_path_hint", "")), str(item.get("sha256", ""))))
    filtered = [row for row in rows if _matches_baseline_filters(row, decision, kind, text)]
    try:
        safe_limit = max(1, min(int(limit), 5000))
    except Exception:
        safe_limit = 500
    decisions: Dict[str, int] = {}
    kinds: Dict[str, int] = {}
    for row in rows:
        decisions[row.get("trusted_decision") or "UNKNOWN"] = decisions.get(row.get("trusted_decision") or "UNKNOWN", 0) + 1
        kinds[row.get("kind") or "UNKNOWN"] = kinds.get(row.get("kind") or "UNKNOWN", 0) + 1
    summary = data.get("summary", {}) if isinstance(data.get("summary"), dict) else {}
    result = {
        "tool": "PooleShield baseline loader",
        "version": VERSION,
        "mode": "baseline-load",
        "baseline_path": str(path),
        "baseline_version": data.get("version"),
        "generated_at": data.get("generated_at"),
        "summary": summary,
        "filters": {"decision": decision or "ANY", "kind": kind or "", "text": text or "", "limit": safe_limit},
        "total_entries_available": len(rows),
        "entries_after_filter": len(filtered),
        "entries_returned": min(len(filtered), safe_limit),
        "by_trusted_decision": decisions,
        "by_kind": kinds,
        "entries": filtered[:safe_limit],
        "safety_boundary": {
            "metadata_only": True,
            "raw_scanned_file_contents_loaded": False,
            "executed_files": False,
            "modified_files": False,
            "deleted_files": False,
            "quarantined_files": False,
            "baseline_file_modified": False,
        },
    }
    return _with_engine_metadata(result, "baseline.load")


def baseline_diff(baseline_a: str, baseline_b: str, limit: int = 500) -> Dict[str, Any]:
    """Compare two local trusted baselines by SHA256 without mutating either file."""
    path_a, data_a = _load_baseline_json(baseline_a)
    path_b, data_b = _load_baseline_json(baseline_b)
    rows_a = [_normalize_baseline_entry(x) for x in data_a.get("entries", []) if isinstance(x, dict)]
    rows_b = [_normalize_baseline_entry(x) for x in data_b.get("entries", []) if isinstance(x, dict)]
    map_a = {row["sha256"]: row for row in rows_a if row.get("sha256")}
    map_b = {row["sha256"]: row for row in rows_b if row.get("sha256")}
    added_keys = sorted(set(map_b) - set(map_a))
    removed_keys = sorted(set(map_a) - set(map_b))
    common_keys = sorted(set(map_a) & set(map_b))
    changed_keys = [k for k in common_keys if (map_a[k].get("trusted_decision"), map_a[k].get("kind"), map_a[k].get("labels")) != (map_b[k].get("trusted_decision"), map_b[k].get("kind"), map_b[k].get("labels"))]
    try:
        safe_limit = max(1, min(int(limit), 5000))
    except Exception:
        safe_limit = 500
    result = {
        "tool": "PooleShield baseline diff",
        "version": VERSION,
        "mode": "baseline-diff",
        "baseline_a": str(path_a),
        "baseline_b": str(path_b),
        "counts": {
            "entries_a": len(rows_a),
            "entries_b": len(rows_b),
            "common": len(common_keys),
            "added_in_b": len(added_keys),
            "removed_from_b": len(removed_keys),
            "metadata_changed": len(changed_keys),
        },
        "limit": safe_limit,
        "added_in_b": [map_b[k] for k in added_keys[:safe_limit]],
        "removed_from_b": [map_a[k] for k in removed_keys[:safe_limit]],
        "metadata_changed": [{"sha256": k, "a": map_a[k], "b": map_b[k]} for k in changed_keys[:safe_limit]],
        "safety_boundary": {
            "metadata_only": True,
            "raw_scanned_file_contents_loaded": False,
            "executed_files": False,
            "modified_files": False,
            "deleted_files": False,
            "quarantined_files": False,
            "baseline_files_modified": False,
        },
    }
    return _with_engine_metadata(result, "baseline.diff")


def _require_params(request: Dict[str, Any]) -> Dict[str, Any]:
    params = request.get("params", {})
    if not isinstance(params, dict):
        raise PooleShieldConfigError("engine request params must be an object")
    return params


def dispatch(request: Dict[str, Any]) -> Dict[str, Any]:
    """Run a JSON-style engine request and return a JSON-serializable response.

    Request shape:
      {"operation": "profile.show", "params": {"name": "developer"}}

    This function catches exceptions and returns a stable error response so a
    future UI can display a useful setup/path/config message without parsing a
    CLI traceback.
    """
    operation = request.get("operation") if isinstance(request, dict) else None
    if operation not in SUPPORTED_OPERATIONS:
        return {
            "ok": False,
            "engine": "PooleShield Engine API",
            "engine_version": VERSION,
            "engine_api_version": ENGINE_API_VERSION,
            "operation": operation,
            "error_type": "unsupported_operation",
            "error": f"unsupported operation: {operation}; expected one of {list(SUPPORTED_OPERATIONS)}",
        }
    params = _require_params(request)
    handlers: Dict[str, Callable[..., Dict[str, Any]]] = {
        "config.init": config_init,
        "config.validate": config_validate,
        "config.show": config_show,
        "profile.list": profile_list,
        "profile.show": profile_show,
        "history.init": history_init,
        "history.record": history_record,
        "history.list": history_list,
        "history.show": history_show,
        "rule_pack.validate": rule_pack_validate,
        "file_av.scan_baseline": file_av_scan_baseline,
        "results.load": results_load,
        "baseline.load": baseline_load,
        "baseline.diff": baseline_diff,
    }
    try:
        result = handlers[operation](**params)
        return {
            "ok": True,
            "engine": "PooleShield Engine API",
            "engine_version": VERSION,
            "engine_api_version": ENGINE_API_VERSION,
            "operation": operation,
            "result": result,
        }
    except Exception as exc:  # UI-ready structured error, not silent failure.
        return {
            "ok": False,
            "engine": "PooleShield Engine API",
            "engine_version": VERSION,
            "engine_api_version": ENGINE_API_VERSION,
            "operation": operation,
            "error_type": type(exc).__name__,
            "error": str(exc),
        }


def dispatch_file(request_path: str, output_path: Optional[str] = None) -> Dict[str, Any]:
    request = json.loads(Path(request_path).read_text(encoding="utf-8"))
    response = dispatch(request)
    if output_path:
        write_json(output_path, response)
    return response
