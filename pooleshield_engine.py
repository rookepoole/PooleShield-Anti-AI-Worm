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
from typing import Any, Callable, Dict, Optional, Sequence

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

VERSION = "4.0.0"
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
