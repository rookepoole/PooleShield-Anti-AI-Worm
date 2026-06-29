#!/usr/bin/env python3
"""PooleShield local configuration helpers.

Defensive purpose:
  Keep local operator defaults in one validated JSON file without committing
  private baselines, scan outputs, or machine-specific paths to the public repo.
"""
from __future__ import annotations

import json
import os
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

VERSION = "3.7.0"
CONFIG_FILENAMES = ("pooleshield_config.json", ".pooleshield_config.json")
RISK_PROFILES = {"standard", "developer"}
POLICY_PROFILES = {"balanced", "strict"}


class PooleShieldConfigError(ValueError):
    """Raised when a config file is malformed or missing a required default."""


DEFAULT_CONFIG: Dict[str, Any] = {
    "tool": "PooleShield",
    "version": VERSION,
    "profile_name": "local-defaults",
    "description": "Local PooleShield defaults. Keep machine-specific/private paths out of Git.",
    "defaults": {
        "output_root": "out",
        "file_av_output_dir": "out/file_av_scan",
        "file_av_baseline_scan_output_dir": "out/file_av_baseline_scan",
        "rule_pack": "examples/rule_packs/file_av_rules.default.json",
        "baseline": "local_trust/trusted_file_baseline.json",
        "risk_profile": "standard",
        "policy_profile": "balanced",
        "privacy_bundle": True,
        "bundle_output": False,
    },
    "limits": {
        "max_bytes_per_file": 5 * 1024 * 1024,
        "max_archive_entries": 500,
        "max_archive_entry_bytes": 2 * 1024 * 1024,
    },
    "safety": {
        "read_only": True,
        "dry_run_only": True,
        "do_not_execute_scanned_files": True,
        "do_not_delete_or_quarantine_by_default": True,
    },
}


def default_config() -> Dict[str, Any]:
    return deepcopy(DEFAULT_CONFIG)


def expand_config_path(value: Optional[str], base_dir: Optional[Path] = None) -> Optional[str]:
    if value is None or value == "":
        return value
    expanded = os.path.expandvars(str(value))
    expanded = os.path.expanduser(expanded)
    p = Path(expanded)
    if not p.is_absolute() and base_dir is not None:
        p = base_dir / p
    return str(p)


def merge_config(user_config: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    cfg = default_config()
    if not user_config:
        return cfg
    for key, value in user_config.items():
        if isinstance(value, dict) and isinstance(cfg.get(key), dict):
            cfg[key].update(value)
        else:
            cfg[key] = value
    return cfg


def find_config_file(start: Optional[Path] = None) -> Optional[Path]:
    start = (start or Path.cwd()).resolve()
    for name in CONFIG_FILENAMES:
        p = start / name
        if p.exists():
            return p
    return None


def load_config(path: Optional[str] = None, cwd: Optional[Path] = None) -> Tuple[Dict[str, Any], Optional[Path]]:
    config_path: Optional[Path]
    if path:
        config_path = Path(path).expanduser()
        if not config_path.exists():
            raise PooleShieldConfigError(f"config file not found: {config_path}")
    else:
        config_path = find_config_file(cwd)
    if config_path is None:
        return default_config(), None
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PooleShieldConfigError(f"config JSON parse error in {config_path}: {exc}") from exc
    if not isinstance(data, dict):
        raise PooleShieldConfigError("config root must be a JSON object")
    cfg = merge_config(data)
    return cfg, config_path


def write_default_config(path: str, force: bool = False) -> Dict[str, Any]:
    p = Path(path).expanduser()
    if p.exists() and not force:
        raise PooleShieldConfigError(f"config already exists: {p}. Use --force to overwrite.")
    p.parent.mkdir(parents=True, exist_ok=True)
    cfg = default_config()
    p.write_text(json.dumps(cfg, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return {"path": str(p), "created": True, "version": VERSION, "config": cfg}


def validate_config(cfg: Dict[str, Any], config_path: Optional[Path] = None, require_existing_paths: bool = False) -> Dict[str, Any]:
    errors: List[str] = []
    warnings: List[str] = []
    defaults = cfg.get("defaults")
    limits = cfg.get("limits")
    safety = cfg.get("safety")
    if not isinstance(defaults, dict):
        errors.append("defaults must be an object")
        defaults = {}
    if not isinstance(limits, dict):
        errors.append("limits must be an object")
        limits = {}
    if not isinstance(safety, dict):
        errors.append("safety must be an object")
        safety = {}

    risk_profile = defaults.get("risk_profile")
    if risk_profile not in RISK_PROFILES:
        errors.append(f"defaults.risk_profile must be one of {sorted(RISK_PROFILES)}")
    policy_profile = defaults.get("policy_profile")
    if policy_profile not in POLICY_PROFILES:
        errors.append(f"defaults.policy_profile must be one of {sorted(POLICY_PROFILES)}")
    for key in ("privacy_bundle", "bundle_output"):
        if not isinstance(defaults.get(key), bool):
            errors.append(f"defaults.{key} must be true or false")

    for key in ("max_bytes_per_file", "max_archive_entries", "max_archive_entry_bytes"):
        value = limits.get(key)
        if not isinstance(value, int) or value <= 0:
            errors.append(f"limits.{key} must be a positive integer")

    for key in ("read_only", "dry_run_only", "do_not_execute_scanned_files", "do_not_delete_or_quarantine_by_default"):
        if safety.get(key) is not True:
            errors.append(f"safety.{key} must be true")

    base_dir = config_path.parent if config_path else Path.cwd()
    resolved_paths: Dict[str, Optional[str]] = {}
    for key in ("output_root", "file_av_output_dir", "file_av_baseline_scan_output_dir", "rule_pack", "baseline"):
        value = defaults.get(key)
        if not isinstance(value, str) or not value:
            errors.append(f"defaults.{key} must be a non-empty string")
            resolved_paths[key] = None
            continue
        resolved = expand_config_path(value, base_dir=base_dir)
        resolved_paths[key] = resolved
        if require_existing_paths and key in {"rule_pack", "baseline"} and resolved and not Path(resolved).exists():
            warnings.append(f"configured {key} path does not exist yet: {resolved}")

    return {
        "tool": "PooleShield config validation",
        "version": VERSION,
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "config_path": str(config_path) if config_path else None,
        "resolved_paths": resolved_paths,
        "effective_defaults": defaults,
        "effective_limits": limits,
        "safety": safety,
    }


def load_and_validate_config(path: Optional[str] = None, cwd: Optional[Path] = None, require_existing_paths: bool = False) -> Tuple[Dict[str, Any], Optional[Path], Dict[str, Any]]:
    cfg, config_path = load_config(path=path, cwd=cwd)
    validation = validate_config(cfg, config_path=config_path, require_existing_paths=require_existing_paths)
    if not validation.get("valid"):
        raise PooleShieldConfigError("config validation failed: " + "; ".join(validation.get("errors") or []))
    return cfg, config_path, validation


def bool_from_config_or_arg(arg_value: Optional[bool], default_value: bool) -> bool:
    return default_value if arg_value is None else bool(arg_value)


def resolve_file_av_baseline_scan_options(args: Any) -> Dict[str, Any]:
    cfg, config_path, validation = load_and_validate_config(getattr(args, "config", None))
    defaults = cfg.get("defaults", {})
    limits = cfg.get("limits", {})
    base_dir = config_path.parent if config_path else Path.cwd()

    baseline = getattr(args, "baseline", None) or defaults.get("baseline")
    if not baseline:
        raise PooleShieldConfigError("baseline is required; pass --baseline or set defaults.baseline in config")
    output_dir = getattr(args, "output_dir", None) or defaults.get("file_av_baseline_scan_output_dir") or "out/file_av_baseline_scan"
    risk_profile = getattr(args, "risk_profile", None) or defaults.get("risk_profile", "standard")
    rule_pack = getattr(args, "rule_pack", None) or defaults.get("rule_pack")

    resolved = {
        "baseline": expand_config_path(baseline, base_dir=base_dir),
        "output_dir": expand_config_path(output_dir, base_dir=base_dir) or "out/file_av_baseline_scan",
        "risk_profile": risk_profile,
        "rule_pack": expand_config_path(rule_pack, base_dir=base_dir) if rule_pack else None,
        "max_bytes_per_file": getattr(args, "max_bytes_per_file", None) or limits.get("max_bytes_per_file", 5 * 1024 * 1024),
        "max_archive_entries": getattr(args, "max_archive_entries", None) or limits.get("max_archive_entries", 500),
        "max_archive_entry_bytes": getattr(args, "max_archive_entry_bytes", None) or limits.get("max_archive_entry_bytes", 2 * 1024 * 1024),
        "privacy_bundle": getattr(args, "privacy_bundle", defaults.get("privacy_bundle", True)),
        "bundle_output": getattr(args, "bundle_output", defaults.get("bundle_output", False)),
        "config_summary": {
            "config_path": str(config_path) if config_path else None,
            "used_config_file": config_path is not None,
            "validation": validation,
        },
    }
    if resolved["risk_profile"] not in RISK_PROFILES:
        raise PooleShieldConfigError(f"risk_profile must be one of {sorted(RISK_PROFILES)}")
    return resolved


def resolve_rule_pack_validate_options(args: Any) -> Dict[str, Any]:
    cfg, config_path, validation = load_and_validate_config(getattr(args, "config", None))
    defaults = cfg.get("defaults", {})
    base_dir = config_path.parent if config_path else Path.cwd()
    rule_pack = getattr(args, "rule_pack", None) or defaults.get("rule_pack")
    if not rule_pack:
        raise PooleShieldConfigError("rule pack is required; pass --rule-pack or set defaults.rule_pack in config")
    output_dir = getattr(args, "output_dir", None) or "out/rule_pack_validate"
    return {
        "rule_pack": expand_config_path(rule_pack, base_dir=base_dir),
        "output_dir": expand_config_path(output_dir, base_dir=base_dir) or "out/rule_pack_validate",
        "config_summary": {
            "config_path": str(config_path) if config_path else None,
            "used_config_file": config_path is not None,
            "validation": validation,
        },
    }
