#!/usr/bin/env python3
"""PooleShield scan profile definitions.

Defensive purpose:
  Provide named, auditable scan-intensity defaults without changing the core
  read-only safety boundary. Profiles tune local scan breadth/depth; they do
  not execute, delete, quarantine, or silently trust files.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping, Optional

VERSION = "5.2.1"

SCAN_PROFILE_NAMES = (
    "quick",
    "standard",
    "developer",
    "strict",
    "deep",
    "archive-heavy",
    "privacy-sensitive",
)

DEFAULT_SCAN_PROFILES: Dict[str, Dict[str, Any]] = {
    "quick": {
        "description": "Fast triage scan for a trusted folder; skips archive expansion and uses small read limits.",
        "risk_profile": "standard",
        "recursive": True,
        "include_hidden": False,
        "scan_archives": False,
        "max_bytes_per_file": 1 * 1024 * 1024,
        "max_archive_entries": 50,
        "max_archive_entry_bytes": 512 * 1024,
        "privacy_bundle": True,
    },
    "standard": {
        "description": "Balanced everyday second-opinion scan with archive expansion enabled.",
        "risk_profile": "standard",
        "recursive": True,
        "include_hidden": False,
        "scan_archives": True,
        "max_bytes_per_file": 5 * 1024 * 1024,
        "max_archive_entries": 500,
        "max_archive_entry_bytes": 2 * 1024 * 1024,
        "privacy_bundle": True,
    },
    "developer": {
        "description": "Developer/source-tree scan that reduces noise for known code/tooling contexts while still logging review-worthy items.",
        "risk_profile": "developer",
        "recursive": True,
        "include_hidden": False,
        "scan_archives": True,
        "max_bytes_per_file": 5 * 1024 * 1024,
        "max_archive_entries": 500,
        "max_archive_entry_bytes": 2 * 1024 * 1024,
        "privacy_bundle": True,
    },
    "strict": {
        "description": "Conservative scan for untrusted downloads; includes hidden files and expands archives with higher limits.",
        "risk_profile": "standard",
        "recursive": True,
        "include_hidden": True,
        "scan_archives": True,
        "max_bytes_per_file": 8 * 1024 * 1024,
        "max_archive_entries": 1000,
        "max_archive_entry_bytes": 4 * 1024 * 1024,
        "privacy_bundle": True,
    },
    "deep": {
        "description": "Slower broad scan for larger local folders; includes hidden files and uses high read/archive limits.",
        "risk_profile": "standard",
        "recursive": True,
        "include_hidden": True,
        "scan_archives": True,
        "max_bytes_per_file": 25 * 1024 * 1024,
        "max_archive_entries": 3000,
        "max_archive_entry_bytes": 8 * 1024 * 1024,
        "privacy_bundle": True,
    },
    "archive-heavy": {
        "description": "Archive-focused scan for folders with many ZIP/JAR/Office-container files.",
        "risk_profile": "standard",
        "recursive": True,
        "include_hidden": False,
        "scan_archives": True,
        "max_bytes_per_file": 10 * 1024 * 1024,
        "max_archive_entries": 5000,
        "max_archive_entry_bytes": 10 * 1024 * 1024,
        "privacy_bundle": True,
    },
    "privacy-sensitive": {
        "description": "Low-content-exposure scan for private folders; uses smaller read limits and privacy bundles by default.",
        "risk_profile": "standard",
        "recursive": True,
        "include_hidden": False,
        "scan_archives": True,
        "max_bytes_per_file": 2 * 1024 * 1024,
        "max_archive_entries": 250,
        "max_archive_entry_bytes": 1 * 1024 * 1024,
        "privacy_bundle": True,
    },
}

_REQUIRED_BOOL_KEYS = {"recursive", "include_hidden", "scan_archives", "privacy_bundle"}
_REQUIRED_INT_KEYS = {"max_bytes_per_file", "max_archive_entries", "max_archive_entry_bytes"}
_REQUIRED_STRING_KEYS = {"description", "risk_profile"}
_RISK_PROFILES = {"standard", "developer"}


class ScanProfileError(ValueError):
    """Raised when a scan profile is unknown or malformed."""


def built_in_profiles() -> Dict[str, Dict[str, Any]]:
    return deepcopy(DEFAULT_SCAN_PROFILES)


def _merged_profiles(overrides: Optional[Mapping[str, Any]] = None) -> Dict[str, Dict[str, Any]]:
    profiles = built_in_profiles()
    if isinstance(overrides, Mapping):
        for name, override in overrides.items():
            if name not in profiles or not isinstance(override, Mapping):
                continue
            merged = dict(profiles[name])
            merged.update(dict(override))
            profiles[name] = merged
    return profiles


def validate_profile(name: str, profile: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if name not in SCAN_PROFILE_NAMES:
        errors.append(f"unknown scan profile: {name}")
    for key in _REQUIRED_STRING_KEYS:
        if not isinstance(profile.get(key), str) or not profile.get(key):
            errors.append(f"scan_profiles.{name}.{key} must be a non-empty string")
    if profile.get("risk_profile") not in _RISK_PROFILES:
        errors.append(f"scan_profiles.{name}.risk_profile must be one of {sorted(_RISK_PROFILES)}")
    for key in _REQUIRED_BOOL_KEYS:
        if not isinstance(profile.get(key), bool):
            errors.append(f"scan_profiles.{name}.{key} must be true or false")
    for key in _REQUIRED_INT_KEYS:
        value = profile.get(key)
        if not isinstance(value, int) or value <= 0:
            errors.append(f"scan_profiles.{name}.{key} must be a positive integer")
    return errors


def validate_scan_profile_overrides(overrides: Optional[Mapping[str, Any]] = None) -> list[str]:
    errors: list[str] = []
    if overrides is not None and not isinstance(overrides, Mapping):
        return ["scan_profiles must be an object when provided"]
    if isinstance(overrides, Mapping):
        for name, value in overrides.items():
            if name not in SCAN_PROFILE_NAMES:
                errors.append(f"scan_profiles contains unknown profile name: {name}")
            if not isinstance(value, Mapping):
                errors.append(f"scan_profiles.{name} must be an object")
    for name, profile in _merged_profiles(overrides).items():
        errors.extend(validate_profile(name, profile))
    return errors


def get_scan_profile(name: str, overrides: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    profiles = _merged_profiles(overrides)
    if name not in profiles:
        raise ScanProfileError(f"unknown scan profile: {name}; expected one of {list(SCAN_PROFILE_NAMES)}")
    profile = profiles[name]
    errors = validate_profile(name, profile)
    if errors:
        raise ScanProfileError("; ".join(errors))
    out = deepcopy(profile)
    out["name"] = name
    return out


def profile_catalog(overrides: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    profiles = _merged_profiles(overrides)
    return {
        "tool": "PooleShield scan profiles",
        "version": VERSION,
        "profile_names": list(SCAN_PROFILE_NAMES),
        "profiles": {name: dict(profiles[name]) for name in SCAN_PROFILE_NAMES},
    }
