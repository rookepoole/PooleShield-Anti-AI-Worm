#!/usr/bin/env python3
"""
PooleShield v3.4 local file-AV rule pack support.

Rule packs are defensive, local JSON files that add labels/risk deltas to the
read-only file scanner. They never execute scanned content, modify files,
delete files, quarantine files, or override trusted-baseline decisions.

Supported rule types:
  - filename_regex: match basename/display path
  - path_regex: match full display path
  - archive_entry_regex: match archive-entry display paths containing '!'
  - text_regex: match decoded text for text-like/script files only
  - extension: match file extension from display path
  - magic_type: match detected magic_type
  - label_has: match labels already produced by the built-in scanner

Actions:
  - label: label to add when matched
  - risk_delta: non-negative float added to risk, capped later by scanner
  - reason: human-readable audit reason

Design note: rule packs are for additional detection/tuning. Broad trust/allow
behavior belongs in the trusted hash baseline, not in rule packs.
"""
from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

VERSION = "5.2.1"
SUPPORTED_TYPES = {
    "filename_regex",
    "path_regex",
    "archive_entry_regex",
    "text_regex",
    "extension",
    "magic_type",
    "label_has",
}


class RulePackError(ValueError):
    pass


@dataclass
class RulePackResult:
    path: str
    version: str
    rules_loaded: int
    rules_enabled: int
    errors: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "version": self.version,
            "rules_loaded": self.rules_loaded,
            "rules_enabled": self.rules_enabled,
            "errors": list(self.errors),
        }


def read_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise RulePackError("rule pack root must be a JSON object")
    return data


def normalize_rule_pack_path(rule_pack: Optional[str]) -> Optional[Path]:
    if not rule_pack:
        return None
    path = Path(rule_pack).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"rule pack not found: {path}. Use --rule-pack with an existing JSON file or omit it.")
    return path


def validate_rule_pack_data(data: Dict[str, Any], path: str = "") -> RulePackResult:
    errors: List[str] = []
    rules = data.get("rules", [])
    if not isinstance(rules, list):
        errors.append("rules must be a list")
        rules = []
    enabled = 0
    for idx, rule in enumerate(rules):
        prefix = f"rules[{idx}]"
        if not isinstance(rule, dict):
            errors.append(f"{prefix} must be an object")
            continue
        if rule.get("enabled", True):
            enabled += 1
        rtype = rule.get("type")
        if rtype not in SUPPORTED_TYPES:
            errors.append(f"{prefix}.type must be one of {sorted(SUPPORTED_TYPES)}")
        label = rule.get("label")
        if not isinstance(label, str) or not label.strip():
            errors.append(f"{prefix}.label must be a non-empty string")
        risk_delta = rule.get("risk_delta", 0.0)
        if not isinstance(risk_delta, (int, float)) or risk_delta < 0 or risk_delta > 1:
            errors.append(f"{prefix}.risk_delta must be a number from 0 to 1")
        if rtype in {"filename_regex", "path_regex", "archive_entry_regex", "text_regex"}:
            pattern = rule.get("pattern")
            if not isinstance(pattern, str) or not pattern:
                errors.append(f"{prefix}.pattern must be a non-empty regex string")
            else:
                try:
                    re.compile(pattern)
                except re.error as exc:
                    errors.append(f"{prefix}.pattern invalid regex: {exc}")
        elif rtype == "extension":
            exts = rule.get("extensions")
            if not isinstance(exts, list) or not all(isinstance(x, str) and x.startswith(".") for x in exts):
                errors.append(f"{prefix}.extensions must be a list of dot-prefixed extensions")
        elif rtype == "magic_type":
            magic = rule.get("magic_types")
            if not isinstance(magic, list) or not all(isinstance(x, str) and x for x in magic):
                errors.append(f"{prefix}.magic_types must be a list of strings")
        elif rtype == "label_has":
            labels = rule.get("labels")
            if not isinstance(labels, list) or not all(isinstance(x, str) and x for x in labels):
                errors.append(f"{prefix}.labels must be a list of strings")
    return RulePackResult(
        path=path,
        version=str(data.get("version", "unknown")),
        rules_loaded=len(rules),
        rules_enabled=enabled,
        errors=errors,
    )


def load_rule_pack(rule_pack: Optional[str]) -> Optional[Dict[str, Any]]:
    path = normalize_rule_pack_path(rule_pack)
    if not path:
        return None
    data = read_json(path)
    result = validate_rule_pack_data(data, str(path))
    if result.errors:
        raise RulePackError("invalid rule pack: " + "; ".join(result.errors))
    data["_rule_pack_path"] = str(path)
    data["_validation"] = result.to_dict()
    return data


def validate_rule_pack_file(rule_pack: str) -> Dict[str, Any]:
    path = normalize_rule_pack_path(rule_pack)
    assert path is not None
    data = read_json(path)
    result = validate_rule_pack_data(data, str(path))
    return {
        "tool": "PooleShield file AV rule pack validator",
        "version": VERSION,
        "valid": not result.errors,
        "rule_pack": result.to_dict(),
    }



def _safe_limit(limit: int) -> int:
    try:
        return max(1, min(int(limit), 5000))
    except Exception:
        return 500


def _normalize_rule(rule: Dict[str, Any], index: int) -> Dict[str, Any]:
    rtype = str(rule.get("type") or "")
    return {
        "index": index,
        "id": str(rule.get("id") or f"rule_{index}"),
        "enabled": bool(rule.get("enabled", True)),
        "type": rtype,
        "label": str(rule.get("label") or ""),
        "risk_delta": float(rule.get("risk_delta", 0.0) or 0.0),
        "reason": str(rule.get("reason") or ""),
        "pattern": str(rule.get("pattern") or ""),
        "extensions": [str(x) for x in rule.get("extensions", [])] if isinstance(rule.get("extensions", []), list) else [],
        "magic_types": [str(x) for x in rule.get("magic_types", [])] if isinstance(rule.get("magic_types", []), list) else [],
        "labels": [str(x) for x in rule.get("labels", [])] if isinstance(rule.get("labels", []), list) else [],
    }


def _rule_matches_filters(row: Dict[str, Any], enabled: Optional[str], type_filter: str, text: str) -> bool:
    if enabled and enabled != "ANY":
        want = enabled.lower()
        if want in {"true", "enabled", "yes", "1"} and not row.get("enabled"):
            return False
        if want in {"false", "disabled", "no", "0"} and row.get("enabled"):
            return False
    if type_filter and type_filter.lower() not in str(row.get("type", "")).lower():
        return False
    if text:
        needle = text.lower()
        haystack = " ".join([
            str(row.get("id", "")),
            str(row.get("type", "")),
            str(row.get("label", "")),
            str(row.get("reason", "")),
            str(row.get("pattern", "")),
            " ".join(row.get("extensions", [])),
            " ".join(row.get("magic_types", [])),
            " ".join(row.get("labels", [])),
        ]).lower()
        if needle not in haystack:
            return False
    return True


def summarize_rule_pack_file(rule_pack: str, enabled: str = "ANY", type_filter: str = "", text: str = "", limit: int = 500) -> Dict[str, Any]:
    """Load a rule pack as metadata for the local Rule Pack Editor UI."""
    path = normalize_rule_pack_path(rule_pack)
    assert path is not None
    data = read_json(path)
    validation = validate_rule_pack_data(data, str(path))
    rules_raw = data.get("rules", [])
    if not isinstance(rules_raw, list):
        rules_raw = []
    rows = [_normalize_rule(rule, idx) for idx, rule in enumerate(rules_raw) if isinstance(rule, dict)]
    filtered = [row for row in rows if _rule_matches_filters(row, enabled, type_filter, text)]
    safe_limit = _safe_limit(limit)
    by_type: Dict[str, int] = {}
    for row in rows:
        key = row.get("type") or "UNKNOWN"
        by_type[key] = by_type.get(key, 0) + 1
    return {
        "tool": "PooleShield rule pack loader",
        "version": VERSION,
        "mode": "rule-pack-load",
        "rule_pack_path": str(path),
        "rule_pack_version": str(data.get("version", "unknown")),
        "valid": not validation.errors,
        "validation": validation.to_dict(),
        "filters": {"enabled": enabled or "ANY", "type": type_filter or "", "text": text or "", "limit": safe_limit},
        "total_rules_available": len(rows),
        "rules_after_filter": len(filtered),
        "rules_returned": min(len(filtered), safe_limit),
        "rules_enabled": sum(1 for row in rows if row.get("enabled")),
        "rules_disabled": sum(1 for row in rows if not row.get("enabled")),
        "by_type": by_type,
        "rules": filtered[:safe_limit],
        "safety_boundary": {
            "metadata_only": True,
            "scanned_files_opened": False,
            "executed_files": False,
            "modified_scanned_files": False,
            "rule_pack_modified": False,
        },
    }


def export_default_rule_pack(output_path: str, default_path: str = "examples/rule_packs/file_av_rules.default.json", force: bool = False) -> Dict[str, Any]:
    """Copy the public default rule pack to a local editable path."""
    src = normalize_rule_pack_path(default_path)
    assert src is not None
    dst = Path(output_path).expanduser()
    if dst.exists() and not force:
        raise FileExistsError(f"output rule pack already exists: {dst}. Use force=true or --force to overwrite.")
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)
    return {
        "tool": "PooleShield rule pack export default",
        "version": VERSION,
        "mode": "rule-pack-export-default",
        "source_rule_pack": str(src),
        "output_rule_pack": str(dst),
        "overwrote_existing": bool(force),
        "validation": validate_rule_pack_file(str(dst)),
        "safety_boundary": {
            "scanned_files_opened": False,
            "executed_files": False,
            "modified_scanned_files": False,
            "rule_pack_modified": True,
            "write_target": "rule_pack_json_only",
        },
    }


def _find_rule_index(rules: List[Any], rule_id: Optional[str], index: Optional[int]) -> int:
    if index is not None:
        idx = int(index)
        if idx < 0 or idx >= len(rules):
            raise IndexError(f"rule index out of range: {idx}")
        if not isinstance(rules[idx], dict):
            raise RulePackError(f"rules[{idx}] is not an object")
        return idx
    if rule_id:
        for idx, rule in enumerate(rules):
            if isinstance(rule, dict) and str(rule.get("id") or "") == str(rule_id):
                return idx
        raise KeyError(f"rule id not found: {rule_id}")
    raise RulePackError("rule_id or index is required")


def update_rule_pack_rule(
    rule_pack: str,
    output_path: str,
    *,
    rule_id: Optional[str] = None,
    index: Optional[int] = None,
    enabled: Optional[bool] = None,
    risk_delta: Optional[float] = None,
    label: Optional[str] = None,
    pattern: Optional[str] = None,
    reason: Optional[str] = None,
) -> Dict[str, Any]:
    """Write an edited rule-pack copy. It never scans or modifies scanned files."""
    src = normalize_rule_pack_path(rule_pack)
    assert src is not None
    data = read_json(src)
    rules = data.get("rules", [])
    if not isinstance(rules, list):
        raise RulePackError("rules must be a list before a rule can be edited")
    idx = _find_rule_index(rules, rule_id, index)
    before = dict(rules[idx])
    if enabled is not None:
        rules[idx]["enabled"] = bool(enabled)
    if risk_delta is not None:
        value = float(risk_delta)
        if value < 0 or value > 1:
            raise RulePackError("risk_delta must be between 0 and 1")
        rules[idx]["risk_delta"] = value
    if label is not None:
        if not str(label).strip():
            raise RulePackError("label must be non-empty")
        rules[idx]["label"] = str(label).strip()
    if pattern is not None:
        re.compile(str(pattern))
        rules[idx]["pattern"] = str(pattern)
    if reason is not None:
        rules[idx]["reason"] = str(reason)
    validation = validate_rule_pack_data(data, str(src))
    if validation.errors:
        raise RulePackError("updated rule pack would be invalid: " + "; ".join(validation.errors))
    dst = Path(output_path).expanduser()
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return {
        "tool": "PooleShield rule pack update rule",
        "version": VERSION,
        "mode": "rule-pack-update-rule",
        "source_rule_pack": str(src),
        "output_rule_pack": str(dst),
        "rule_index": idx,
        "rule_id": str(rules[idx].get("id") or ""),
        "before": _normalize_rule(before, idx),
        "after": _normalize_rule(rules[idx], idx),
        "validation": validate_rule_pack_file(str(dst)),
        "safety_boundary": {
            "scanned_files_opened": False,
            "executed_files": False,
            "modified_scanned_files": False,
            "rule_pack_modified": True,
            "write_target": "rule_pack_json_only",
        },
    }

def _regex_search(pattern: str, text: str) -> bool:
    return re.search(pattern, text or "") is not None


def _match_rule(rule: Dict[str, Any], *, display_path: str, suffix: str, magic_type: str, labels: Sequence[str], text: Optional[str]) -> bool:
    rtype = rule.get("type")
    if rtype == "filename_regex":
        return _regex_search(str(rule.get("pattern", "")), Path(display_path.replace("!", "/")).name or display_path)
    if rtype == "path_regex":
        return _regex_search(str(rule.get("pattern", "")), display_path)
    if rtype == "archive_entry_regex":
        return "!" in display_path and _regex_search(str(rule.get("pattern", "")), display_path)
    if rtype == "text_regex":
        return text is not None and _regex_search(str(rule.get("pattern", "")), text)
    if rtype == "extension":
        return suffix.lower() in {str(x).lower() for x in rule.get("extensions", [])}
    if rtype == "magic_type":
        return magic_type in {str(x) for x in rule.get("magic_types", [])}
    if rtype == "label_has":
        return bool(set(labels).intersection({str(x) for x in rule.get("labels", [])}))
    return False


def apply_rule_pack(
    rule_pack: Optional[Dict[str, Any]],
    *,
    display_path: str,
    suffix: str,
    magic_type: str,
    labels: List[str],
    reasons: List[str],
    risk: float,
    text: Optional[str] = None,
) -> float:
    if not rule_pack:
        return risk
    for rule in rule_pack.get("rules", []):
        if not isinstance(rule, dict) or not rule.get("enabled", True):
            continue
        if not _match_rule(rule, display_path=display_path, suffix=suffix, magic_type=magic_type, labels=labels, text=text):
            continue
        label = str(rule.get("label", "rule_pack_match")).strip() or "rule_pack_match"
        labels.append(label)
        delta = float(rule.get("risk_delta", 0.0) or 0.0)
        risk += max(0.0, delta)
        reason = str(rule.get("reason", "matched local file AV rule pack rule")).strip()
        rid = str(rule.get("id", "unnamed_rule")).strip()
        if reason:
            reasons.append(f"rule_pack:{rid}: {reason}")
    return risk


def rule_pack_summary(rule_pack: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not rule_pack:
        return {"enabled": False, "rules_loaded": 0, "rules_enabled": 0, "path": ""}
    validation = rule_pack.get("_validation") or {}
    return {
        "enabled": True,
        "path": rule_pack.get("_rule_pack_path", ""),
        "version": rule_pack.get("version", "unknown"),
        "rules_loaded": validation.get("rules_loaded", len(rule_pack.get("rules", []))),
        "rules_enabled": validation.get("rules_enabled", sum(1 for r in rule_pack.get("rules", []) if isinstance(r, dict) and r.get("enabled", True))),
    }
