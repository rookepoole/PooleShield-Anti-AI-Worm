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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

VERSION = "4.1.0"
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
