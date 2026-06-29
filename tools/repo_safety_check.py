#!/usr/bin/env python3
"""
PooleShield repository safety check.

Defensive purpose:
  Fail CI if private/generated scan artifacts are accidentally committed.

This tool scans repository paths and file contents for high-confidence leak
patterns. It is intentionally conservative for runtime output folders and
private baseline/evidence files, while allowing the small synthetic fixtures
that are part of the public test suite.
"""
from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List

VERSION = "5.1.1"

FORBIDDEN_DIR_NAMES = {
    "out",
    "local_trust",
    "local_history",
    "local_rule_packs",
    "dist",
    "build",
    "portable_build",
    "installer_build",
    "installer_output",
    "installer_release",
    "installer_scripts",
    ".venv-build",
    "extracted_dat_text",
    "extracted_dat_content",
    "extracted_text_like",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "__pycache__",
}

FORBIDDEN_FILE_NAMES = {
    "pooleshield_results_bundle.zip",
    "BUNDLE_MANIFEST.json",
    "PRIVACY_BUNDLE_NOTE.md",
    "normalized_events.jsonl",
    "review_evidence_local.md",
    "review_evidence_report.json",
    "trusted_file_baseline.json",
    "trusted_file_baseline.csv",
    "trusted_file_baseline.md",
    "pooleshield_config.json",
    ".pooleshield_config.json",
    "pooleshield_scan_history.sqlite",
    "pooleshield_history.sqlite",
    "engine_request.json",
    "engine_response.json",
    "results_response.json",
    "baseline_response.json",
    "baseline_diff_response.json",
    "rule_pack_response.json",
    "rule_pack_export_response.json",
    "rule_pack_update_response.json",
    "portable_build_plan.json",
    "portable_build_result.json",
    "installer_build_plan.json",
    "installer_build_result.json",
    "installer_compile_result.json",
    "PooleShield.exe",
}

FORBIDDEN_SUFFIXES = {
    ".dat",
    ".pyc",
    ".pyo",
    ".sqlite",
    ".sqlite3",
    ".db",
    ".exe",
    ".msi",
    ".msix",
    ".spec",
    ".iss",
}

ALLOWED_PUBLIC_FIXTURES = {
    "examples/file_av_fixture/fixture_archive.zip",
    "examples/dat_fixture/nested_dat_bundle.zip",
    "examples/dat_fixture/chat_json_like.dat",
    "examples/dat_fixture/image_like.dat",
    "examples/dat_fixture/plain_text_like.dat",
}

SECRET_PATTERNS = [
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{24,}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{20,}\b")),
]

TEXT_SUFFIXES = {
    ".py", ".md", ".txt", ".json", ".jsonl", ".yml", ".yaml", ".csv",
    ".ps1", ".bat", ".cmd", ".toml", ".ini", ".cfg", ".gitignore",
}

@dataclass
class Finding:
    path: str
    reason: str


def rel_posix(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def should_skip_tree(path: Path) -> bool:
    parts = set(path.parts)
    # Ignore local runtime/tooling directories so this check can run after pytest.
    # CI still protects committed leaks because forbidden runtime/private paths
    # such as out/ and local_trust/ are not skipped.
    return bool(parts.intersection({".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}))


def iter_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if should_skip_tree(path):
            continue
        if path.is_file():
            yield path


def is_allowed_fixture(rel: str) -> bool:
    return rel in ALLOWED_PUBLIC_FIXTURES


def scan_paths(root: Path) -> List[Finding]:
    findings: List[Finding] = []
    forbidden_names_lower = {x.lower() for x in FORBIDDEN_FILE_NAMES}
    for path in iter_files(root):
        rel = rel_posix(path, root)
        if is_allowed_fixture(rel):
            continue
        parts_lower = {p.lower() for p in path.relative_to(root).parts}
        blocked_parts = parts_lower.intersection(FORBIDDEN_DIR_NAMES)
        if blocked_parts:
            findings.append(Finding(rel, f"forbidden generated/private directory component: {sorted(blocked_parts)}"))
            continue
        name = path.name
        lower_name = name.lower()
        if lower_name in forbidden_names_lower:
            findings.append(Finding(rel, f"forbidden private/generated filename: {name}"))
            continue
        if lower_name.endswith("pooleshield_results_bundle.zip") or lower_name.endswith("_results_bundle.zip"):
            findings.append(Finding(rel, "forbidden result bundle ZIP"))
            continue
        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            findings.append(Finding(rel, f"forbidden suffix: {path.suffix}"))
            continue
        if path.suffix.lower() == ".zip":
            findings.append(Finding(rel, "ZIP files are blocked except explicit synthetic fixtures"))
            continue
    return findings


def scan_secrets(root: Path) -> List[Finding]:
    findings: List[Finding] = []
    for path in iter_files(root):
        rel = rel_posix(path, root)
        if is_allowed_fixture(rel):
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name != ".gitignore":
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for label, pattern in SECRET_PATTERNS:
            if pattern.search(text):
                findings.append(Finding(rel, f"possible secret/token pattern: {label}"))
    return findings


def run_check(root: Path) -> int:
    root = root.resolve()
    findings = scan_paths(root) + scan_secrets(root)
    if findings:
        print("PooleShield repo safety check FAILED.\n")
        for f in findings:
            print(f"- {f.path}: {f.reason}")
        print("\nRemove private/generated artifacts from the commit and rerun.")
        return 1
    print(f"PooleShield repo safety check passed. Version {VERSION}.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check repo for private/generated PooleShield artifacts.")
    parser.add_argument("--root", default=".", help="Repository root to scan")
    args = parser.parse_args(argv)
    return run_check(Path(args.root))


if __name__ == "__main__":
    raise SystemExit(main())
