#!/usr/bin/env python3
"""PooleShield v5.2.1 release manifest helper.

Defensive purpose:
  Create metadata-only integrity manifests for locally built PooleShield release
  artifacts such as the portable app folder and Windows installer executable.
  This helper never executes artifacts, installs artifacts, scans user files,
  deletes files, quarantines files, installs hooks/drivers, sends network
  requests, or uploads data. It reads artifact metadata and hashes only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

VERSION = "5.2.1"
DEFAULT_RELEASE_VERSION = VERSION
DEFAULT_APP_NAME = "PooleShield"
DEFAULT_OUTPUT = "release_manifest.json"

FORBIDDEN_SOURCE_NAMES = {
    "pooleshield_config.json",
    ".pooleshield_config.json",
    "trusted_file_baseline.json",
    "trusted_file_baseline.csv",
    "trusted_file_baseline.md",
    "pooleshield_results_bundle.zip",
    "normalized_events.jsonl",
    "review_evidence_local.md",
    "review_evidence_report.json",
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
    "installer_status_response.json",
    "installer_build_plan.json",
    "installer_script_response.json",
    "installer_build_result.json",
    "installer_compile_result.json",
    "release_manifest.json",
    "release_manifest_response.json",
}

FORBIDDEN_SOURCE_DIRS = {
    "local_history",
    "local_trust",
    "local_rule_packs",
    "out",
    "extracted_dat_text",
    "extracted_dat_content",
    "extracted_text_like",
    "installer_build_verify",
    "installer_install_uninstall_smoke_verify",
    "release_verify",
    "release_output",
    "release_artifacts",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}

FORBIDDEN_SOURCE_SUFFIXES = {".sqlite", ".sqlite3", ".db", ".dat", ".pyc", ".pyo"}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def root_path(root: Optional[str] = None) -> Path:
    return Path(root or Path.cwd()).resolve()


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest().upper()


def rel_posix(path: Path, base: Path) -> str:
    return path.relative_to(base).as_posix()


def iter_files(path: Path) -> Iterable[Path]:
    for item in sorted(path.rglob("*"), key=lambda p: p.as_posix().lower()):
        if item.is_file():
            yield item


def scan_forbidden_source(path: Path) -> List[Dict[str, str]]:
    """Return findings for private/generated files in a release input path.

    Installer executables and portable runtime binaries are allowed as release
    artifacts. This scan blocks PooleShield private outputs/config/baselines and
    local review/scanning artifacts that must not be bundled into public release
    materials.
    """
    findings: List[Dict[str, str]] = []
    if not path.exists():
        return findings

    files = list(iter_files(path)) if path.is_dir() else [path]
    base = path if path.is_dir() else path.parent
    forbidden_names_lower = {x.lower() for x in FORBIDDEN_SOURCE_NAMES}
    forbidden_dirs_lower = {x.lower() for x in FORBIDDEN_SOURCE_DIRS}

    for file_path in files:
        try:
            rel = rel_posix(file_path, base)
        except ValueError:
            rel = str(file_path)
        parts_lower = {part.lower() for part in file_path.relative_to(base).parts}
        blocked_dirs = parts_lower.intersection(forbidden_dirs_lower)
        if blocked_dirs:
            findings.append({"path": rel, "reason": f"forbidden private/generated directory component: {sorted(blocked_dirs)}"})
            continue
        if file_path.name.lower() in forbidden_names_lower:
            findings.append({"path": rel, "reason": f"forbidden private/generated filename: {file_path.name}"})
            continue
        if file_path.suffix.lower() in FORBIDDEN_SOURCE_SUFFIXES:
            findings.append({"path": rel, "reason": f"forbidden private/generated suffix: {file_path.suffix}"})
            continue
    return findings


def file_record(path: Path, base: Path) -> Dict[str, Any]:
    st = path.stat()
    return {
        "relative_path": rel_posix(path, base),
        "size_bytes": st.st_size,
        "sha256": sha256_file(path),
    }


def summarize_file_artifact(path: Path, label: str) -> Dict[str, Any]:
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"file artifact does not exist: {path}")
    findings = scan_forbidden_source(path)
    st = path.stat()
    return {
        "label": label,
        "kind": "file",
        "path": str(path),
        "filename": path.name,
        "size_bytes": st.st_size,
        "sha256": sha256_file(path),
        "forbidden_findings": findings,
        "safe_to_release": not findings,
    }


def summarize_directory_artifact(path: Path, label: str, app_name: str = DEFAULT_APP_NAME) -> Dict[str, Any]:
    if not path.exists() or not path.is_dir():
        raise FileNotFoundError(f"directory artifact does not exist: {path}")
    files = list(iter_files(path))
    findings = scan_forbidden_source(path)
    records = [file_record(p, path) for p in files]
    app_exe = path / f"{app_name}.exe"
    return {
        "label": label,
        "kind": "directory",
        "path": str(path),
        "file_count": len(records),
        "total_size_bytes": sum(int(r["size_bytes"]) for r in records),
        "contains_app_exe": app_exe.exists(),
        "app_exe": str(app_exe),
        "app_exe_sha256": sha256_file(app_exe) if app_exe.exists() else "",
        "forbidden_findings": findings,
        "safe_to_release": bool(files) and not findings,
        "files": records,
    }


def release_status(
    *,
    root: Optional[str] = None,
    portable_dir: Optional[str] = None,
    installer_path: Optional[str] = None,
    app_name: str = DEFAULT_APP_NAME,
) -> Dict[str, Any]:
    repo = root_path(root)
    artifacts: List[Dict[str, Any]] = []
    errors: List[str] = []

    if portable_dir:
        p = Path(portable_dir)
        if not p.is_absolute():
            p = (repo / p).resolve()
        try:
            artifacts.append(summarize_directory_artifact(p, "portable", app_name=app_name))
        except Exception as exc:
            errors.append(f"portable_dir: {exc}")
            artifacts.append({"label": "portable", "kind": "directory", "path": str(p), "exists": p.exists(), "safe_to_release": False, "error": str(exc)})

    if installer_path:
        p = Path(installer_path)
        if not p.is_absolute():
            p = (repo / p).resolve()
        try:
            artifacts.append(summarize_file_artifact(p, "windows_installer"))
        except Exception as exc:
            errors.append(f"installer_path: {exc}")
            artifacts.append({"label": "windows_installer", "kind": "file", "path": str(p), "exists": p.exists(), "safe_to_release": False, "error": str(exc)})

    ok = bool(artifacts) and not errors and all(bool(a.get("safe_to_release")) for a in artifacts)
    return {
        "tool": "PooleShield release manifest helper",
        "version": VERSION,
        "mode": "release-status",
        "root": str(repo),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "errors": errors,
        "safe_to_write_manifest": ok,
        "safety_boundary": {
            "metadata_only": True,
            "artifact_contents_copied": False,
            "artifacts_executed": False,
            "installer_run": False,
            "files_deleted": False,
            "files_quarantined": False,
            "drivers_or_hooks_installed": False,
            "network_uploads": False,
        },
        "ok": ok,
    }


def build_release_manifest(
    *,
    root: Optional[str] = None,
    release_version: str = DEFAULT_RELEASE_VERSION,
    portable_dir: Optional[str] = None,
    installer_path: Optional[str] = None,
    app_name: str = DEFAULT_APP_NAME,
) -> Dict[str, Any]:
    status = release_status(root=root, portable_dir=portable_dir, installer_path=installer_path, app_name=app_name)
    if not status.get("safe_to_write_manifest"):
        raise RuntimeError("release artifacts are not safe/ready; check release-manifest --status")
    manifest = {
        "tool": "PooleShield release manifest helper",
        "version": VERSION,
        "mode": "release-manifest",
        "release_version": release_version,
        "generated_at_utc": utc_now(),
        "root": status["root"],
        "artifact_count": status["artifact_count"],
        "artifacts": status["artifacts"],
        "safety_boundary": status["safety_boundary"],
        "distribution_notes": [
            "Generated locally from release artifacts; artifact contents are not copied into this manifest.",
            "Installer is unsigned unless separately code-signed by the operator.",
            "Publish checksums alongside release artifacts so users can verify downloads.",
        ],
        "ok": True,
    }
    manifest_json = json.dumps(manifest, indent=2, ensure_ascii=False, sort_keys=True)
    manifest["manifest_sha256"] = hashlib.sha256(manifest_json.encode("utf-8")).hexdigest().upper()
    return manifest


def write_json(path: str | Path, data: Any) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def write_release_notes_template(
    path: str | Path,
    *,
    manifest: Dict[str, Any],
    unsigned: bool = True,
) -> Dict[str, Any]:
    release_version = manifest.get("release_version", VERSION)
    artifacts = manifest.get("artifacts", []) or []
    lines = [
        f"# PooleShield v{release_version} Release Notes",
        "",
        "PooleShield is a privacy-first, defensive, non-executing second-opinion scanner for suspicious files, archives, scripts, AI-agent logs, exported chat/data bundles, and local workflow artifacts.",
        "",
        "## Release focus",
        "",
        "v5.2 adds release packaging and integrity-manifest tooling for locally built portable and installer artifacts.",
        "",
        "## Safety boundary",
        "",
        "- No real-time protection",
        "- No kernel hooks or drivers",
        "- No automatic quarantine or deletion",
        "- No execution of scanned files",
        "- No network upload of raw scanned content",
        "- Release manifests contain metadata and hashes only",
        "",
        "## Artifacts and checksums",
        "",
    ]
    for artifact in artifacts:
        if artifact.get("kind") == "file":
            lines += [
                f"### {artifact.get('label')}: `{artifact.get('filename')}`",
                "",
                f"- Size: `{artifact.get('size_bytes')}` bytes",
                f"- SHA256: `{artifact.get('sha256')}`",
                "",
            ]
        elif artifact.get("kind") == "directory":
            lines += [
                f"### {artifact.get('label')}: portable folder",
                "",
                f"- File count: `{artifact.get('file_count')}`",
                f"- Total size: `{artifact.get('total_size_bytes')}` bytes",
                f"- App executable SHA256: `{artifact.get('app_exe_sha256')}`",
                "",
            ]
    if unsigned:
        lines += [
            "## Windows unsigned-build note",
            "",
            "This local Windows build is not code-signed unless a separate signing step has been performed. Windows SmartScreen may warn on first launch or install. Verify the SHA256 checksum before running downloaded artifacts.",
            "",
        ]
    lines += [
        "## Verification",
        "",
        f"Release manifest SHA256: `{manifest.get('manifest_sha256')}`",
        "",
        "Compare the published SHA256 values with your downloaded files before running them.",
    ]
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(lines), encoding="utf-8")
    return {"notes_path": str(p), "release_version": release_version, "ok": True}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Create metadata-only PooleShield release manifests and release-note drafts.")
    parser.add_argument("--root", default=".")
    parser.add_argument("--release-version", default=DEFAULT_RELEASE_VERSION)
    parser.add_argument("--portable-dir", default=None, help="Portable app folder to include in the manifest")
    parser.add_argument("--installer-path", default=None, help="Installer executable to include in the manifest")
    parser.add_argument("--name", default=DEFAULT_APP_NAME, help="Application executable base name")
    parser.add_argument("--status", action="store_true", help="Only report artifact readiness")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Output JSON path")
    parser.add_argument("--notes-output", default=None, help="Optional release notes draft path")
    args = parser.parse_args(argv)

    try:
        if args.status:
            result = release_status(root=args.root, portable_dir=args.portable_dir, installer_path=args.installer_path, app_name=args.name)
        else:
            result = build_release_manifest(root=args.root, release_version=args.release_version, portable_dir=args.portable_dir, installer_path=args.installer_path, app_name=args.name)
            if args.notes_output:
                result["release_notes"] = write_release_notes_template(args.notes_output, manifest=result)
        if args.output:
            write_json(args.output, result)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result.get("ok") else 2
    except Exception as exc:
        result = {"ok": False, "version": VERSION, "error_type": type(exc).__name__, "error": str(exc)}
        if args.output:
            write_json(args.output, result)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
