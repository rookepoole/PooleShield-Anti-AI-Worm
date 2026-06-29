#!/usr/bin/env python3
"""PooleShield v5.1.1 Windows installer helper.

Defensive purpose:
  Generate and optionally compile a local Inno Setup installer script for the
  already-built PooleShield portable folder. This helper never scans user files,
  executes scanned files, deletes files, quarantines files, installs drivers, or
  uploads data. It only inspects build inputs and writes installer artifacts when
  explicitly requested by the operator.
"""
from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

VERSION = "5.1.1"
DEFAULT_APP_NAME = "PooleShield"
DEFAULT_APP_VERSION = VERSION
DEFAULT_PUBLISHER = "Rooke Poole"
DEFAULT_PORTABLE_DIR = "dist/PooleShield"
DEFAULT_OUTPUT_DIR = "installer_output"
DEFAULT_SCRIPT_PATH = "build/installer/PooleShield.iss"
DEFAULT_INSTALLER_BASENAME = "PooleShieldSetup"

FORBIDDEN_SOURCE_NAMES = {
    "pooleshield_config.json",
    "trusted_file_baseline.json",
    "pooleshield_results_bundle.zip",
    "normalized_events.jsonl",
    "review_evidence_local.md",
    "review_evidence_report.json",
}
FORBIDDEN_SOURCE_DIRS = {
    "local_history",
    "local_trust",
    "local_rule_packs",
    "out",
    "extracted_dat_text",
    "extracted_dat_content",
    "extracted_text_like",
    "__pycache__",
    ".pytest_cache",
}
FORBIDDEN_SOURCE_SUFFIXES = {".sqlite", ".sqlite3", ".db", ".dat"}


def root_path(root: Optional[str] = None) -> Path:
    return Path(root or Path.cwd()).resolve()


def find_iscc() -> Optional[str]:
    """Return a usable Inno Setup compiler path if one is visible."""
    direct = shutil.which("iscc") or shutil.which("ISCC") or shutil.which("ISCC.exe")
    if direct:
        return direct
    candidates = [
        Path(r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe"),
        Path(r"C:\Program Files\Inno Setup 6\ISCC.exe"),
        Path.home() / "AppData" / "Local" / "Programs" / "Inno Setup 6" / "ISCC.exe",
        Path(r"C:\Program Files (x86)\Inno Setup 5\ISCC.exe"),
        Path(r"C:\Program Files\Inno Setup 5\ISCC.exe"),
        Path.home() / "AppData" / "Local" / "Programs" / "Inno Setup 5" / "ISCC.exe",
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return None


def _scan_forbidden(portable_dir: Path) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    if not portable_dir.exists():
        return findings
    for p in portable_dir.rglob("*"):
        try:
            rel = p.relative_to(portable_dir).as_posix()
        except ValueError:
            rel = str(p)
        parts = set(p.parts)
        if any(part in FORBIDDEN_SOURCE_DIRS for part in parts):
            findings.append({"path": rel, "reason": "forbidden private/generated directory"})
            continue
        if p.is_file():
            if p.name in FORBIDDEN_SOURCE_NAMES:
                findings.append({"path": rel, "reason": "forbidden private/generated filename"})
            elif p.suffix.lower() in FORBIDDEN_SOURCE_SUFFIXES:
                findings.append({"path": rel, "reason": f"forbidden private/generated suffix: {p.suffix}"})
    return findings


def installer_status(
    *,
    root: Optional[str] = None,
    portable_dir: str = DEFAULT_PORTABLE_DIR,
    app_name: str = DEFAULT_APP_NAME,
) -> Dict[str, Any]:
    repo = root_path(root)
    src = (repo / portable_dir).resolve()
    exe = src / f"{app_name}.exe"
    files = [p for p in src.rglob("*") if p.is_file()] if src.exists() else []
    forbidden = _scan_forbidden(src)
    iscc = find_iscc()
    return {
        "tool": "PooleShield Windows installer helper",
        "version": VERSION,
        "mode": "installer-build-status",
        "root": str(repo),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "windows": platform.system().lower() == "windows",
        "iscc_available": bool(iscc),
        "iscc_path": iscc or "",
        "portable_dir": str(src),
        "portable_dir_exists": src.exists(),
        "portable_exe": str(exe),
        "portable_exe_exists": exe.exists(),
        "portable_file_count": len(files),
        "portable_total_size_bytes": sum(p.stat().st_size for p in files) if files else 0,
        "forbidden_portable_findings": forbidden,
        "safe_to_attempt_installer": src.exists() and exe.exists() and not forbidden,
        "installer_artifacts_gitignored": True,
        "safety_boundary": {
            "installer_build_only": True,
            "scanned_files_opened": False,
            "scanned_files_executed": False,
            "files_deleted": False,
            "files_quarantined": False,
            "drivers_or_hooks_installed": False,
            "network_uploads": False,
            "installs_only_when_operator_runs_installer": True,
        },
    }


def render_inno_script(
    *,
    root: Optional[str] = None,
    portable_dir: str = DEFAULT_PORTABLE_DIR,
    output_dir: str = DEFAULT_OUTPUT_DIR,
    app_name: str = DEFAULT_APP_NAME,
    app_version: str = DEFAULT_APP_VERSION,
    publisher: str = DEFAULT_PUBLISHER,
    installer_basename: str = DEFAULT_INSTALLER_BASENAME,
) -> str:
    repo = root_path(root)
    src = (repo / portable_dir).resolve()
    out = (repo / output_dir).resolve()
    exe_name = f"{app_name}.exe"
    # Inno syntax requires doubled braces for constants in Python f-strings.
    return f"""; PooleShield installer script generated by installer_build.py v{VERSION}
; Generated locally. Do not commit generated .iss, .exe, or installer output.
; The installer source is the portable folder only; private config/baseline/history/output files are excluded.

#define MyAppName "{app_name}"
#define MyAppVersion "{app_version}"
#define MyAppPublisher "{publisher}"
#define MyAppExeName "{exe_name}"
#define MySourceDir "{str(src)}"
#define MyOutputDir "{str(out)}"

[Setup]
AppId={{{{39A37B02-49E8-4E38-9F4A-50E1E5A10D5D}}}}
AppName={{#MyAppName}}
AppVersion={{#MyAppVersion}}
AppPublisher={{#MyAppPublisher}}
DefaultDirName={{localappdata}}\\Programs\\{{#MyAppName}}
DefaultGroupName={{#MyAppName}}
DisableProgramGroupPage=yes
OutputDir={{#MyOutputDir}}
OutputBaseFilename={installer_basename}
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
UninstallDisplayIcon={{app}}\\{{#MyAppExeName}}

[Files]
Source: "{{#MySourceDir}}\\*"; DestDir: "{{app}}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{{group}}\\{{#MyAppName}}"; Filename: "{{app}}\\{{#MyAppExeName}}"
Name: "{{autodesktop}}\\{{#MyAppName}}"; Filename: "{{app}}\\{{#MyAppExeName}}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked

[Run]
Filename: "{{app}}\\{{#MyAppExeName}}"; Description: "Launch {{#MyAppName}}"; Flags: nowait postinstall skipifsilent
"""


def write_inno_script(
    script_path: str = DEFAULT_SCRIPT_PATH,
    *,
    root: Optional[str] = None,
    portable_dir: str = DEFAULT_PORTABLE_DIR,
    output_dir: str = DEFAULT_OUTPUT_DIR,
    app_name: str = DEFAULT_APP_NAME,
    app_version: str = DEFAULT_APP_VERSION,
    publisher: str = DEFAULT_PUBLISHER,
    installer_basename: str = DEFAULT_INSTALLER_BASENAME,
    force: bool = False,
) -> Dict[str, Any]:
    repo = root_path(root)
    status = installer_status(root=str(repo), portable_dir=portable_dir, app_name=app_name)
    if not status["safe_to_attempt_installer"]:
        raise RuntimeError("portable folder is not safe/ready for installer; check installer-build --status")
    target = repo / script_path
    if target.exists() and not force:
        raise FileExistsError(f"installer script already exists: {target}. Use --force to overwrite.")
    text = render_inno_script(root=str(repo), portable_dir=portable_dir, output_dir=output_dir, app_name=app_name, app_version=app_version, publisher=publisher, installer_basename=installer_basename)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return {
        "tool": "PooleShield Windows installer helper",
        "version": VERSION,
        "mode": "installer-build-write-script",
        "root": str(repo),
        "script_path": str(target),
        "portable_dir": status["portable_dir"],
        "output_dir": str((repo / output_dir).resolve()),
        "app_name": app_name,
        "app_version": app_version,
        "installer_basename": installer_basename,
        "safety_boundary": status["safety_boundary"],
        "ok": True,
    }


def installer_command(script_path: str = DEFAULT_SCRIPT_PATH, *, root: Optional[str] = None) -> List[str]:
    repo = root_path(root)
    iscc = find_iscc() or "ISCC.exe"
    return [iscc, str((repo / script_path).resolve())]


def installer_plan(
    *,
    root: Optional[str] = None,
    portable_dir: str = DEFAULT_PORTABLE_DIR,
    output_dir: str = DEFAULT_OUTPUT_DIR,
    script_path: str = DEFAULT_SCRIPT_PATH,
    app_name: str = DEFAULT_APP_NAME,
    app_version: str = DEFAULT_APP_VERSION,
    publisher: str = DEFAULT_PUBLISHER,
    installer_basename: str = DEFAULT_INSTALLER_BASENAME,
) -> Dict[str, Any]:
    repo = root_path(root)
    status = installer_status(root=str(repo), portable_dir=portable_dir, app_name=app_name)
    return {
        "tool": "PooleShield Windows installer helper",
        "version": VERSION,
        "mode": "installer-build-plan",
        "root": str(repo),
        "status": status,
        "script_path": str((repo / script_path).resolve()),
        "portable_dir": str((repo / portable_dir).resolve()),
        "output_dir": str((repo / output_dir).resolve()),
        "app_name": app_name,
        "app_version": app_version,
        "publisher": publisher,
        "installer_basename": installer_basename,
        "expected_installer": str((repo / output_dir / f"{installer_basename}.exe").resolve()),
        "command": installer_command(script_path, root=str(repo)),
        "notes": [
            "Run on Windows with Inno Setup installed for actual installer compilation.",
            "Generated installer scripts/output are local artifacts and must not be committed.",
            "Installer source should be the portable folder only; no local config, baseline, history DB, or scan outputs should be bundled.",
        ],
        "ok": True,
    }


def run_iscc(
    script_path: str = DEFAULT_SCRIPT_PATH,
    *,
    root: Optional[str] = None,
    portable_dir: str = DEFAULT_PORTABLE_DIR,
    output_dir: str = DEFAULT_OUTPUT_DIR,
    app_name: str = DEFAULT_APP_NAME,
    app_version: str = DEFAULT_APP_VERSION,
    publisher: str = DEFAULT_PUBLISHER,
    installer_basename: str = DEFAULT_INSTALLER_BASENAME,
    force: bool = False,
) -> Dict[str, Any]:
    repo = root_path(root)
    status = installer_status(root=str(repo), portable_dir=portable_dir, app_name=app_name)
    if not status["safe_to_attempt_installer"]:
        raise RuntimeError("portable folder is not safe/ready for installer; check installer-build --status")
    iscc = find_iscc()
    if not iscc:
        raise RuntimeError("Inno Setup compiler was not found. Install Inno Setup 6 or add ISCC.exe to PATH.")
    script = (repo / script_path).resolve()
    if force or not script.exists():
        write_inno_script(
            script_path,
            root=str(repo),
            portable_dir=portable_dir,
            output_dir=output_dir,
            app_name=app_name,
            app_version=app_version,
            publisher=publisher,
            installer_basename=installer_basename,
            force=True,
        )
    cmd = [iscc, str(script)]
    proc = subprocess.run(cmd, cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return {
        "tool": "PooleShield Windows installer helper",
        "version": VERSION,
        "mode": "installer-build-run",
        "root": str(repo),
        "portable_dir": status["portable_dir"],
        "portable_file_count": status["portable_file_count"],
        "portable_total_size_bytes": status["portable_total_size_bytes"],
        "script_path": str(script),
        "output_dir": str((repo / output_dir).resolve()),
        "expected_installer": str((repo / output_dir / f"{installer_basename}.exe").resolve()),
        "installer_basename": installer_basename,
        "command": cmd,
        "returncode": proc.returncode,
        "stdout_tail": proc.stdout[-4000:],
        "stderr_tail": proc.stderr[-4000:],
        "success": proc.returncode == 0,
        "ok": proc.returncode == 0,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Build/status helper for PooleShield v5.1.1 Windows installer.")
    parser.add_argument("--root", default=".")
    parser.add_argument("--portable-dir", default=DEFAULT_PORTABLE_DIR)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--script-path", default=DEFAULT_SCRIPT_PATH)
    parser.add_argument("--name", default=DEFAULT_APP_NAME)
    parser.add_argument("--app-version", default=DEFAULT_APP_VERSION)
    parser.add_argument("--publisher", default=DEFAULT_PUBLISHER)
    parser.add_argument("--installer-basename", default=DEFAULT_INSTALLER_BASENAME)
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--write-script", action="store_true")
    parser.add_argument("--run-iscc", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--output", default=None)
    args = parser.parse_args(argv)
    try:
        if args.status:
            result = installer_status(root=args.root, portable_dir=args.portable_dir, app_name=args.name)
        elif args.write_script:
            result = write_inno_script(args.script_path, root=args.root, portable_dir=args.portable_dir, output_dir=args.output_dir, app_name=args.name, app_version=args.app_version, publisher=args.publisher, installer_basename=args.installer_basename, force=args.force)
        elif args.run_iscc:
            result = run_iscc(
                args.script_path,
                root=args.root,
                portable_dir=args.portable_dir,
                output_dir=args.output_dir,
                app_name=args.name,
                app_version=args.app_version,
                publisher=args.publisher,
                installer_basename=args.installer_basename,
                force=args.force,
            )
        else:
            result = installer_plan(root=args.root, portable_dir=args.portable_dir, output_dir=args.output_dir, script_path=args.script_path, app_name=args.name, app_version=args.app_version, publisher=args.publisher, installer_basename=args.installer_basename)
    except Exception as exc:
        result = {"ok": False, "version": VERSION, "error_type": exc.__class__.__name__, "error": str(exc)}
        if args.output:
            Path(args.output).write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps(result, indent=2))
        return 2
    result.setdefault("ok", True)
    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
