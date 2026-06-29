#!/usr/bin/env python3
"""Portable launcher entry point for the PooleShield desktop app."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

VERSION = "5.1.0"


def runtime_status() -> dict:
    try:
        from pooleshield_desktop import qt_status
        status = qt_status()
    except Exception as exc:
        status = {"qt_available": False, "qt_import_error": str(exc), "install_hint": "python -m pip install PySide6"}
    return {
        "tool": "PooleShield portable launcher",
        "version": VERSION,
        "cwd": str(Path.cwd()),
        "qt_status": status,
        "safety_boundary": {
            "executes_scanned_files": False,
            "deletes_files": False,
            "quarantines_files": False,
            "kills_processes": False,
            "installs_hooks_or_drivers": False,
            "uploads_raw_contents": False,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PooleShield portable desktop launcher")
    parser.add_argument("--status", action="store_true", help="Print launcher/dependency status and exit")
    args = parser.parse_args(argv)
    if args.status:
        print(json.dumps(runtime_status(), indent=2))
        return 0
    from pooleshield_desktop import main as desktop_main
    return desktop_main([])


if __name__ == "__main__":
    raise SystemExit(main())
