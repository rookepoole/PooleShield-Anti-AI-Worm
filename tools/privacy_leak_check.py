#!/usr/bin/env python3
"""Compatibility wrapper for PooleShield privacy leak checks."""
from __future__ import annotations

import argparse
from pathlib import Path
from repo_safety_check import run_check


def main() -> int:
    parser = argparse.ArgumentParser(description="Run PooleShield privacy leak checks.")
    parser.add_argument("--root", default=".")
    args = parser.parse_args()
    return run_check(Path(args.root))


if __name__ == "__main__":
    raise SystemExit(main())
