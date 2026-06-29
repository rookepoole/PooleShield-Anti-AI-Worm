from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scan_profiles import SCAN_PROFILE_NAMES, get_scan_profile, profile_catalog
from pooleshield_config import default_config, validate_config, resolve_file_av_baseline_scan_options


class Args:
    config = None
    baseline = None
    output_dir = None
    scan_profile = None
    risk_profile = None
    rule_pack = None
    max_bytes_per_file = None
    max_archive_entries = None
    max_archive_entry_bytes = None
    privacy_bundle = True
    bundle_output = False
    no_recursive = False
    include_hidden = False
    no_archives = False


def test_builtin_scan_profiles_are_valid():
    catalog = profile_catalog()
    assert set(catalog["profile_names"]) == set(SCAN_PROFILE_NAMES)
    assert get_scan_profile("quick")["scan_archives"] is False
    assert get_scan_profile("developer")["risk_profile"] == "developer"
    assert get_scan_profile("strict")["include_hidden"] is True


def test_config_accepts_scan_profile_default():
    cfg = default_config()
    cfg["defaults"]["scan_profile"] = "developer"
    result = validate_config(cfg)
    assert result["valid"] is True


def test_config_rejects_unknown_scan_profile():
    cfg = default_config()
    cfg["defaults"]["scan_profile"] = "loud-mode"
    result = validate_config(cfg)
    assert result["valid"] is False
    assert any("scan_profile" in e for e in result["errors"])


def test_resolve_baseline_scan_options_applies_profile(tmp_path: Path):
    cfg = default_config()
    cfg["defaults"].update({
        "baseline": str(tmp_path / "baseline.json"),
        "rule_pack": str(tmp_path / "rules.json"),
        "scan_profile": "quick",
    })
    config_path = tmp_path / "pooleshield_config.json"
    config_path.write_text(json.dumps(cfg), encoding="utf-8")
    args = Args()
    args.config = str(config_path)
    resolved = resolve_file_av_baseline_scan_options(args)
    assert resolved["scan_profile"] == "quick"
    assert resolved["scan_archives"] is False
    assert resolved["max_bytes_per_file"] == 1024 * 1024


def test_profile_list_cli(tmp_path: Path):
    repo = Path(__file__).resolve().parents[1]
    cmd = [sys.executable, str(repo / "pooleshield_operator.py"), "profile-list"]
    result = subprocess.run(cmd, cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert "developer" in data["profiles"]


def test_profile_show_cli(tmp_path: Path):
    repo = Path(__file__).resolve().parents[1]
    cmd = [sys.executable, str(repo / "pooleshield_operator.py"), "profile-show", "--name", "developer"]
    result = subprocess.run(cmd, cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["profile"]["name"] == "developer"
    assert data["profile"]["risk_profile"] == "developer"
