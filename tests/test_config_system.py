from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from pooleshield_config import (
    default_config,
    validate_config,
    write_default_config,
    load_and_validate_config,
)
from tests.test_file_av_baseline_scan import _make_baseline


def test_default_config_validates():
    cfg = default_config()
    result = validate_config(cfg)
    assert result["valid"] is True
    assert result["errors"] == []
    assert cfg["defaults"]["privacy_bundle"] is True
    assert cfg["safety"]["read_only"] is True


def test_write_and_load_config(tmp_path: Path):
    config_path = tmp_path / "pooleshield_config.json"
    created = write_default_config(str(config_path))
    assert created["created"] is True
    cfg, loaded_path, validation = load_and_validate_config(str(config_path))
    assert loaded_path == config_path
    assert validation["valid"] is True
    assert cfg["defaults"]["risk_profile"] == "standard"


def test_config_validate_cli(tmp_path: Path):
    repo = Path(__file__).resolve().parents[1]
    config_path = tmp_path / "pooleshield_config.json"
    cmd_init = [sys.executable, str(repo / "pooleshield_operator.py"), "config-init", "--config", str(config_path)]
    result = subprocess.run(cmd_init, cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert result.returncode == 0, result.stderr
    assert config_path.exists()

    cmd_validate = [sys.executable, str(repo / "pooleshield_operator.py"), "config-validate", "--config", str(config_path)]
    result2 = subprocess.run(cmd_validate, cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert result2.returncode == 0, result2.stderr
    data = json.loads(result2.stdout)
    assert data["valid"] is True


def test_operator_file_av_scan_baseline_uses_config(tmp_path: Path):
    repo = Path(__file__).resolve().parents[1]
    root, baseline_path = _make_baseline(tmp_path)
    out = tmp_path / "configured_out"
    config_path = tmp_path / "pooleshield_config.json"
    cfg = default_config()
    cfg["defaults"].update({
        "baseline": str(baseline_path),
        "rule_pack": str(repo / "examples" / "rule_packs" / "file_av_rules.default.json"),
        "file_av_baseline_scan_output_dir": str(out),
        "risk_profile": "developer",
    })
    config_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    cmd = [
        sys.executable, str(repo / "pooleshield_operator.py"), "file-av-scan-baseline",
        "--config", str(config_path),
        "--path", str(root),
        "--clean-output",
        "--bundle-output",
        "--privacy-bundle",
    ]
    result = subprocess.run(cmd, cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert result.returncode == 0, result.stderr
    data = json.loads((out / "RUN_SUMMARY_FILE_AV_BASELINE_SCAN.json").read_text(encoding="utf-8"))
    assert data["baseline_matches"] >= 1
    assert data["pending_review_rows"] == 0
    assert data["risk_profile"] == "developer"
    assert data["config_summary"]["used_config_file"] is True
    assert (out / "pooleshield_results_bundle.zip").exists()


def test_rule_pack_validate_uses_config(tmp_path: Path):
    repo = Path(__file__).resolve().parents[1]
    out = tmp_path / "rule_out"
    config_path = tmp_path / "pooleshield_config.json"
    cfg = default_config()
    cfg["defaults"]["rule_pack"] = str(repo / "examples" / "rule_packs" / "file_av_rules.default.json")
    config_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    cmd = [
        sys.executable, str(repo / "pooleshield_operator.py"), "rule-pack-validate",
        "--config", str(config_path),
        "--output-dir", str(out),
        "--clean-output",
    ]
    result = subprocess.run(cmd, cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert result.returncode == 0, result.stderr
    data = json.loads((out / "rule_pack_validation.json").read_text(encoding="utf-8"))
    assert data["valid"] is True
    assert data["config_summary"]["used_config_file"] is True
