from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from portable_build import VERSION, build_command, build_plan, build_status, render_spec, write_spec
from pooleshield_engine import dispatch, portable_plan, portable_status


def test_portable_status_is_safe_metadata():
    status = build_status(".")
    assert status["version"] == VERSION
    assert status["safety_boundary"]["scanned_files_executed"] is False
    assert status["safety_boundary"]["files_quarantined"] is False
    assert "pooleshield_portable_launcher.py" not in status["missing_required_files"]


def test_portable_plan_and_spec_render():
    plan = build_plan(root=".", clean=True)
    assert plan["mode"] == "portable-build-plan"
    assert any("pyinstaller" in str(part).lower() for part in plan["command"])
    spec = render_spec(root=".")
    assert "pooleshield_portable_launcher.py" in spec
    assert "trusted_file_baseline" not in spec
    assert "local_history" not in spec


def test_build_command_uses_pyinstaller_or_python_module():
    command = build_command(root=".", clean=True)
    joined = " ".join(str(part) for part in command).lower()
    assert "pyinstaller" in joined
    assert "--clean" in command


def test_write_spec_to_tmp_path(tmp_path: Path):
    spec_path = tmp_path / "pooleshield_portable.spec"
    summary = write_spec(str(spec_path), root=".", force=True)
    assert summary["mode"] == "portable-build-write-spec"
    assert spec_path.exists()
    text = spec_path.read_text(encoding="utf-8")
    assert "PooleShield" in text


def test_engine_portable_operations():
    status = portable_status(".")
    assert status["operation"] == "portable.status"
    plan = portable_plan(root=".")
    assert plan["operation"] == "portable.plan"
    ok = dispatch({"operation": "portable.status", "params": {"root": "."}})
    assert ok["ok"] is True
    assert ok["operation"] == "portable.status"


def test_operator_portable_build_status_cli(tmp_path: Path):
    repo = Path(__file__).resolve().parents[1]
    response = tmp_path / "portable_status.json"
    cmd = [
        sys.executable,
        str(repo / "pooleshield_operator.py"),
        "portable-build",
        "--status",
        "--output",
        str(response),
    ]
    result = subprocess.run(cmd, cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert result.returncode == 0, result.stderr
    data = json.loads(response.read_text(encoding="utf-8"))
    assert data["ok"] is True
    assert data["mode"] == "portable-build-status"


def test_portable_launcher_status_cli():
    repo = Path(__file__).resolve().parents[1]
    cmd = [sys.executable, str(repo / "pooleshield_portable_launcher.py"), "--status"]
    result = subprocess.run(cmd, cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["tool"] == "PooleShield portable launcher"
    assert data["safety_boundary"]["uploads_raw_contents"] is False
