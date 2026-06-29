from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from installer_build import VERSION, installer_plan, installer_status, render_inno_script, write_inno_script
from pooleshield_engine import dispatch, installer_plan as engine_installer_plan, installer_status as engine_installer_status


def test_installer_status_is_safe_metadata():
    status = installer_status(root='.')
    assert status['version'] == VERSION
    assert status['safety_boundary']['scanned_files_executed'] is False
    assert status['safety_boundary']['drivers_or_hooks_installed'] is False
    assert 'forbidden_portable_findings' in status


def test_installer_plan_and_script_render():
    plan = installer_plan(root='.')
    assert plan['mode'] == 'installer-build-plan'
    assert 'PooleShieldSetup.exe' in plan['expected_installer']
    script = render_inno_script(root='.')
    assert 'PooleShield' in script
    assert 'trusted_file_baseline' not in script
    assert 'local_history' not in script


def test_write_inno_script_with_fixture_portable(tmp_path: Path):
    portable = tmp_path / 'dist' / 'PooleShield'
    portable.mkdir(parents=True)
    (portable / 'PooleShield.exe').write_bytes(b'fake exe for installer test')
    (portable / 'README.md').write_text('fixture', encoding='utf-8')
    script_path = tmp_path / 'build' / 'installer' / 'PooleShield.iss'
    result = write_inno_script(str(script_path), root=str(tmp_path), portable_dir='dist/PooleShield', force=True)
    assert result['mode'] == 'installer-build-write-script'
    assert script_path.exists()
    text = script_path.read_text(encoding='utf-8')
    assert 'PooleShield.exe' in text


def test_engine_installer_operations():
    status = engine_installer_status('.')
    assert status['operation'] == 'installer.status'
    plan = engine_installer_plan(root='.')
    assert plan['operation'] == 'installer.plan'
    ok = dispatch({'operation': 'installer.status', 'params': {'root': '.'}})
    assert ok['ok'] is True
    assert ok['operation'] == 'installer.status'


def test_operator_installer_build_status_cli(tmp_path: Path):
    repo = Path(__file__).resolve().parents[1]
    response = tmp_path / 'installer_status.json'
    cmd = [
        sys.executable,
        str(repo / 'pooleshield_operator.py'),
        'installer-build',
        '--status',
        '--output',
        str(response),
    ]
    result = subprocess.run(cmd, cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert result.returncode == 0, result.stderr
    data = json.loads(response.read_text(encoding='utf-8'))
    assert data['ok'] is True
    assert data['mode'] == 'installer-build-status'
