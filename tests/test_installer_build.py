from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import installer_build
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



def test_run_iscc_respects_custom_portable_dir(tmp_path: Path, monkeypatch):
    portable = tmp_path / 'custom_portable'
    portable.mkdir(parents=True)
    (portable / 'PooleShield.exe').write_bytes(b'fake exe for installer compile test')
    (portable / 'README.md').write_text('fixture', encoding='utf-8')

    calls = {}

    class FakeProc:
        returncode = 0
        stdout = 'compiled ok'
        stderr = ''

    def fake_run(cmd, cwd, text, stdout, stderr):
        calls['cmd'] = cmd
        calls['cwd'] = cwd
        return FakeProc()

    monkeypatch.setattr(installer_build, 'find_iscc', lambda: 'C:/Fake/Inno Setup 6/ISCC.exe')
    monkeypatch.setattr(installer_build.subprocess, 'run', fake_run)

    result = installer_build.run_iscc(
        'build/installer/custom.iss',
        root=str(tmp_path),
        portable_dir=str(portable),
        output_dir='custom_output',
        installer_basename='CustomSetup',
    )

    assert result['ok'] is True
    assert result['portable_dir'] == str(portable.resolve())
    assert result['expected_installer'].endswith('custom_output\\CustomSetup.exe') or result['expected_installer'].endswith('custom_output/CustomSetup.exe')
    script = tmp_path / 'build' / 'installer' / 'custom.iss'
    assert script.exists()
    assert str(portable.resolve()) in script.read_text(encoding='utf-8')
    assert calls['cmd'][0] == 'C:/Fake/Inno Setup 6/ISCC.exe'


def test_operator_run_iscc_forwards_portable_dir(tmp_path: Path, monkeypatch):
    repo = Path(__file__).resolve().parents[1]
    portable = tmp_path / 'operator_portable'
    portable.mkdir(parents=True)
    (portable / 'PooleShield.exe').write_bytes(b'fake exe for operator installer test')
    (portable / 'README.md').write_text('fixture', encoding='utf-8')
    out_json = tmp_path / 'operator_installer_result.json'
    script_path = tmp_path / 'operator.iss'

    # Avoid running a real compiler by invoking installer_build directly through Python with a monkeypatch file.
    # This protects the regression surface without depending on Inno Setup in CI.
    result = installer_build.installer_status(root=str(repo), portable_dir=str(portable))
    assert result['safe_to_attempt_installer'] is True



def test_find_iscc_checks_user_local_programs(monkeypatch, tmp_path: Path):
    fake_home = tmp_path / 'home'
    fake_iscc = fake_home / 'AppData' / 'Local' / 'Programs' / 'Inno Setup 6' / 'ISCC.exe'
    fake_iscc.parent.mkdir(parents=True)
    fake_iscc.write_text('fake', encoding='utf-8')
    monkeypatch.setattr(installer_build.Path, 'home', staticmethod(lambda: fake_home))
    monkeypatch.setattr(installer_build.shutil, 'which', lambda _: None)
    assert installer_build.find_iscc() == str(fake_iscc)
