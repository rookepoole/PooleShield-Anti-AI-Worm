from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from pooleshield_engine import dispatch, release_manifest as engine_release_manifest, release_status as engine_release_status
from release_manifest import VERSION, build_release_manifest, release_status, write_release_notes_template


def _make_portable(tmp_path: Path) -> Path:
    portable = tmp_path / "PooleShieldPortable"
    portable.mkdir(parents=True)
    (portable / "PooleShield.exe").write_bytes(b"fake portable exe")
    (portable / "README.md").write_text("portable fixture", encoding="utf-8")
    runtime = portable / "runtime"
    runtime.mkdir()
    (runtime / "library.dll").write_bytes(b"fake runtime")
    return portable


def _make_installer(tmp_path: Path) -> Path:
    installer = tmp_path / "PooleShieldSetup.exe"
    installer.write_bytes(b"fake installer exe")
    return installer


def test_release_status_and_manifest_metadata_only(tmp_path: Path):
    portable = _make_portable(tmp_path)
    installer = _make_installer(tmp_path)
    status = release_status(root=str(tmp_path), portable_dir=str(portable), installer_path=str(installer))
    assert status["version"] == VERSION
    assert status["ok"] is True
    assert status["safe_to_write_manifest"] is True
    assert status["safety_boundary"]["artifact_contents_copied"] is False
    assert status["safety_boundary"]["artifacts_executed"] is False

    manifest = build_release_manifest(root=str(tmp_path), portable_dir=str(portable), installer_path=str(installer), release_version="5.2.1")
    assert manifest["mode"] == "release-manifest"
    assert manifest["artifact_count"] == 2
    assert manifest["manifest_sha256"]
    portable_artifact = next(a for a in manifest["artifacts"] if a["label"] == "portable")
    assert portable_artifact["file_count"] == 3
    assert portable_artifact["contains_app_exe"] is True
    assert all("content" not in f for f in portable_artifact["files"])


def test_release_manifest_blocks_private_artifacts(tmp_path: Path):
    portable = _make_portable(tmp_path)
    (portable / "pooleshield_config.json").write_text("{}", encoding="utf-8")
    installer = _make_installer(tmp_path)
    status = release_status(root=str(tmp_path), portable_dir=str(portable), installer_path=str(installer))
    assert status["ok"] is False
    assert status["safe_to_write_manifest"] is False
    portable_artifact = next(a for a in status["artifacts"] if a["label"] == "portable")
    assert portable_artifact["forbidden_findings"]


def test_release_notes_template(tmp_path: Path):
    portable = _make_portable(tmp_path)
    installer = _make_installer(tmp_path)
    manifest = build_release_manifest(root=str(tmp_path), portable_dir=str(portable), installer_path=str(installer))
    notes = tmp_path / "release_notes.md"
    result = write_release_notes_template(notes, manifest=manifest)
    text = notes.read_text(encoding="utf-8")
    assert result["ok"] is True
    assert "Unsigned" in text or "unsigned" in text
    assert "SHA256" in text
    assert "PooleShieldSetup.exe" in text


def test_engine_release_operations(tmp_path: Path):
    portable = _make_portable(tmp_path)
    installer = _make_installer(tmp_path)
    status = engine_release_status(root=str(tmp_path), portable_dir=str(portable), installer_path=str(installer))
    assert status["operation"] == "release.status"
    assert status["ok"] is True
    manifest = engine_release_manifest(root=str(tmp_path), portable_dir=str(portable), installer_path=str(installer))
    assert manifest["operation"] == "release.manifest"
    assert manifest["ok"] is True
    response = dispatch({"operation": "release.status", "params": {"root": str(tmp_path), "portable_dir": str(portable), "installer_path": str(installer)}})
    assert response["ok"] is True
    assert response["operation"] == "release.status"


def test_operator_release_manifest_cli(tmp_path: Path):
    repo = Path(__file__).resolve().parents[1]
    portable = _make_portable(tmp_path)
    installer = _make_installer(tmp_path)
    out_json = tmp_path / "release_manifest_response.json"
    notes = tmp_path / "release_notes.md"
    cmd = [
        sys.executable,
        str(repo / "pooleshield_operator.py"),
        "release-manifest",
        "--portable-dir",
        str(portable),
        "--installer-path",
        str(installer),
        "--output",
        str(out_json),
        "--notes-output",
        str(notes),
    ]
    result = subprocess.run(cmd, cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert result.returncode == 0, result.stderr
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data["ok"] is True
    assert data["artifact_count"] == 2
    assert notes.exists()
