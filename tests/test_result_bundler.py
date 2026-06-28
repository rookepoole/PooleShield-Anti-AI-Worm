import json
import zipfile
from pathlib import Path

from result_bundler import bundle_output_dir


def test_bundle_output_dir(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "RUN_SUMMARY.json").write_text('{"ok": true}', encoding="utf-8")
    (out / "report.csv").write_text('a,b\n1,2\n', encoding="utf-8")
    (out / "ignore.bin").write_bytes(b"not included")
    report = bundle_output_dir(str(out))
    bundle = Path(report["bundle_path"])
    assert bundle.exists()
    assert report["file_count"] == 2
    with zipfile.ZipFile(bundle) as zf:
        names = set(zf.namelist())
    assert "RUN_SUMMARY.json" in names
    assert "report.csv" in names
    assert "BUNDLE_MANIFEST.json" in names
    assert "ignore.bin" not in names
    assert "pooleshield_results_bundle.zip" not in names


def test_privacy_bundle_excludes_normalized_events(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "RUN_SUMMARY.json").write_text('{"ok": true}', encoding="utf-8")
    (out / "normalized_events.jsonl").write_text('{"content":"private chat"}\n', encoding="utf-8")
    (out / "policy_decisions.json").write_text('{"summary": {}}', encoding="utf-8")
    report = bundle_output_dir(str(out), privacy_mode=True)
    bundle = Path(report["bundle_path"])
    assert bundle.exists()
    assert report["privacy_mode"] is True
    assert "normalized_events.jsonl" in report["excluded_content_files"]
    with zipfile.ZipFile(bundle) as zf:
        names = set(zf.namelist())
        manifest = json.loads(zf.read("BUNDLE_MANIFEST.json"))
    assert "normalized_events.jsonl" not in names
    assert "PRIVACY_BUNDLE_NOTE.md" in names
    assert manifest["privacy_mode"] is True
    assert "normalized_events.jsonl" in manifest["excluded_content_files"]


def test_privacy_bundle_excludes_review_evidence_reports(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "RUN_SUMMARY_EVIDENCE.json").write_text('{"ok": true}', encoding="utf-8")
    (out / "review_evidence_report.json").write_text('{"snippets":[{"text":"private context"}]}', encoding="utf-8")
    (out / "review_evidence_local.md").write_text("private context", encoding="utf-8")
    (out / "review_evidence_summary.csv").write_text("review_key,reason\nabc,metadata only\n", encoding="utf-8")
    report = bundle_output_dir(str(out), privacy_mode=True)
    bundle = Path(report["bundle_path"])
    assert bundle.exists()
    assert "review_evidence_report.json" in report["excluded_content_files"]
    assert "review_evidence_local.md" in report["excluded_content_files"]
    with zipfile.ZipFile(bundle) as zf:
        names = set(zf.namelist())
        manifest = json.loads(zf.read("BUNDLE_MANIFEST.json"))
    assert "review_evidence_report.json" not in names
    assert "review_evidence_local.md" not in names
    assert "review_evidence_summary.csv" in names
    assert "review_evidence_report.json" in manifest["excluded_content_files"]


def test_bundle_skips_existing_generated_manifest_files(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "RUN_SUMMARY.json").write_text('{"ok": true}', encoding="utf-8")
    (out / "BUNDLE_MANIFEST.json").write_text('{"old": true}', encoding="utf-8")
    (out / "PRIVACY_BUNDLE_NOTE.md").write_text("old note", encoding="utf-8")
    report = bundle_output_dir(str(out), privacy_mode=True)
    bundle = Path(report["bundle_path"])
    with zipfile.ZipFile(bundle) as zf:
        names = zf.namelist()
    assert names.count("BUNDLE_MANIFEST.json") == 1
    assert names.count("PRIVACY_BUNDLE_NOTE.md") == 1
