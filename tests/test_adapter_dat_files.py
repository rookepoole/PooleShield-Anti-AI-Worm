import json
import zipfile
from pathlib import Path

from adapter_dat_files import inspect_dat_paths, run_dat_inspect


def test_dat_inspector_classifies_local_dat_fixture(tmp_path):
    root = tmp_path / "dat_fixture"
    root.mkdir()
    (root / "chat.dat").write_text('{"messages":[{"role":"user","content":"hello"}]}', encoding="utf-8")
    (root / "plain.dat").write_text("User: hello\nAssistant: hi\n", encoding="utf-8")
    (root / "image.dat").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 12)

    report = inspect_dat_paths([str(root)])
    assert report["summary"]["total_dat_entries"] == 3
    types = {e["name"]: e["likely_type"] for e in report["entries"]}
    assert types["chat.dat"] == "json_text"
    assert types["plain.dat"] == "plain_text"
    assert types["image.dat"] == "image_binary"


def test_dat_inspector_reads_dat_entries_inside_zip(tmp_path):
    bundle = tmp_path / "export.zip"
    with zipfile.ZipFile(bundle, "w") as z:
        z.writestr("blob.dat", '{"messages":[{"role":"user","content":"hello"}]}')
        z.writestr("not_dat.txt", "ignore")
    report = inspect_dat_paths([str(bundle)])
    assert report["summary"]["zip_archives_seen"] == 1
    assert report["summary"]["zip_dat_entries"] == 1
    assert report["entries"][0]["source_kind"] == "zip_entry"
    assert report["entries"][0]["likely_type"] == "json_text"


def test_run_dat_inspect_writes_bundle(tmp_path):
    root = tmp_path / "dat_fixture"
    root.mkdir()
    (root / "chat.dat").write_text('{"messages":[{"role":"user","content":"hello"}]}', encoding="utf-8")
    out = tmp_path / "out"
    summary = run_dat_inspect([str(root)], output_dir=str(out), clean_output=True, bundle_output=True)
    assert (out / "dat_inventory.json").exists()
    assert (out / "pooleshield_results_bundle.zip").exists()
    assert summary["summary"]["total_dat_entries"] == 1
