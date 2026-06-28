from pathlib import Path
import json
import zipfile

from adapter_dat_extract import run_dat_extract
from result_bundler import bundle_output_dir


def test_dat_extract_extracts_text_and_excludes_content_from_privacy_bundle(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "note.dat").write_text("hello from a text-like dat file", encoding="utf-8")
    (src / "data.dat").write_text('{"messages":[{"role":"user","content":"hi"}]}', encoding="utf-8")
    (src / "image.dat").write_bytes(b"\x89PNG\r\n\x1a\n" + b"x" * 20)

    out = tmp_path / "out"
    report = run_dat_extract(
        paths=[str(src)],
        output_dir=str(out),
        clean_output=True,
        bundle_output=True,
        privacy_bundle=True,
    )
    assert report["summary"]["extracted_files"] == 2
    extracted_dir = out / "extracted_dat_text"
    assert extracted_dir.exists()
    assert len(list(extracted_dir.iterdir())) == 2

    bundle_path = Path(report["result_bundle"])
    assert bundle_path.exists()
    with zipfile.ZipFile(bundle_path) as zf:
        names = set(zf.namelist())
        assert "BUNDLE_MANIFEST.json" in names
        assert not any(name.startswith("extracted_dat_text/") for name in names)
        manifest = json.loads(zf.read("BUNDLE_MANIFEST.json").decode("utf-8"))
    assert manifest["privacy_mode"] is True
    assert any(path.startswith("extracted_dat_text/") for path in manifest["excluded_content_files"])
