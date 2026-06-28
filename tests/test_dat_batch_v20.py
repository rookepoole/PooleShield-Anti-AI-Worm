from pathlib import Path
import zipfile
import json

from adapter_dat_extract import run_dat_extract
from pooleshield_operator import run_dat_batch


def _write_dat_fixture(root: Path, n: int = 6) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        (root / f"note_{i}.dat").write_text(f"normal archived note {i}\n", encoding="utf-8")


def test_dat_extract_start_index_batches(tmp_path: Path):
    src = tmp_path / "dats"
    _write_dat_fixture(src, 6)
    out = tmp_path / "extract"
    result = run_dat_extract([str(src)], output_dir=str(out), clean_output=True, start_index=2, max_files=3)
    summary = result["summary"]
    assert summary["extracted_files"] == 3
    assert summary["start_index"] == 2
    assert summary["next_start_index"] == 5
    names = sorted(p.name for p in (out / "extracted_dat_text").glob("*.txt"))
    assert names[0].startswith("0003_")
    assert names[-1].startswith("0005_")


def test_dat_batch_privacy_bundle_excludes_content(tmp_path: Path):
    src = tmp_path / "dats"
    _write_dat_fixture(src, 4)
    out = tmp_path / "batch"
    result = run_dat_batch([str(src)], output_dir=str(out), clean_output=True, start_index=0, batch_size=4, bundle_output=True, privacy_bundle=True)
    assert result["extract_summary"]["summary"]["extracted_files"] == 4
    bundle = Path(result["result_bundle"])
    assert bundle.exists()
    with zipfile.ZipFile(bundle, "r") as zf:
        names = set(zf.namelist())
        manifest = json.loads(zf.read("BUNDLE_MANIFEST.json"))
    assert manifest["privacy_mode"] is True
    assert not any("extracted_dat_text" in name for name in names)
    assert not any(name.endswith("normalized_events.jsonl") for name in names)
