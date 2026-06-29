from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

from repo_safety_check import run_check


def test_repo_safety_current_tree_passes():
    assert run_check(ROOT) == 0


def test_repo_safety_blocks_private_artifacts(tmp_path):
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "normalized_events.jsonl").write_text("private content", encoding="utf-8")
    assert run_check(tmp_path) == 1


def test_repo_safety_blocks_result_bundle(tmp_path):
    (tmp_path / "pooleshield_results_bundle.zip").write_bytes(b"not a real zip")
    assert run_check(tmp_path) == 1


def test_repo_safety_allows_known_public_fixture_paths(tmp_path):
    fixture = tmp_path / "examples" / "file_av_fixture"
    fixture.mkdir(parents=True)
    (fixture / "fixture_archive.zip").write_bytes(b"synthetic fixture")
    assert run_check(tmp_path) == 0
