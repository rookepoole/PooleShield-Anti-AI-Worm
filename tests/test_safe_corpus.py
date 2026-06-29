from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from dataset_adapters.eicar_fixture_adapter import write_fixture
from dataset_adapters.ember_adapter import normalize_ember_file
from dataset_adapters.sorel_adapter import normalize_sorel_file
from dataset_schema import VERSION, load_safe_corpus, normalize_label, normalize_record, summarize_records
from pooleshield_benchmark import run_safe_corpus_benchmark, score_feature_vector
from pooleshield_engine import dispatch, safe_corpus_benchmark, safe_corpus_status


def _tiny_dataset(repo: Path) -> Path:
    return repo / "examples" / "safe_corpus" / "tiny_feature_dataset.jsonl"


def test_label_normalization():
    assert normalize_label(1) == "malicious"
    assert normalize_label(0) == "benign"
    assert normalize_label("pup") == "suspicious"
    assert normalize_label(None) == "unknown"


def test_normalize_record_blocks_raw_binary_by_default():
    rec = normalize_record({
        "sample_id": "unsafe",
        "source": "unit",
        "label": "malicious",
        "features_only": False,
        "raw_binary_present": True,
        "feature_vector": {"entropy": 7.2},
    })
    assert rec["validation"]["valid"] is False
    assert any("raw_binary_present" in err for err in rec["validation"]["errors"])


def test_load_tiny_safe_corpus():
    repo = Path(__file__).resolve().parents[1]
    records = load_safe_corpus(_tiny_dataset(repo))
    summary = summarize_records(records)
    assert summary["record_count"] == 6
    assert summary["raw_binary_present_records"] == 0
    assert summary["invalid_records"] == 0
    assert summary["by_label"]["malicious"] == 2


def test_score_feature_vector_eicar_style_marker():
    scored = score_feature_vector({"eicar_style_marker": 1.0, "malicious_vendor_ratio": 1.0})
    assert scored["risk_score"] >= 0.9
    assert any("eicar_style_marker" in reason for reason in scored["reasons"])


def test_safe_corpus_benchmark_outputs(tmp_path: Path):
    repo = Path(__file__).resolve().parents[1]
    out = tmp_path / "bench"
    summary = run_safe_corpus_benchmark(str(_tiny_dataset(repo)), output_dir=str(out), clean_output=True)
    assert summary["version"] == VERSION
    assert summary["record_summary"]["record_count"] == 6
    assert summary["safety_boundary"]["raw_binaries_loaded"] is False
    assert summary["metrics_at_require_approval_threshold"]["supervised_count"] == 5
    assert (out / "safe_corpus_benchmark.json").exists()
    assert (out / "safe_corpus_benchmark.csv").exists()
    assert (out / "safe_corpus_benchmark.md").exists()


def test_eicar_style_fixture_adapter(tmp_path: Path):
    out = tmp_path / "fixture.jsonl"
    summary = write_fixture(out)
    assert summary["ok"] is True
    assert summary["safety_boundary"]["canonical_eicar_string_included"] is False
    text = out.read_text(encoding="utf-8")
    assert "X5O!P%@AP" not in text
    records = load_safe_corpus(out)
    assert len(records) == 3


def test_ember_and_sorel_adapters(tmp_path: Path):
    ember_in = tmp_path / "ember.jsonl"
    ember_out = tmp_path / "safe_ember.jsonl"
    ember_in.write_text(json.dumps({"sha256": "a" * 64, "label": 1, "features": {"entropy": 7.1, "packer_score": 0.5}}) + "\n", encoding="utf-8")
    ember_summary = normalize_ember_file(ember_in, ember_out)
    assert ember_summary["summary"]["record_count"] == 1
    assert load_safe_corpus(ember_out)[0]["source"] == "ember"

    sorel_in = tmp_path / "sorel.jsonl"
    sorel_out = tmp_path / "safe_sorel.jsonl"
    sorel_in.write_text(json.dumps({"file_id": "s1", "is_malware": False, "features": {"malicious_vendor_ratio": 0.0}}) + "\n", encoding="utf-8")
    sorel_summary = normalize_sorel_file(sorel_in, sorel_out)
    assert sorel_summary["summary"]["by_label"]["benign"] == 1


def test_engine_safe_corpus_operations(tmp_path: Path):
    repo = Path(__file__).resolve().parents[1]
    dataset = str(_tiny_dataset(repo))
    status = safe_corpus_status(dataset)
    assert status["operation"] == "safe_corpus.status"
    assert status["summary"]["record_count"] == 6
    bench = safe_corpus_benchmark(dataset, output_dir=str(tmp_path / "bench"), clean_output=True)
    assert bench["operation"] == "safe_corpus.benchmark"
    response = dispatch({"operation": "safe_corpus.status", "params": {"dataset": dataset}})
    assert response["ok"] is True
    assert response["operation"] == "safe_corpus.status"


def test_operator_safe_corpus_cli(tmp_path: Path):
    repo = Path(__file__).resolve().parents[1]
    dataset = _tiny_dataset(repo)
    status_json = tmp_path / "safe_status.json"
    cmd = [
        sys.executable,
        str(repo / "pooleshield_operator.py"),
        "safe-corpus-status",
        "--dataset",
        str(dataset),
        "--output",
        str(status_json),
    ]
    result = subprocess.run(cmd, cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert result.returncode == 0, result.stderr
    data = json.loads(status_json.read_text(encoding="utf-8"))
    assert data["summary"]["record_count"] == 6

    out = tmp_path / "bench_cli"
    cmd2 = [
        sys.executable,
        str(repo / "pooleshield_operator.py"),
        "safe-corpus-benchmark",
        "--dataset",
        str(dataset),
        "--output-dir",
        str(out),
        "--clean-output",
        "--bundle-output",
        "--privacy-bundle",
    ]
    result2 = subprocess.run(cmd2, cwd=repo, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert result2.returncode == 0, result2.stderr
    assert (out / "safe_corpus_benchmark.json").exists()
    assert (out / "pooleshield_results_bundle.zip").exists()
