import os
import sys

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, ROOT)

from benchmark_calibration import run_calibration


def test_labeled_fixture_scores_without_false_negatives():
    fixture = os.path.join(ROOT, "examples", "labeled_calibration_trace.jsonl")
    report = run_calibration(fixture, None, 0.25)
    metrics = report["metrics"]
    assert metrics["total_cases"] == 10
    assert metrics["confusion"]["TP"] >= 5
    assert metrics["confusion"]["FP"] == 0
    assert metrics["confusion"]["FN"] == 0
    assert metrics["f1"] >= 0.99


def test_untrusted_persistence_is_watch_or_higher():
    fixture = os.path.join(ROOT, "examples", "labeled_calibration_trace.jsonl")
    report = run_calibration(fixture, None, 0.25)
    case = next(c for c in report["cases"] if c["case_id"] == "untrusted_memory_write_request")
    assert case["predicted_level"] in {"WATCH", "RESTRICT", "QUARANTINE", "ISOLATE"}
    assert case["predicted_alert"] is True
