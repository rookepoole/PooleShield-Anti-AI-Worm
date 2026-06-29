from __future__ import annotations

from pooleshield_desktop import (
    VERSION,
    build_config_validate_request,
    build_file_av_scan_request,
    build_history_list_request,
    build_profile_request,
    build_results_load_request,
    qt_status,
    summarize_engine_response,
    summarize_results_response,
)


def test_desktop_helpers_do_not_require_qt():
    status = qt_status()
    assert status["version"] == VERSION
    assert "qt_available" in status
    assert "engine_version" in status


def test_desktop_request_builders():
    assert build_profile_request("developer") == {"operation": "profile.show", "params": {"name": "developer"}}
    assert build_config_validate_request("pooleshield_config.json")["params"]["config"] == "pooleshield_config.json"
    history = build_history_list_request(history_db="local.sqlite", limit=3)
    assert history["operation"] == "history.list"
    assert history["params"]["limit"] == 3
    scan = build_file_av_scan_request(
        ["C:/scanme"],
        baseline="baseline.json",
        output_dir="out/ui",
        scan_profile="developer",
        record_history=True,
    )
    assert scan["operation"] == "file_av.scan_baseline"
    assert scan["params"]["paths"] == ["C:/scanme"]
    assert scan["params"]["baseline"] == "baseline.json"
    assert scan["params"]["privacy_bundle"] is True
    assert scan["params"]["record_history"] is True
    results = build_results_load_request("out/ui", decision="ALLOW_LOG", label="script", text="ledger", limit=25)
    assert results["operation"] == "results.load"
    assert results["params"]["output_dir"] == "out/ui"
    assert results["params"]["decision"] == "ALLOW_LOG"
    assert results["params"]["label"] == "script"
    assert results["params"]["text"] == "ledger"
    assert results["params"]["limit"] == 25


def test_desktop_response_summary():
    ok = {
        "ok": True,
        "result": {
            "final_verdict": "CLEAN_AFTER_POLICY",
            "items_scanned": 10,
            "baseline_matches": 2,
            "decision_counts": {"REQUIRE_APPROVAL": 0, "BLOCK": 0, "QUARANTINE": 0},
            "result_bundle": "out/pooleshield_results_bundle.zip",
        },
    }
    summary = summarize_engine_response(ok)
    assert "CLEAN_AFTER_POLICY" in summary
    assert "items_scanned=10" in summary
    assert "baseline_matches=2" in summary
    bad = summarize_engine_response({"ok": False, "error_type": "ExampleError", "error": "bad path"})
    assert bad.startswith("ERROR [ExampleError]")


def test_desktop_results_summary():
    ok = {
        "ok": True,
        "result": {
            "final_verdict": "CLEAN_AFTER_POLICY",
            "items_scanned": 310,
            "total_items_available": 310,
            "items_after_filter": 12,
            "items_returned": 12,
            "baseline_matches": 102,
            "bundle_path": "out/file_av_desktop_v4_2/pooleshield_results_bundle.zip",
        },
    }
    summary = summarize_results_response(ok)
    assert "CLEAN_AFTER_POLICY" in summary
    assert "items_after_filter=12" in summary
    assert "bundle=" in summary
    bad = summarize_results_response({"ok": False, "error_type": "FileNotFoundError", "error": "missing"})
    assert bad.startswith("ERROR [FileNotFoundError]")
