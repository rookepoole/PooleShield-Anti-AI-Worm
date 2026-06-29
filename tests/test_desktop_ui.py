from __future__ import annotations

from pooleshield_desktop import (
    VERSION,
    build_config_validate_request,
    build_file_av_scan_request,
    build_history_list_request,
    build_profile_request,
    qt_status,
    summarize_engine_response,
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
