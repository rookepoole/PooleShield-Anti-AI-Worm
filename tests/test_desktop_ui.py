from __future__ import annotations

from pooleshield_desktop import (
    VERSION,
    build_config_validate_request,
    build_file_av_scan_request,
    build_history_list_request,
    build_profile_request,
    build_results_load_request,
    build_baseline_load_request,
    build_baseline_diff_request,
    build_rule_pack_load_request,
    build_rule_pack_export_default_request,
    build_rule_pack_update_rule_request,
    qt_status,
    summarize_engine_response,
    summarize_results_response,
    summarize_baseline_response,
    summarize_rule_pack_response,
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
    baseline = build_baseline_load_request("trusted_file_baseline.json", decision="ALLOW_LOG", kind="file", text="helper", limit=25)
    assert baseline["operation"] == "baseline.load"
    assert baseline["params"]["baseline"] == "trusted_file_baseline.json"
    assert baseline["params"]["decision"] == "ALLOW_LOG"
    assert baseline["params"]["kind"] == "file"
    assert baseline["params"]["text"] == "helper"
    assert baseline["params"]["limit"] == 25
    diff = build_baseline_diff_request("a.json", "b.json", limit=7)
    assert diff["operation"] == "baseline.diff"
    assert diff["params"]["baseline_a"] == "a.json"
    assert diff["params"]["baseline_b"] == "b.json"
    assert diff["params"]["limit"] == 7
    rule_pack = build_rule_pack_load_request("rules.json", enabled="enabled", type_filter="text_regex", text="token", limit=9)
    assert rule_pack["operation"] == "rule_pack.load"
    assert rule_pack["params"]["rule_pack"] == "rules.json"
    assert rule_pack["params"]["enabled"] == "enabled"
    exported = build_rule_pack_export_default_request("rules.editable.json", force=True)
    assert exported["operation"] == "rule_pack.export_default"
    updated = build_rule_pack_update_rule_request("rules.json", "rules.edited.json", index=0, enabled=False, risk_delta=0.2)
    assert updated["operation"] == "rule_pack.update_rule"
    assert updated["params"]["enabled"] is False


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
            "bundle_path": "out/file_av_desktop_v4_4/pooleshield_results_bundle.zip",
        },
    }
    summary = summarize_results_response(ok)
    assert "CLEAN_AFTER_POLICY" in summary
    assert "items_after_filter=12" in summary
    assert "bundle=" in summary
    bad = summarize_results_response({"ok": False, "error_type": "FileNotFoundError", "error": "missing"})
    assert bad.startswith("ERROR [FileNotFoundError]")



def test_desktop_baseline_summary():
    ok = {
        "ok": True,
        "result": {
            "mode": "baseline-load",
            "total_entries_available": 10,
            "entries_after_filter": 3,
            "entries_returned": 3,
            "baseline_path": "local_trust/trusted_file_baseline.json",
        },
    }
    summary = summarize_baseline_response(ok)
    assert "baseline-load" in summary
    assert "entries_returned=3" in summary
    bad = summarize_baseline_response({"ok": False, "error_type": "FileNotFoundError", "error": "missing baseline"})
    assert bad.startswith("ERROR [FileNotFoundError]")



def test_desktop_rule_pack_summary():
    ok = {
        "ok": True,
        "result": {
            "mode": "rule-pack-load",
            "total_rules_available": 5,
            "rules_after_filter": 2,
            "rules_returned": 2,
            "rules_enabled": 4,
            "rules_disabled": 1,
            "valid": True,
            "rule_pack_path": "examples/rule_packs/file_av_rules.default.json",
        },
    }
    summary = summarize_rule_pack_response(ok)
    assert "rule-pack-load" in summary
    assert "rules_returned=2" in summary
    bad = summarize_rule_pack_response({"ok": False, "error_type": "RulePackError", "error": "bad rule"})
    assert bad.startswith("ERROR [RulePackError]")
