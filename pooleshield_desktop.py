#!/usr/bin/env python3
"""PooleShield v5.1 desktop UI prototype.

Defensive purpose:
  Provide a local desktop dashboard, results-review UI, and baseline-manager UI for the PooleShield Engine API.
  The UI calls local engine functions and writes local metadata/report outputs only.

Safety boundary:
  This UI does not execute scanned files, delete files, quarantine files, kill
  processes, install hooks/drivers, send network requests, or upload raw scanned
  contents. It is a read-only front end for the same metadata/report workflow
  used by the CLI.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from pooleshield_engine import VERSION as ENGINE_VERSION, dispatch

VERSION = "5.1.0"

try:  # PySide6 is optional so core tests and CLI usage stay dependency-light.
    from PySide6.QtCore import QObject, QThread, Signal, Qt  # type: ignore
    from PySide6.QtGui import QFont  # type: ignore
    from PySide6.QtWidgets import (  # type: ignore
        QApplication,
        QCheckBox,
        QComboBox,
        QFileDialog,
        QFormLayout,
        QGridLayout,
        QGroupBox,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QMainWindow,
        QMessageBox,
        QPushButton,
        QPlainTextEdit,
        QTableWidget,
        QTableWidgetItem,
        QTabWidget,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )
    HAS_QT = True
    QT_IMPORT_ERROR = ""
except Exception as exc:  # pragma: no cover - exercised when PySide6 is absent.
    QObject = object  # type: ignore
    QThread = object  # type: ignore
    Signal = None  # type: ignore
    Qt = None  # type: ignore
    QFont = None  # type: ignore
    QApplication = None  # type: ignore
    QCheckBox = None  # type: ignore
    QComboBox = None  # type: ignore
    QFileDialog = None  # type: ignore
    QFormLayout = None  # type: ignore
    QGridLayout = None  # type: ignore
    QGroupBox = None  # type: ignore
    QHBoxLayout = None  # type: ignore
    QLabel = None  # type: ignore
    QLineEdit = None  # type: ignore
    QMainWindow = object  # type: ignore
    QMessageBox = None  # type: ignore
    QPushButton = None  # type: ignore
    QPlainTextEdit = None  # type: ignore
    QTableWidget = None  # type: ignore
    QTableWidgetItem = None  # type: ignore
    QTabWidget = None  # type: ignore
    QTextEdit = None  # type: ignore
    QVBoxLayout = None  # type: ignore
    QWidget = None  # type: ignore
    HAS_QT = False
    QT_IMPORT_ERROR = str(exc)


def qt_status() -> Dict[str, Any]:
    """Return a dependency status object that is safe to call without PySide6."""
    return {
        "tool": "PooleShield desktop UI prototype",
        "version": VERSION,
        "engine_version": ENGINE_VERSION,
        "qt_available": HAS_QT,
        "qt_import_error": QT_IMPORT_ERROR,
        "install_hint": "python -m pip install PySide6" if not HAS_QT else "",
    }


def build_profile_request(name: str = "developer") -> Dict[str, Any]:
    return {"operation": "profile.show", "params": {"name": name}}


def build_config_validate_request(config: Optional[str] = None) -> Dict[str, Any]:
    params: Dict[str, Any] = {}
    if config:
        params["config"] = config
    return {"operation": "config.validate", "params": params}


def build_history_list_request(config: Optional[str] = None, history_db: Optional[str] = None, limit: int = 10) -> Dict[str, Any]:
    params: Dict[str, Any] = {"limit": limit}
    if config:
        params["config"] = config
    if history_db:
        params["history_db"] = history_db
    return {"operation": "history.list", "params": params}


def build_results_load_request(
    output_dir: str,
    *,
    decision: str = "ANY",
    label: str = "",
    text: str = "",
    limit: int = 500,
) -> Dict[str, Any]:
    params: Dict[str, Any] = {"output_dir": output_dir, "limit": limit}
    if decision and decision != "ANY":
        params["decision"] = decision
    if label:
        params["label"] = label
    if text:
        params["text"] = text
    return {"operation": "results.load", "params": params}


def build_baseline_load_request(
    baseline: str,
    *,
    decision: str = "ANY",
    kind: str = "",
    text: str = "",
    limit: int = 500,
) -> Dict[str, Any]:
    params: Dict[str, Any] = {"baseline": baseline, "limit": limit}
    if decision and decision != "ANY":
        params["decision"] = decision
    if kind:
        params["kind"] = kind
    if text:
        params["text"] = text
    return {"operation": "baseline.load", "params": params}


def build_baseline_diff_request(baseline_a: str, baseline_b: str, *, limit: int = 500) -> Dict[str, Any]:
    return {"operation": "baseline.diff", "params": {"baseline_a": baseline_a, "baseline_b": baseline_b, "limit": limit}}


def build_rule_pack_load_request(
    rule_pack: str,
    *,
    enabled: str = "ANY",
    type_filter: str = "",
    text: str = "",
    limit: int = 500,
) -> Dict[str, Any]:
    params: Dict[str, Any] = {"rule_pack": rule_pack, "enabled": enabled, "type_filter": type_filter, "text": text, "limit": limit}
    return {"operation": "rule_pack.load", "params": params}


def build_rule_pack_export_default_request(output_path: str, *, default_path: str = "examples/rule_packs/file_av_rules.default.json", force: bool = False) -> Dict[str, Any]:
    return {"operation": "rule_pack.export_default", "params": {"output_path": output_path, "default_path": default_path, "force": force}}


def build_rule_pack_update_rule_request(
    rule_pack: str,
    output_path: str,
    *,
    rule_id: str = "",
    index: Optional[int] = None,
    enabled: Optional[bool] = None,
    risk_delta: Optional[float] = None,
    label: Optional[str] = None,
    pattern: Optional[str] = None,
    reason: Optional[str] = None,
) -> Dict[str, Any]:
    params: Dict[str, Any] = {"rule_pack": rule_pack, "output_path": output_path}
    if rule_id:
        params["rule_id"] = rule_id
    if index is not None:
        params["index"] = index
    for key, value in {"enabled": enabled, "risk_delta": risk_delta, "label": label, "pattern": pattern, "reason": reason}.items():
        if value is not None:
            params[key] = value
    return {"operation": "rule_pack.update_rule", "params": params}


def build_file_av_scan_request(
    paths: Sequence[str],
    *,
    config: Optional[str] = None,
    baseline: Optional[str] = None,
    output_dir: Optional[str] = None,
    scan_profile: Optional[str] = "developer",
    rule_pack: Optional[str] = None,
    clean_output: bool = True,
    bundle_output: bool = True,
    privacy_bundle: bool = True,
    record_history: bool = True,
    history_db: Optional[str] = None,
    history_notes: str = "desktop ui scan",
) -> Dict[str, Any]:
    params: Dict[str, Any] = {
        "paths": list(paths),
        "clean_output": clean_output,
        "bundle_output": bundle_output,
        "privacy_bundle": privacy_bundle,
        "record_history": record_history,
        "history_notes": history_notes,
    }
    optional = {
        "config": config,
        "baseline": baseline,
        "output_dir": output_dir,
        "scan_profile": scan_profile,
        "rule_pack": rule_pack,
        "history_db": history_db,
    }
    params.update({k: v for k, v in optional.items() if v})
    return {"operation": "file_av.scan_baseline", "params": params}


def summarize_results_response(response: Dict[str, Any]) -> str:
    """Summarize metadata-only loaded results for the v5.1 results tab."""
    if not response.get("ok"):
        return f"ERROR [{response.get('error_type')}]: {response.get('error')}"
    result = response.get("result", {})
    if not isinstance(result, dict):
        return "OK"
    pieces = ["OK"]
    if result.get("final_verdict"):
        pieces.append(f"verdict={result.get('final_verdict')}")
    for key in ("items_scanned", "total_items_available", "items_after_filter", "items_returned", "baseline_matches", "actionable_items"):
        if key in result:
            pieces.append(f"{key}={result.get(key)}")
    if result.get("bundle_path"):
        pieces.append(f"bundle={result.get('bundle_path')}")
    return " | ".join(pieces)


def summarize_baseline_response(response: Dict[str, Any]) -> str:
    """Summarize metadata-only baseline manager responses."""
    if not response.get("ok"):
        return f"ERROR [{response.get('error_type')}]: {response.get('error')}"
    result = response.get("result", {})
    if not isinstance(result, dict):
        return "OK"
    pieces = ["OK"]
    mode = result.get("mode")
    if mode:
        pieces.append(str(mode))
    for key in ("total_entries_available", "entries_after_filter", "entries_returned"):
        if key in result:
            pieces.append(f"{key}={result.get(key)}")
    counts = result.get("counts")
    if isinstance(counts, dict):
        pieces.append("diff=" + ",".join(f"{k}={v}" for k, v in counts.items()))
    if result.get("baseline_path"):
        pieces.append(f"baseline={result.get('baseline_path')}")
    return " | ".join(pieces)


def summarize_rule_pack_response(response: Dict[str, Any]) -> str:
    """Summarize metadata-only rule-pack editor responses."""
    if not response.get("ok"):
        return f"ERROR [{response.get('error_type')}]: {response.get('error')}"
    result = response.get("result", {})
    if not isinstance(result, dict):
        return "OK"
    pieces = ["OK"]
    mode = result.get("mode")
    if mode:
        pieces.append(str(mode))
    for key in ("total_rules_available", "rules_after_filter", "rules_returned", "rules_enabled", "rules_disabled"):
        if key in result:
            pieces.append(f"{key}={result.get(key)}")
    if result.get("valid") is not None:
        pieces.append(f"valid={result.get('valid')}")
    if result.get("rule_pack_path"):
        pieces.append(f"rule_pack={result.get('rule_pack_path')}")
    if result.get("output_rule_pack"):
        pieces.append(f"output={result.get('output_rule_pack')}")
    return " | ".join(pieces)


def summarize_engine_response(response: Dict[str, Any]) -> str:
    """Produce a compact operator-facing summary for dashboard/status panels."""
    if not response.get("ok"):
        return f"ERROR [{response.get('error_type')}]: {response.get('error')}"
    result = response.get("result", {})
    if not isinstance(result, dict):
        return "OK"
    verdict = result.get("final_verdict") or result.get("verdict")
    decision_counts = result.get("decision_counts") or result.get("effective_decision_counts") or {}
    pieces = ["OK"]
    if verdict:
        pieces.append(f"verdict={verdict}")
    for key in ("items_scanned", "files_scanned", "archive_entries_scanned", "baseline_matches", "action_item_count"):
        if key in result:
            pieces.append(f"{key}={result.get(key)}")
    for key in ("REQUIRE_APPROVAL", "BLOCK", "QUARANTINE"):
        if isinstance(decision_counts, dict) and key in decision_counts:
            pieces.append(f"{key}={decision_counts.get(key)}")
    bundle = result.get("result_bundle")
    bundle_summary = result.get("bundle_summary")
    if not bundle and isinstance(bundle_summary, dict):
        bundle = bundle_summary.get("bundle_path")
    if bundle:
        pieces.append(f"bundle={bundle}")
    return " | ".join(pieces)


def _pretty(data: Any) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False)


if HAS_QT:
    class EngineWorker(QObject):  # type: ignore[misc]
        finished = Signal(dict)

        def __init__(self, request: Dict[str, Any]):
            super().__init__()
            self.request = request

        def run(self) -> None:
            self.finished.emit(dispatch(self.request))


    class PooleShieldDesktop(QMainWindow):  # type: ignore[misc]
        def __init__(self) -> None:
            super().__init__()
            self.setWindowTitle(f"PooleShield Desktop Prototype v{VERSION}")
            self.resize(1120, 760)
            self._thread: Optional[QThread] = None
            self._worker: Optional[EngineWorker] = None

            self.tabs = QTabWidget()
            self.setCentralWidget(self.tabs)
            self._last_results_response: Dict[str, Any] = {}
            self._last_results_rows: List[Dict[str, Any]] = []
            self._last_baseline_response: Dict[str, Any] = {}
            self._last_baseline_rows: List[Dict[str, Any]] = []
            self._last_rule_pack_response: Dict[str, Any] = {}
            self._last_rule_pack_rows: List[Dict[str, Any]] = []

            self._build_dashboard_tab()
            self._build_scan_tab()
            self._build_results_tab()
            self._build_baseline_tab()
            self._build_rule_pack_tab()
            self._build_history_tab()
            self._build_about_tab()

        def _make_path_row(self, line: QLineEdit, button_text: str, file_mode: str) -> QWidget:
            box = QWidget()
            row = QHBoxLayout(box)
            row.setContentsMargins(0, 0, 0, 0)
            row.addWidget(line)
            btn = QPushButton(button_text)
            row.addWidget(btn)

            def choose() -> None:
                if file_mode == "folder":
                    chosen = QFileDialog.getExistingDirectory(self, "Choose folder")
                else:
                    chosen, _ = QFileDialog.getOpenFileName(self, "Choose file")
                if chosen:
                    line.setText(chosen)

            btn.clicked.connect(choose)
            return box

        def _build_dashboard_tab(self) -> None:
            tab = QWidget()
            layout = QVBoxLayout(tab)
            title = QLabel("PooleShield Desktop Dashboard")
            title_font = QFont()
            title_font.setPointSize(16)
            title_font.setBold(True)
            title.setFont(title_font)
            layout.addWidget(title)
            layout.addWidget(QLabel("Local-first defensive scanner. Read-only. Privacy bundle focused."))

            self.dashboard_output = QPlainTextEdit()
            self.dashboard_output.setReadOnly(True)
            layout.addWidget(self.dashboard_output, 1)

            row = QHBoxLayout()
            validate_btn = QPushButton("Validate default config")
            profiles_btn = QPushButton("List profiles")
            row.addWidget(validate_btn)
            row.addWidget(profiles_btn)
            row.addStretch(1)
            layout.addLayout(row)

            validate_btn.clicked.connect(lambda: self._run_sync(build_config_validate_request(), self.dashboard_output))
            profiles_btn.clicked.connect(lambda: self._run_sync({"operation": "profile.list", "params": {}}, self.dashboard_output))

            self.tabs.addTab(tab, "Dashboard")

        def _build_scan_tab(self) -> None:
            tab = QWidget()
            layout = QVBoxLayout(tab)
            form_box = QGroupBox("Baseline-aware folder scan")
            form = QFormLayout(form_box)

            self.config_path = QLineEdit("pooleshield_config.json")
            self.target_path = QLineEdit(str(Path.home() / "Desktop" / "PooleShieldRealScanSmall"))
            self.baseline_path = QLineEdit("")
            self.rule_pack_path = QLineEdit("examples/rule_packs/file_av_rules.default.json")
            self.output_dir = QLineEdit("out/file_av_desktop_v5_1")
            self.history_db = QLineEdit("local_history/pooleshield_scan_history.sqlite")
            self.profile_name = QComboBox()
            self.profile_name.addItems(["standard", "developer", "strict", "quick", "deep", "archive-heavy", "privacy-sensitive"])
            self.profile_name.setCurrentText("developer")
            self.clean_output = QCheckBox("Clean output before scan")
            self.clean_output.setChecked(True)
            self.bundle_output = QCheckBox("Create privacy results bundle")
            self.bundle_output.setChecked(True)
            self.record_history = QCheckBox("Record metadata-only scan history")
            self.record_history.setChecked(True)

            form.addRow("Config JSON", self._make_path_row(self.config_path, "Browse", "file"))
            form.addRow("Scan folder", self._make_path_row(self.target_path, "Browse", "folder"))
            form.addRow("Trusted baseline JSON", self._make_path_row(self.baseline_path, "Browse", "file"))
            form.addRow("Rule pack JSON", self._make_path_row(self.rule_pack_path, "Browse", "file"))
            form.addRow("Output folder", self.output_dir)
            form.addRow("History DB", self.history_db)
            form.addRow("Scan profile", self.profile_name)
            form.addRow("Options", self.clean_output)
            form.addRow("", self.bundle_output)
            form.addRow("", self.record_history)
            layout.addWidget(form_box)

            buttons = QHBoxLayout()
            self.scan_btn = QPushButton("Run scan")
            self.validate_btn = QPushButton("Validate config")
            buttons.addWidget(self.scan_btn)
            buttons.addWidget(self.validate_btn)
            buttons.addStretch(1)
            layout.addLayout(buttons)

            self.scan_status = QLabel("Ready.")
            layout.addWidget(self.scan_status)
            self.scan_output = QPlainTextEdit()
            self.scan_output.setReadOnly(True)
            layout.addWidget(self.scan_output, 1)

            self.scan_btn.clicked.connect(self._start_scan)
            self.validate_btn.clicked.connect(lambda: self._run_sync(build_config_validate_request(self.config_path.text().strip() or None), self.scan_output))
            self.tabs.addTab(tab, "Scan Folder")

        def _build_results_tab(self) -> None:
            tab = QWidget()
            layout = QVBoxLayout(tab)
            controls = QGroupBox("Results table and filters")
            row = QHBoxLayout(controls)
            self.results_output_dir = QLineEdit("out/file_av_desktop_v5_1")
            self.results_decision = QComboBox()
            self.results_decision.addItems(["ANY", "ALLOW", "ALLOW_LOG", "REQUIRE_APPROVAL", "BLOCK", "QUARANTINE"])
            self.results_label_filter = QLineEdit("")
            self.results_label_filter.setPlaceholderText("label contains")
            self.results_text_filter = QLineEdit("")
            self.results_text_filter.setPlaceholderText("path/hash/text contains")
            load_btn = QPushButton("Load results")
            copy_bundle_btn = QPushButton("Copy bundle path")
            row.addWidget(QLabel("Output"))
            row.addWidget(self.results_output_dir, 2)
            row.addWidget(QLabel("Decision"))
            row.addWidget(self.results_decision)
            row.addWidget(QLabel("Label"))
            row.addWidget(self.results_label_filter)
            row.addWidget(QLabel("Search"))
            row.addWidget(self.results_text_filter)
            row.addWidget(load_btn)
            row.addWidget(copy_bundle_btn)
            layout.addWidget(controls)

            self.results_status = QLabel("Load a PooleShield output folder to review metadata-only results.")
            layout.addWidget(self.results_status)
            self.results_table = QTableWidget(0, 6)
            self.results_table.setHorizontalHeaderLabels(["Decision", "Risk", "Baseline", "Kind", "Labels", "Path"])
            layout.addWidget(self.results_table, 2)
            self.results_detail = QPlainTextEdit()
            self.results_detail.setReadOnly(True)
            layout.addWidget(self.results_detail, 1)

            load_btn.clicked.connect(self._load_results)
            copy_bundle_btn.clicked.connect(self._copy_bundle_path)
            self.results_table.itemSelectionChanged.connect(self._show_selected_result_detail)
            self.tabs.addTab(tab, "Results")

        def _build_baseline_tab(self) -> None:
            tab = QWidget()
            layout = QVBoxLayout(tab)
            controls = QGroupBox("Trusted baseline manager")
            form = QFormLayout(controls)
            self.baseline_manager_path = QLineEdit("")
            self.baseline_manager_decision = QComboBox()
            self.baseline_manager_decision.addItems(["ANY", "ALLOW", "ALLOW_LOG"])
            self.baseline_manager_kind = QLineEdit("")
            self.baseline_manager_kind.setPlaceholderText("kind contains")
            self.baseline_manager_text = QLineEdit("")
            self.baseline_manager_text.setPlaceholderText("sha/path/label/notes contains")
            form.addRow("Baseline JSON", self._make_path_row(self.baseline_manager_path, "Browse", "file"))
            form.addRow("Decision", self.baseline_manager_decision)
            form.addRow("Kind filter", self.baseline_manager_kind)
            form.addRow("Search", self.baseline_manager_text)
            layout.addWidget(controls)

            row = QHBoxLayout()
            load_btn = QPushButton("Load baseline")
            copy_sha_btn = QPushButton("Copy selected SHA")
            copy_path_btn = QPushButton("Copy baseline path")
            row.addWidget(load_btn)
            row.addWidget(copy_sha_btn)
            row.addWidget(copy_path_btn)
            row.addStretch(1)
            layout.addLayout(row)

            diff_box = QGroupBox("Compare two baselines")
            diff_row = QHBoxLayout(diff_box)
            self.baseline_diff_a = QLineEdit("")
            self.baseline_diff_b = QLineEdit("")
            diff_btn = QPushButton("Diff")
            diff_row.addWidget(QLabel("A"))
            diff_row.addWidget(self.baseline_diff_a, 1)
            diff_row.addWidget(QLabel("B"))
            diff_row.addWidget(self.baseline_diff_b, 1)
            diff_row.addWidget(diff_btn)
            layout.addWidget(diff_box)

            self.baseline_status = QLabel("Load a local trusted_file_baseline.json. Baseline contents stay local/private.")
            layout.addWidget(self.baseline_status)
            self.baseline_table = QTableWidget(0, 6)
            self.baseline_table.setHorizontalHeaderLabels(["Decision", "Kind", "Size", "SHA prefix", "Labels", "Path hint"])
            layout.addWidget(self.baseline_table, 2)
            self.baseline_detail = QPlainTextEdit()
            self.baseline_detail.setReadOnly(True)
            layout.addWidget(self.baseline_detail, 1)

            load_btn.clicked.connect(self._load_baseline)
            copy_sha_btn.clicked.connect(self._copy_selected_baseline_sha)
            copy_path_btn.clicked.connect(self._copy_baseline_path)
            diff_btn.clicked.connect(self._diff_baselines)
            self.baseline_table.itemSelectionChanged.connect(self._show_selected_baseline_detail)
            self.tabs.addTab(tab, "Baseline")

        def _build_rule_pack_tab(self) -> None:
            tab = QWidget()
            layout = QVBoxLayout(tab)
            controls = QGroupBox("Rule pack editor")
            form = QFormLayout(controls)
            self.rule_pack_editor_path = QLineEdit("examples/rule_packs/file_av_rules.default.json")
            self.rule_pack_editor_enabled = QComboBox()
            self.rule_pack_editor_enabled.addItems(["ANY", "enabled", "disabled"])
            self.rule_pack_editor_type = QLineEdit("")
            self.rule_pack_editor_type.setPlaceholderText("type contains")
            self.rule_pack_editor_text = QLineEdit("")
            self.rule_pack_editor_text.setPlaceholderText("id/label/pattern/reason contains")
            self.rule_pack_export_path = QLineEdit("local_rule_packs/file_av_rules.editable.json")
            form.addRow("Rule pack JSON", self._make_path_row(self.rule_pack_editor_path, "Browse", "file"))
            form.addRow("Enabled filter", self.rule_pack_editor_enabled)
            form.addRow("Type filter", self.rule_pack_editor_type)
            form.addRow("Search", self.rule_pack_editor_text)
            form.addRow("Export/edit path", self.rule_pack_export_path)
            layout.addWidget(controls)

            row = QHBoxLayout()
            load_btn = QPushButton("Load rule pack")
            export_btn = QPushButton("Export default copy")
            copy_path_btn = QPushButton("Copy rule pack path")
            row.addWidget(load_btn)
            row.addWidget(export_btn)
            row.addWidget(copy_path_btn)
            row.addStretch(1)
            layout.addLayout(row)

            edit_box = QGroupBox("Edit selected rule into output copy")
            edit_row = QHBoxLayout(edit_box)
            self.rule_pack_set_enabled = QCheckBox("Enabled")
            self.rule_pack_set_enabled.setChecked(True)
            self.rule_pack_risk_delta = QLineEdit("")
            self.rule_pack_risk_delta.setPlaceholderText("risk_delta")
            self.rule_pack_label = QLineEdit("")
            self.rule_pack_label.setPlaceholderText("label")
            self.rule_pack_pattern = QLineEdit("")
            self.rule_pack_pattern.setPlaceholderText("regex pattern")
            save_rule_btn = QPushButton("Save selected rule copy")
            edit_row.addWidget(self.rule_pack_set_enabled)
            edit_row.addWidget(self.rule_pack_risk_delta)
            edit_row.addWidget(self.rule_pack_label)
            edit_row.addWidget(self.rule_pack_pattern)
            edit_row.addWidget(save_rule_btn)
            layout.addWidget(edit_box)

            self.rule_pack_status = QLabel("Load a local rule pack. Edits write only to a rule-pack JSON copy, never to scanned files.")
            layout.addWidget(self.rule_pack_status)
            self.rule_pack_table = QTableWidget(0, 7)
            self.rule_pack_table.setHorizontalHeaderLabels(["Index", "Enabled", "Type", "Risk", "Label", "ID", "Pattern"])
            layout.addWidget(self.rule_pack_table, 2)
            self.rule_pack_detail = QPlainTextEdit()
            self.rule_pack_detail.setReadOnly(True)
            layout.addWidget(self.rule_pack_detail, 1)

            load_btn.clicked.connect(self._load_rule_pack)
            export_btn.clicked.connect(self._export_default_rule_pack)
            copy_path_btn.clicked.connect(self._copy_rule_pack_path)
            save_rule_btn.clicked.connect(self._save_selected_rule_pack_rule)
            self.rule_pack_table.itemSelectionChanged.connect(self._show_selected_rule_pack_detail)
            self.tabs.addTab(tab, "Rule Packs")

        def _build_history_tab(self) -> None:
            tab = QWidget()
            layout = QVBoxLayout(tab)
            row = QHBoxLayout()
            self.history_config_path = QLineEdit("pooleshield_config.json")
            self.history_db_path = QLineEdit("local_history/pooleshield_scan_history.sqlite")
            refresh = QPushButton("Refresh history")
            row.addWidget(QLabel("Config"))
            row.addWidget(self.history_config_path)
            row.addWidget(QLabel("DB"))
            row.addWidget(self.history_db_path)
            row.addWidget(refresh)
            layout.addLayout(row)

            self.history_table = QTableWidget(0, 7)
            self.history_table.setHorizontalHeaderLabels(["ID", "Timestamp", "Verdict", "Profile", "Items", "Baseline", "Bundle"])
            layout.addWidget(self.history_table, 1)
            self.history_output = QPlainTextEdit()
            self.history_output.setReadOnly(True)
            layout.addWidget(self.history_output, 1)

            refresh.clicked.connect(self._refresh_history)
            self.tabs.addTab(tab, "History")

        def _build_about_tab(self) -> None:
            tab = QWidget()
            layout = QVBoxLayout(tab)
            text = QTextEdit()
            text.setReadOnly(True)
            text.setHtml(f"""
            <h2>PooleShield v{VERSION}</h2>
            <p><b>Engine:</b> {ENGINE_VERSION}</p>
            <p>PooleShield is a privacy-first second-opinion defensive scanner.</p>
            <ul>
              <li>No scanned-file execution</li>
              <li>No deletion</li>
              <li>No automatic quarantine</li>
              <li>No process killing</li>
              <li>No drivers or real-time hooks</li>
              <li>No raw private content upload by default</li>
            </ul>
            <p>This is a prototype UI with metadata-only results review before packaging as a Windows app.</p>
            """)
            layout.addWidget(text)
            self.tabs.addTab(tab, "About")

        def _run_sync(self, request: Dict[str, Any], target: QPlainTextEdit) -> None:
            response = dispatch(request)
            target.setPlainText(_pretty(response))

        def _start_scan(self) -> None:
            target = self.target_path.text().strip()
            if not target:
                QMessageBox.warning(self, "Missing scan folder", "Choose a folder to scan first.")
                return
            request = build_file_av_scan_request(
                [target],
                config=self.config_path.text().strip() or None,
                baseline=self.baseline_path.text().strip() or None,
                output_dir=self.output_dir.text().strip() or None,
                scan_profile=self.profile_name.currentText(),
                rule_pack=self.rule_pack_path.text().strip() or None,
                clean_output=self.clean_output.isChecked(),
                bundle_output=self.bundle_output.isChecked(),
                privacy_bundle=True,
                record_history=self.record_history.isChecked(),
                history_db=self.history_db.text().strip() or None,
                history_notes="desktop ui scan",
            )
            self.scan_btn.setEnabled(False)
            self.scan_status.setText("Scanning... UI remains local/read-only.")
            self.scan_output.setPlainText(_pretty(request))
            self._thread = QThread()
            self._worker = EngineWorker(request)
            self._worker.moveToThread(self._thread)
            self._thread.started.connect(self._worker.run)
            self._worker.finished.connect(self._scan_finished)
            self._worker.finished.connect(self._thread.quit)
            self._worker.finished.connect(self._worker.deleteLater)
            self._thread.finished.connect(self._thread.deleteLater)
            self._thread.start()

        def _scan_finished(self, response: Dict[str, Any]) -> None:
            self.scan_btn.setEnabled(True)
            self.scan_status.setText(summarize_engine_response(response))
            self.scan_output.setPlainText(_pretty(response))
            if response.get("ok"):
                result = response.get("result", {})
                if isinstance(result, dict) and result.get("output_dir"):
                    self.results_output_dir.setText(str(result.get("output_dir")))
                    self._load_results(str(result.get("output_dir")))

        def _load_results(self, output_dir: Optional[str] = None) -> None:
            out = output_dir or self.results_output_dir.text().strip()
            if not out:
                QMessageBox.warning(self, "Missing output folder", "Choose or enter a PooleShield output folder first.")
                return
            request = build_results_load_request(
                out,
                decision=self.results_decision.currentText(),
                label=self.results_label_filter.text().strip(),
                text=self.results_text_filter.text().strip(),
                limit=1000,
            )
            response = dispatch(request)
            self._last_results_response = response
            self.results_status.setText(summarize_results_response(response))
            self.results_detail.setPlainText(_pretty(response))
            self._fill_results_table(response)

        def _fill_results_table(self, response: Dict[str, Any]) -> None:
            self.results_table.setRowCount(0)
            self._last_results_rows = []
            if not response.get("ok"):
                return
            result = response.get("result", {})
            if not isinstance(result, dict):
                return
            rows = result.get("items", [])
            if not isinstance(rows, list):
                return
            self._last_results_rows = [dict(row) for row in rows if isinstance(row, dict)]
            for row_idx, item in enumerate(self._last_results_rows):
                self.results_table.insertRow(row_idx)
                labels = ";".join(str(x) for x in item.get("labels", []))
                values = [
                    item.get("effective_decision", ""),
                    item.get("risk_score", ""),
                    item.get("baseline_status", ""),
                    item.get("kind", ""),
                    labels,
                    item.get("display_path", ""),
                ]
                for col, value in enumerate(values):
                    self.results_table.setItem(row_idx, col, QTableWidgetItem(str(value)))
            if self._last_results_rows:
                self.results_table.selectRow(0)

        def _show_selected_result_detail(self) -> None:
            row = self.results_table.currentRow()
            if row < 0 or row >= len(self._last_results_rows):
                return
            self.results_detail.setPlainText(_pretty(self._last_results_rows[row]))

        def _copy_bundle_path(self) -> None:
            result = self._last_results_response.get("result", {}) if isinstance(self._last_results_response, dict) else {}
            bundle = result.get("bundle_path", "") if isinstance(result, dict) else ""
            if not bundle:
                QMessageBox.information(self, "No bundle path", "Load results from a bundled scan output first.")
                return
            QApplication.clipboard().setText(str(bundle))
            self.results_status.setText(f"Copied bundle path: {bundle}")

        def _load_baseline(self) -> None:
            baseline = self.baseline_manager_path.text().strip()
            if not baseline:
                QMessageBox.warning(self, "Missing baseline", "Choose a trusted_file_baseline.json first.")
                return
            request = build_baseline_load_request(
                baseline,
                decision=self.baseline_manager_decision.currentText(),
                kind=self.baseline_manager_kind.text().strip(),
                text=self.baseline_manager_text.text().strip(),
                limit=1000,
            )
            response = dispatch(request)
            self._last_baseline_response = response
            self.baseline_status.setText(summarize_baseline_response(response))
            self.baseline_detail.setPlainText(_pretty(response))
            self._fill_baseline_table(response)
            if response.get("ok"):
                self.baseline_diff_a.setText(baseline)

        def _fill_baseline_table(self, response: Dict[str, Any]) -> None:
            self.baseline_table.setRowCount(0)
            self._last_baseline_rows = []
            if not response.get("ok"):
                return
            result = response.get("result", {})
            if not isinstance(result, dict):
                return
            rows = result.get("entries", [])
            if not isinstance(rows, list):
                return
            self._last_baseline_rows = [dict(row) for row in rows if isinstance(row, dict)]
            for row_idx, item in enumerate(self._last_baseline_rows):
                self.baseline_table.insertRow(row_idx)
                labels = ";".join(str(x) for x in item.get("labels", []))
                values = [
                    item.get("trusted_decision", ""),
                    item.get("kind", ""),
                    item.get("size_bytes", ""),
                    item.get("sha256_prefix", ""),
                    labels,
                    item.get("first_path_hint", ""),
                ]
                for col, value in enumerate(values):
                    self.baseline_table.setItem(row_idx, col, QTableWidgetItem(str(value)))
            if self._last_baseline_rows:
                self.baseline_table.selectRow(0)

        def _show_selected_baseline_detail(self) -> None:
            row = self.baseline_table.currentRow()
            if row < 0 or row >= len(self._last_baseline_rows):
                return
            self.baseline_detail.setPlainText(_pretty(self._last_baseline_rows[row]))

        def _copy_selected_baseline_sha(self) -> None:
            row = self.baseline_table.currentRow()
            if row < 0 or row >= len(self._last_baseline_rows):
                QMessageBox.information(self, "No row selected", "Select a baseline entry first.")
                return
            sha = str(self._last_baseline_rows[row].get("sha256", ""))
            QApplication.clipboard().setText(sha)
            self.baseline_status.setText(f"Copied SHA: {sha[:16]}...")

        def _copy_baseline_path(self) -> None:
            baseline = self.baseline_manager_path.text().strip()
            if not baseline:
                QMessageBox.information(self, "No baseline path", "Choose a baseline first.")
                return
            QApplication.clipboard().setText(baseline)
            self.baseline_status.setText(f"Copied baseline path: {baseline}")

        def _diff_baselines(self) -> None:
            a = self.baseline_diff_a.text().strip()
            b = self.baseline_diff_b.text().strip()
            if not a or not b:
                QMessageBox.warning(self, "Missing baseline", "Enter both baseline A and baseline B paths.")
                return
            response = dispatch(build_baseline_diff_request(a, b, limit=500))
            self._last_baseline_response = response
            self.baseline_status.setText(summarize_baseline_response(response))
            self.baseline_detail.setPlainText(_pretty(response))

        def _load_rule_pack(self) -> None:
            rule_pack = self.rule_pack_editor_path.text().strip()
            if not rule_pack:
                QMessageBox.warning(self, "Missing rule pack", "Choose a rule pack JSON file first.")
                return
            response = dispatch(build_rule_pack_load_request(
                rule_pack,
                enabled=self.rule_pack_editor_enabled.currentText(),
                type_filter=self.rule_pack_editor_type.text().strip(),
                text=self.rule_pack_editor_text.text().strip(),
                limit=1000,
            ))
            self._last_rule_pack_response = response
            self.rule_pack_status.setText(summarize_rule_pack_response(response))
            self.rule_pack_detail.setPlainText(_pretty(response))
            self._fill_rule_pack_table(response)

        def _fill_rule_pack_table(self, response: Dict[str, Any]) -> None:
            self.rule_pack_table.setRowCount(0)
            self._last_rule_pack_rows = []
            if not response.get("ok"):
                return
            result = response.get("result", {})
            if not isinstance(result, dict):
                return
            rows = result.get("rules", [])
            if not isinstance(rows, list):
                return
            self._last_rule_pack_rows = [dict(row) for row in rows if isinstance(row, dict)]
            for row_idx, item in enumerate(self._last_rule_pack_rows):
                values = [
                    item.get("index", ""),
                    item.get("enabled", ""),
                    item.get("type", ""),
                    item.get("risk_delta", ""),
                    item.get("label", ""),
                    item.get("id", ""),
                    item.get("pattern", ""),
                ]
                self.rule_pack_table.insertRow(row_idx)
                for col, value in enumerate(values):
                    self.rule_pack_table.setItem(row_idx, col, QTableWidgetItem(str(value)))
            if self._last_rule_pack_rows:
                self.rule_pack_table.selectRow(0)

        def _show_selected_rule_pack_detail(self) -> None:
            row = self.rule_pack_table.currentRow()
            if row < 0 or row >= len(self._last_rule_pack_rows):
                return
            item = self._last_rule_pack_rows[row]
            self.rule_pack_set_enabled.setChecked(bool(item.get("enabled", True)))
            self.rule_pack_risk_delta.setText(str(item.get("risk_delta", "")))
            self.rule_pack_label.setText(str(item.get("label", "")))
            self.rule_pack_pattern.setText(str(item.get("pattern", "")))
            self.rule_pack_detail.setPlainText(_pretty(item))

        def _export_default_rule_pack(self) -> None:
            response = dispatch(build_rule_pack_export_default_request(self.rule_pack_export_path.text().strip(), force=True))
            self._last_rule_pack_response = response
            self.rule_pack_status.setText(summarize_rule_pack_response(response))
            self.rule_pack_detail.setPlainText(_pretty(response))
            if response.get("ok"):
                result = response.get("result", {})
                if isinstance(result, dict) and result.get("output_rule_pack"):
                    self.rule_pack_editor_path.setText(str(result.get("output_rule_pack")))
                    self._load_rule_pack()

        def _save_selected_rule_pack_rule(self) -> None:
            row = self.rule_pack_table.currentRow()
            if row < 0 or row >= len(self._last_rule_pack_rows):
                QMessageBox.information(self, "No row selected", "Select a rule first.")
                return
            item = self._last_rule_pack_rows[row]
            try:
                risk_delta = float(self.rule_pack_risk_delta.text().strip()) if self.rule_pack_risk_delta.text().strip() else None
            except ValueError:
                QMessageBox.warning(self, "Bad risk delta", "risk_delta must be a number between 0 and 1.")
                return
            response = dispatch(build_rule_pack_update_rule_request(
                self.rule_pack_editor_path.text().strip(),
                self.rule_pack_export_path.text().strip(),
                index=int(item.get("index", row)),
                enabled=self.rule_pack_set_enabled.isChecked(),
                risk_delta=risk_delta,
                label=self.rule_pack_label.text().strip() or None,
                pattern=self.rule_pack_pattern.text().strip() or None,
            ))
            self._last_rule_pack_response = response
            self.rule_pack_status.setText(summarize_rule_pack_response(response))
            self.rule_pack_detail.setPlainText(_pretty(response))
            if response.get("ok"):
                result = response.get("result", {})
                if isinstance(result, dict) and result.get("output_rule_pack"):
                    self.rule_pack_editor_path.setText(str(result.get("output_rule_pack")))
                    self._load_rule_pack()

        def _copy_rule_pack_path(self) -> None:
            rule_pack = self.rule_pack_editor_path.text().strip()
            if not rule_pack:
                QMessageBox.information(self, "No rule pack path", "Choose a rule pack first.")
                return
            QApplication.clipboard().setText(rule_pack)
            self.rule_pack_status.setText(f"Copied rule pack path: {rule_pack}")

        def _refresh_history(self) -> None:
            request = build_history_list_request(
                config=self.history_config_path.text().strip() or None,
                history_db=self.history_db_path.text().strip() or None,
                limit=25,
            )
            response = dispatch(request)
            self.history_output.setPlainText(_pretty(response))
            self.history_table.setRowCount(0)
            if not response.get("ok"):
                return
            scans = response.get("result", {}).get("scans", [])
            for row_idx, item in enumerate(scans):
                self.history_table.insertRow(row_idx)
                values = [
                    item.get("scan_id", ""),
                    item.get("scan_timestamp", ""),
                    item.get("final_verdict", ""),
                    item.get("scan_profile", ""),
                    item.get("items_scanned", ""),
                    item.get("baseline_matches", ""),
                    item.get("result_bundle", ""),
                ]
                for col, value in enumerate(values):
                    self.history_table.setItem(row_idx, col, QTableWidgetItem(str(value)))


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(argv or [])
    if "--status" in argv:
        print(json.dumps(qt_status(), indent=2, ensure_ascii=False))
        return 0
    if not HAS_QT:
        print("PooleShield desktop UI requires PySide6.")
        print(f"Import error: {QT_IMPORT_ERROR}")
        print("Install with: python -m pip install PySide6")
        return 2
    app = QApplication(sys.argv[:1] + argv)
    window = PooleShieldDesktop()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
