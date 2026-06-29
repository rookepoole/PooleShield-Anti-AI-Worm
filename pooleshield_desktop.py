#!/usr/bin/env python3
"""PooleShield v4.1 desktop UI prototype.

Defensive purpose:
  Provide the first local desktop dashboard for the PooleShield Engine API.
  The UI calls local engine functions and writes local reports only.

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
from typing import Any, Dict, Optional, Sequence

from pooleshield_engine import VERSION as ENGINE_VERSION, dispatch

VERSION = "4.1.0"

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
            self._build_dashboard_tab()
            self._build_scan_tab()
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
            self.output_dir = QLineEdit("out/file_av_desktop_v4_1")
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
            <p>This is a prototype UI for local operator testing before packaging as a Windows app.</p>
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
