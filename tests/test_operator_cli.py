import json
import subprocess
import sys
from pathlib import Path


def test_operator_demo(tmp_path):
    root = Path(__file__).resolve().parents[1]
    out = tmp_path / "demo_out"
    cmd = [sys.executable, str(root / "pooleshield_operator.py"), "demo", "--output-dir", str(out), "--clean-output"]
    result = subprocess.run(cmd, cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert result.returncode == 0, result.stderr
    assert (out / "scan_report.json").exists()
    assert (out / "approval_queue.json").exists()
    assert (out / "review_ledger_template.csv").exists()
    assert (out / "effective_policy_decisions.json").exists()
    data = json.loads((out / "effective_policy_decisions.json").read_text(encoding="utf-8"))
    assert data["summary"]["by_effective_decision"].get("QUARANTINE") == 1
    assert data["summary"]["by_effective_decision"].get("BLOCK") == 1


def test_operator_scan_then_apply(tmp_path):
    root = Path(__file__).resolve().parents[1]
    out = tmp_path / "real_out"
    scan_cmd = [
        sys.executable, str(root / "pooleshield_operator.py"), "scan",
        "--path", str(root / "examples" / "corpus_scan_fixture"),
        "--output-dir", str(out),
        "--clean-output",
    ]
    result = subprocess.run(scan_cmd, cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert result.returncode == 0, result.stderr
    ledger = out / "review_ledger_template.csv"
    assert ledger.exists()
    apply_cmd = [
        sys.executable, str(root / "pooleshield_operator.py"), "apply-ledger",
        "--output-dir", str(out),
        "--ledger", str(ledger),
    ]
    result2 = subprocess.run(apply_cmd, cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert result2.returncode == 0, result2.stderr
    effective = out / "effective_policy_decisions.json"
    assert effective.exists()
    data = json.loads(effective.read_text(encoding="utf-8"))
    assert data["summary"]["pending_review_rows"] >= 1


def test_operator_demo_bundle(tmp_path):
    import zipfile
    root = Path(__file__).resolve().parents[1]
    out = tmp_path / "demo_bundle_out"
    cmd = [
        sys.executable, str(root / "pooleshield_operator.py"), "demo",
        "--output-dir", str(out), "--clean-output", "--bundle-output"
    ]
    result = subprocess.run(cmd, cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert result.returncode == 0, result.stderr
    bundle = out / "pooleshield_results_bundle.zip"
    assert bundle.exists()
    with zipfile.ZipFile(bundle) as zf:
        names = set(zf.namelist())
    assert "RUN_SUMMARY.json" in names
    assert "effective_policy_decisions.json" in names
    assert "BUNDLE_MANIFEST.json" in names
    assert "pooleshield_results_bundle.zip" not in names


def test_operator_bundle_command(tmp_path):
    import zipfile
    root = Path(__file__).resolve().parents[1]
    out = tmp_path / "bundle_cmd_out"
    out.mkdir()
    (out / "RUN_SUMMARY.json").write_text('{"ok": true}', encoding="utf-8")
    cmd = [sys.executable, str(root / "pooleshield_operator.py"), "bundle", "--output-dir", str(out)]
    result = subprocess.run(cmd, cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert result.returncode == 0, result.stderr
    bundle = out / "pooleshield_results_bundle.zip"
    assert bundle.exists()
    with zipfile.ZipFile(bundle) as zf:
        assert "RUN_SUMMARY.json" in zf.namelist()
