#!/usr/bin/env python3
"""PooleShield v5.4 safe-corpus benchmark runner.

This benchmark consumes metadata/features only. It does not download, unpack,
execute, or inspect live malware binaries.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from dataset_schema import VERSION, POSITIVE_LABELS, NEGATIVE_LABELS, corpus_sha256, load_safe_corpus, summarize_records
from result_bundler import bundle_output_dir


def _num(value: Any, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    try:
        return float(value)
    except Exception:
        return default


def score_feature_vector(features: Dict[str, Any]) -> Dict[str, Any]:
    """Return a deterministic PooleShield-style risk score from safe features."""
    weights = {
        "eicar_style_marker": 0.70,
        "known_test_malware_marker": 0.70,
        "malicious_vendor_ratio": 0.45,
        "suspicious_imports": 0.18,
        "network_indicators": 0.15,
        "powershell_flags": 0.16,
        "macro_indicators": 0.16,
        "packer_score": 0.14,
        "entropy": 0.10,
        "rare_section_names": 0.10,
        "self_modifying_hint": 0.20,
        "unsigned_binary": 0.08,
    }
    score = 0.0
    reasons: List[str] = []
    for key, weight in weights.items():
        if key not in features:
            continue
        raw = _num(features.get(key), 0.0)
        value = min(max(raw, 0.0), 1.0)
        # entropy is usually 0..8 in PE features; map high entropy into 0..1.
        if key == "entropy":
            value = min(max((raw - 6.0) / 2.0, 0.0), 1.0)
        contribution = value * weight
        if contribution > 0:
            reasons.append(f"{key}:{contribution:.3f}")
        score += contribution
    score = max(0.0, min(score, 1.0))
    return {"risk_score": round(score, 6), "reasons": reasons}


def _decision(score: float, require_approval_threshold: float, block_threshold: float) -> str:
    if score >= block_threshold:
        return "BLOCK"
    if score >= require_approval_threshold:
        return "REQUIRE_APPROVAL"
    return "ALLOW_LOG"


def _metrics(rows: List[Dict[str, Any]], threshold: float) -> Dict[str, Any]:
    supervised = [r for r in rows if r["label"] in POSITIVE_LABELS or r["label"] in NEGATIVE_LABELS]
    tp = fp = tn = fn = 0
    for row in supervised:
        predicted_positive = row["risk_score"] >= threshold
        actual_positive = row["label"] in POSITIVE_LABELS
        if predicted_positive and actual_positive:
            tp += 1
        elif predicted_positive and not actual_positive:
            fp += 1
        elif not predicted_positive and not actual_positive:
            tn += 1
        elif not predicted_positive and actual_positive:
            fn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    accuracy = (tp + tn) / len(supervised) if supervised else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "supervised_count": len(supervised),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "specificity": round(specificity, 6),
        "accuracy": round(accuracy, 6),
        "f1": round(f1, 6),
        "false_positive_rate": round(fpr, 6),
    }


def run_safe_corpus_benchmark(
    dataset: str,
    output_dir: str = "out/safe_corpus_benchmark",
    clean_output: bool = False,
    source: str = "generic",
    require_approval_threshold: float = 0.35,
    block_threshold: float = 0.75,
    bundle_output: bool = False,
    bundle_path: Optional[str] = None,
    privacy_bundle: bool = True,
    redact_paths: bool = False,
    path_redaction_mode: str = "basename",
) -> Dict[str, Any]:
    out = Path(output_dir)
    if clean_output and out.exists():
        import shutil
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)
    records = load_safe_corpus(dataset, source=source, allow_raw_binary=False)
    rows: List[Dict[str, Any]] = []
    invalid = []
    for rec in records:
        validation = rec.get("validation") or {}
        if not validation.get("valid", True):
            invalid.append({"sample_id": rec.get("sample_id"), "errors": validation.get("errors", [])})
            continue
        score = score_feature_vector(rec.get("feature_vector") or {})
        risk = float(score["risk_score"])
        rows.append({
            "sample_id": rec.get("sample_id"),
            "source": rec.get("source"),
            "label": rec.get("label"),
            "risk_score": risk,
            "decision": _decision(risk, require_approval_threshold, block_threshold),
            "reasons": score.get("reasons", []),
            "features_only": rec.get("features_only"),
            "raw_binary_present": rec.get("raw_binary_present"),
            "tags": rec.get("tags", []),
        })
    counts: Dict[str, int] = {}
    for row in rows:
        counts[row["decision"]] = counts.get(row["decision"], 0) + 1
    summary = {
        "tool": "PooleShield safe corpus benchmark",
        "version": VERSION,
        "mode": "safe-corpus-benchmark",
        "dataset": str(Path(dataset).resolve()),
        "output_dir": str(out),
        "record_summary": summarize_records(records),
        "corpus_sha256": corpus_sha256(records),
        "invalid_records": invalid,
        "scored_count": len(rows),
        "by_decision": dict(sorted(counts.items())),
        "metrics_at_require_approval_threshold": _metrics(rows, require_approval_threshold),
        "thresholds": {"require_approval": require_approval_threshold, "block": block_threshold},
        "safety_boundary": {
            "features_only": True,
            "raw_binaries_loaded": False,
            "malware_samples_downloaded": False,
            "artifacts_executed": False,
            "files_deleted": False,
            "files_quarantined": False,
            "network_uploads": False,
        },
        "reports": {
            "json": str(out / "safe_corpus_benchmark.json"),
            "csv": str(out / "safe_corpus_benchmark.csv"),
            "md": str(out / "safe_corpus_benchmark.md"),
        },
    }
    (out / "safe_corpus_benchmark.json").write_text(json.dumps({**summary, "items": rows}, indent=2, ensure_ascii=False), encoding="utf-8")
    with (out / "safe_corpus_benchmark.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["sample_id", "source", "label", "risk_score", "decision", "reasons", "features_only", "raw_binary_present", "tags"], extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({**row, "reasons": ";".join(row.get("reasons", [])), "tags": ";".join(row.get("tags", []))})
    md_lines = [
        "# PooleShield Safe Corpus Benchmark",
        "",
        f"Version: {VERSION}",
        f"Dataset: `{summary['dataset']}`",
        f"Records: `{summary['record_summary']['record_count']}`",
        f"Scored: `{summary['scored_count']}`",
        f"Decisions: `{summary['by_decision']}`",
        f"Metrics: `{summary['metrics_at_require_approval_threshold']}`",
        "",
        "## Safety boundary",
        "",
        "This benchmark used feature/metadata records only. It did not download, unpack, execute, quarantine, or upload live malware samples.",
    ]
    (out / "safe_corpus_benchmark.md").write_text("\n".join(md_lines), encoding="utf-8")
    if bundle_output:
        bundle = bundle_output_dir(
            str(out),
            bundle_path or str(out / "pooleshield_results_bundle.zip"),
            privacy_mode=privacy_bundle,
            redact_paths=redact_paths,
            path_redaction_mode=path_redaction_mode,
        )
        summary["bundle_summary"] = bundle
        summary["result_bundle"] = bundle.get("bundle_path")
        (out / "safe_corpus_benchmark.json").write_text(json.dumps({**summary, "items": rows}, indent=2, ensure_ascii=False), encoding="utf-8")
        bundle_output_dir(
            str(out),
            bundle_path or str(out / "pooleshield_results_bundle.zip"),
            privacy_mode=privacy_bundle,
            redact_paths=redact_paths,
            path_redaction_mode=path_redaction_mode,
        )
    return {**summary, "items": rows}
