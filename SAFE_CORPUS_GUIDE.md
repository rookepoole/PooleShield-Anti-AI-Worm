# PooleShield v5.3 Safe Corpus + Benchmark Guide

Version: 5.3.0

PooleShield v5.3 adds a safe corpus path for code testers who want benchmark-style feedback without collecting or running live malware.

## Safety boundary

The v5.3 safe-corpus path is deliberately constrained:

- no live malware downloads
- no raw malware binaries in the repository
- no unpacking unknown malware
- no execution of samples
- no deletion or quarantine
- no drivers, hooks, or real-time protection
- no network upload of raw contents
- feature vectors, metadata, labels, and hashes only

The benchmark can use malware-derived metadata or feature rows, but it must not ingest live malware samples in public/local default workflows.

## Included fixture

```text
examples/safe_corpus/tiny_feature_dataset.jsonl
```

The fixture is safe and metadata-only. It does not contain executable malware, raw binaries, payloads, or the canonical EICAR test string.

## Run the safe benchmark

```powershell
python .\pooleshield_operator.py safe-corpus-benchmark `
  --dataset .\examples\safe_corpus\tiny_feature_dataset.jsonl `
  --output-dir .\out\safe_corpus_v5_3 `
  --clean-output `
  --bundle-output `
  --privacy-bundle
```

Expected output files:

```text
safe_corpus_benchmark.json
safe_corpus_benchmark.csv
safe_corpus_benchmark.md
pooleshield_results_bundle.zip
```

## Validate a safe corpus

```powershell
python .\pooleshield_operator.py safe-corpus-status `
  --dataset .\examples\safe_corpus\tiny_feature_dataset.jsonl `
  --output .\safe_corpus_status_response.json
```

## Create an inert EICAR-style feature fixture

```powershell
python .\pooleshield_operator.py safe-corpus-fixture `
  --output .\examples\safe_corpus\eicar_style_feature_fixture.jsonl
```

The fixture intentionally omits the canonical EICAR string because some antivirus products quarantine the string itself. This keeps the repo and local test flow less disruptive.

## Adapter strategy

Use feature-only adapters for datasets such as EMBER/SOREL-style rows:

```python
from dataset_adapters.ember_adapter import normalize_ember_file
normalize_ember_file("ember_features.jsonl", "safe_ember.jsonl", limit=10000)
```

```python
from dataset_adapters.sorel_adapter import normalize_sorel_file
normalize_sorel_file("sorel_features.jsonl", "safe_sorel.jsonl", limit=10000)
```

These adapters normalize metadata/features. They do not fetch samples, download malware, or include binaries.

## Schema

A safe corpus record uses this shape:

```json
{
  "sample_id": "sha256-or-dataset-id",
  "source": "ember",
  "label": "malicious",
  "features_only": true,
  "raw_binary_present": false,
  "feature_vector": {},
  "metadata": {},
  "tags": [],
  "safety_notes": ["metadata/features only", "no executable sample included"]
}
```

Allowed labels:

```text
benign
malicious
suspicious
unknown
```

Unknown labels are allowed but excluded from supervised precision/recall metrics.
